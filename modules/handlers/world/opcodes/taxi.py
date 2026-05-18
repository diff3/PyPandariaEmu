#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import struct
from dataclasses import dataclass

from DSL.modules.bitsHandler import BitInterPreter
from DSL.modules.bitsHandler import BitWriter
from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger
from server.modules.dbc.DBCReader import read_dbc
from server.modules.game.guid import GuidHelper
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from server.modules.handlers.world.dispatcher import register
from server.modules.handlers.world.feature_config import (
    flight_paths_enabled,
    taxi_cheat_enabled as config_taxi_cheat_enabled,
)
from server.modules.handlers.world.movements.cache import get_movement_cache
from server.modules.handlers.world.taxi_runtime import (
    TaxiPathPoint,
    start_taxi_flight,
)
from server.modules.protocol.PacketContext import PacketContext


_TAXI_NODE_STATUS_KNOWN = 1
_TAXI_ACTIVATE_OK = 0
_TAXI_NODE_MASK_BYTES = 256
_TAXI_NPC_FLAG = 0x00002000
_FALLBACK_HORDE_NODE_IDS = (23, 25, 536, 537)
_TAXI_NODES_FMT = "difffsiixxxx"


@dataclass(frozen=True)
class TaxiNode:
    node_id: int
    map_id: int
    x: float
    y: float
    z: float
    name: str
    mount_creature_id_1: int = 0
    mount_creature_id_2: int = 0


@dataclass(frozen=True)
class TaxiPath:
    path_id: int
    source_node: int
    destination_node: int
    price: int


_TAXI_NODES: dict[int, TaxiNode] | None = None
_TAXI_PATHS_BY_NODES: dict[tuple[int, int], TaxiPath] | None = None
_TAXI_PATH_POINTS_BY_PATH: dict[int, tuple[TaxiPathPoint, ...]] | None = None
_TAXI_MOUNT_DISPLAY_BY_CREATURE_ID: dict[int, int] = {
    541: 6852,    # Riding Gryphon
    2224: 6851,   # Wind Rider
    3574: 1566,   # Riding Bat
    3837: 1936,   # Riding Hippogryph
    32981: 28421,  # Riding Scourge Gryphon (Taxi)
}
_TAXI_PATH_FMT = "diii"
_TAXI_RESAMPLE_DISTANCE_YARDS = 4.0


def _payload(ctx) -> bytes:
    if isinstance(ctx, PacketContext):
        return bytes(ctx.payload or b"")
    return bytes(ctx or b"")


def _append_xor_guid_bytes(payload: bytearray, raw_guid: bytes, order: tuple[int, ...]) -> None:
    for index in order:
        value = int(raw_guid[index]) & 0xFF
        if value:
            payload.append(value ^ 1)


def _decode_bitpacked_guid(
    data: bytes,
    *,
    bit_order: tuple[int, ...],
    byte_order: tuple[int, ...],
    byte_pos: int = 0,
) -> int:
    bit_pos = 0
    mask: dict[int, int] = {}
    for index in bit_order:
        mask[index], byte_pos, bit_pos = BitInterPreter.read_bit(data, byte_pos, bit_pos)

    if bit_pos:
        byte_pos += 1

    guid = [0] * 8
    for index in byte_order:
        if not mask.get(index):
            continue
        if byte_pos >= len(data):
            return 0
        guid[index] = int(data[byte_pos]) ^ 1
        byte_pos += 1

    return int.from_bytes(bytes(guid), "little", signed=False)


def _decode_gossip_guid(data: bytes) -> int:
    return _decode_bitpacked_guid(
        data,
        bit_order=(2, 4, 0, 3, 6, 7, 5, 1),
        byte_order=(4, 7, 1, 0, 5, 3, 6, 2),
    )


def _decode_taxi_query_guid(data: bytes) -> int:
    if len(data) == 8:
        try:
            return GuidHelper.unpack(data)
        except Exception:
            pass

    return _decode_bitpacked_guid(
        data,
        bit_order=(7, 1, 0, 4, 2, 5, 6, 3),
        byte_order=(0, 3, 7, 5, 2, 6, 4, 1),
    )


def _decode_activate_taxi(data: bytes) -> tuple[int, int, int]:
    if len(data) < 8:
        return 0, 0, 0

    destination_node = struct.unpack_from("<I", data, 0)[0]
    source_node = struct.unpack_from("<I", data, 4)[0]
    guid = _decode_bitpacked_guid(
        data,
        bit_order=(4, 0, 1, 2, 5, 6, 7, 3),
        byte_order=(1, 0, 6, 5, 2, 4, 3, 7),
        byte_pos=8,
    )
    return guid, source_node, destination_node


def _decode_activate_taxi_express(data: bytes) -> tuple[int, tuple[int, ...]]:
    if len(data) < 4:
        return 0, ()

    byte_pos = 0
    bit_pos = 0
    mask: dict[int, int] = {}
    for index in (6, 7):
        mask[index], byte_pos, bit_pos = BitInterPreter.read_bit(data, byte_pos, bit_pos)

    node_count, byte_pos, bit_pos = BitInterPreter.read_bits(data, byte_pos, bit_pos, 22)

    for index in (2, 0, 4, 3, 1, 5):
        mask[index], byte_pos, bit_pos = BitInterPreter.read_bit(data, byte_pos, bit_pos)

    if bit_pos:
        byte_pos += 1
        bit_pos = 0

    guid = [0] * 8
    for index in (2, 7, 1):
        if not mask.get(index):
            continue
        if byte_pos >= len(data):
            return 0, ()
        guid[index] = int(data[byte_pos]) ^ 1
        byte_pos += 1

    nodes: list[int] = []
    safe_count = min(int(node_count), 64)
    for _index in range(safe_count):
        if byte_pos + 4 > len(data):
            return int.from_bytes(bytes(guid), "little", signed=False), tuple(nodes)
        nodes.append(struct.unpack_from("<I", data, byte_pos)[0])
        byte_pos += 4

    for index in (0, 5, 3, 6, 4):
        if not mask.get(index):
            continue
        if byte_pos >= len(data):
            return int.from_bytes(bytes(guid), "little", signed=False), tuple(nodes)
        guid[index] = int(data[byte_pos]) ^ 1
        byte_pos += 1

    return int.from_bytes(bytes(guid), "little", signed=False), tuple(nodes)


def _dbc_path() -> str:
    config = ConfigLoader.load_config()
    return str(config.get("dbc_path") or "data/dbc")


def _load_taxi_nodes() -> dict[int, TaxiNode]:
    global _TAXI_NODES
    if _TAXI_NODES is not None:
        return _TAXI_NODES

    nodes: dict[int, TaxiNode] = {}
    try:
        for record in read_dbc(f"{_dbc_path()}/TaxiNodes.dbc", _TAXI_NODES_FMT):
            node_id = int(record[0] or 0)
            if node_id <= 0:
                continue
            nodes[node_id] = TaxiNode(
                node_id=node_id,
                map_id=int(record[1] or 0),
                x=float(record[2] or 0.0),
                y=float(record[3] or 0.0),
                z=float(record[4] or 0.0),
                name=str(record[5] or ""),
                mount_creature_id_1=int(record[6] or 0),
                mount_creature_id_2=int(record[7] or 0),
            )
    except Exception as exc:
        Logger.warning("[Taxi] failed to load TaxiNodes.dbc: %s", exc)

    _TAXI_NODES = nodes
    return _TAXI_NODES


def _load_taxi_paths_by_nodes() -> dict[tuple[int, int], TaxiPath]:
    global _TAXI_PATHS_BY_NODES
    if _TAXI_PATHS_BY_NODES is not None:
        return _TAXI_PATHS_BY_NODES

    paths: dict[tuple[int, int], TaxiPath] = {}
    try:
        for record in read_dbc(f"{_dbc_path()}/TaxiPath.dbc", _TAXI_PATH_FMT):
            path_id = int(record[0] or 0)
            source_node = int(record[1] or 0)
            destination_node = int(record[2] or 0)
            if path_id <= 0 or source_node <= 0 or destination_node <= 0:
                continue
            paths[(source_node, destination_node)] = TaxiPath(
                path_id=path_id,
                source_node=source_node,
                destination_node=destination_node,
                price=int(record[3] or 0),
            )
    except Exception as exc:
        Logger.warning("[Taxi] failed to load TaxiPath.dbc: %s", exc)

    _TAXI_PATHS_BY_NODES = paths
    return _TAXI_PATHS_BY_NODES


def _load_taxi_path_points_by_path() -> dict[int, tuple[TaxiPathPoint, ...]]:
    global _TAXI_PATH_POINTS_BY_PATH
    if _TAXI_PATH_POINTS_BY_PATH is not None:
        return _TAXI_PATH_POINTS_BY_PATH

    paths: dict[int, tuple[TaxiPathPoint, ...]] = {}
    try:
        cache = get_movement_cache()
        cache.load()
    except Exception as exc:
        Logger.warning("[Taxi] failed movement cache TaxiPathNode load: %s", exc)
        _TAXI_PATH_POINTS_BY_PATH = {}
        return _TAXI_PATH_POINTS_BY_PATH

    for path_id, template in cache.taxi_paths.items():
        points: list[TaxiPathPoint] = []
        for node in template.nodes:
            points.append(
                TaxiPathPoint(
                    x=float(node.x),
                    y=float(node.y),
                    z=float(node.z),
                    orientation=None,
                )
            )
        if len(points) >= 2:
            paths[int(path_id)] = tuple(points)

    _TAXI_PATH_POINTS_BY_PATH = paths
    return _TAXI_PATH_POINTS_BY_PATH


def _nearest_taxi_node(session) -> TaxiNode | None:
    map_id = int(getattr(session, "map_id", 0) or 0)
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)
    z = float(getattr(session, "z", 0.0) or 0.0)

    best_node = None
    best_distance = float("inf")
    for node in _load_taxi_nodes().values():
        if node.map_id != map_id:
            continue
        dx = float(node.x) - x
        dy = float(node.y) - y
        dz = float(node.z) - z
        distance = math.sqrt((dx * dx) + (dy * dy) + (dz * dz))
        if distance < best_distance:
            best_node = node
            best_distance = distance

    return best_node


def _known_taxi_node_ids(session) -> tuple[int, ...]:
    if bool(getattr(session, "taxi_cheat_enabled", False)) or config_taxi_cheat_enabled():
        return tuple(sorted(int(node_id) for node_id in _load_taxi_nodes()))

    nodes = set(_FALLBACK_HORDE_NODE_IDS)
    current = _nearest_taxi_node(session)
    if current is not None:
        nodes.add(int(current.node_id))
    return tuple(sorted(nodes))


def _is_taxi_npc(session, guid: int) -> bool:
    npc_flags_by_guid = getattr(session, "npc_flags_by_guid", None)
    if not isinstance(npc_flags_by_guid, dict):
        return False

    flags = int(npc_flags_by_guid.get(int(guid), 0) or 0)
    if flags & _TAXI_NPC_FLAG:
        return True

    try:
        low_guid = int(GuidHelper.decode(int(guid)).low)
    except Exception:
        low_guid = 0
    flags = int(npc_flags_by_guid.get(low_guid, 0) or 0)
    return bool(flags & _TAXI_NPC_FLAG)


def _has_nearby_taxi_context(session) -> bool:
    """Recover from bad packed GUID decodes when the client is at a taxi node."""
    current = _nearest_taxi_node(session)
    if current is None:
        return False

    dx = float(current.x) - float(getattr(session, "x", 0.0) or 0.0)
    dy = float(current.y) - float(getattr(session, "y", 0.0) or 0.0)
    dz = float(current.z) - float(getattr(session, "z", 0.0) or 0.0)
    if math.sqrt((dx * dx) + (dy * dy) + (dz * dz)) > 80.0:
        return False

    npc_flags_by_guid = getattr(session, "npc_flags_by_guid", None)
    if not isinstance(npc_flags_by_guid, dict):
        return False

    return any(int(flags or 0) & _TAXI_NPC_FLAG for flags in npc_flags_by_guid.values())


def _can_use_taxi_interaction(session, guid: int) -> bool:
    return _is_taxi_npc(session, int(guid)) or _has_nearby_taxi_context(session)


def _build_node_mask(node_ids: tuple[int, ...]) -> bytes:
    mask = bytearray(_TAXI_NODE_MASK_BYTES)
    for node_id in node_ids:
        if int(node_id) <= 0:
            continue
        byte_index = int(node_id) // 8
        bit_index = int(node_id) % 8
        if byte_index >= len(mask):
            continue
        mask[byte_index] |= 1 << bit_index
    return bytes(mask)


def build_taxi_node_status_payload(guid: int, *, known: int = _TAXI_NODE_STATUS_KNOWN) -> bytes:
    return struct.pack("<QB", int(guid) & 0xFFFFFFFFFFFFFFFF, int(known) & 0xFF)


def build_show_taxi_nodes_payload(session, guid: int) -> bytes:
    raw_guid = int(guid or 0).to_bytes(8, "little", signed=False)
    current = _nearest_taxi_node(session)
    current_node_id = int(current.node_id) if current is not None else 23
    node_mask = _build_node_mask(_known_taxi_node_ids(session))

    bits = BitWriter()
    bits.write_bits(1, 1)
    for index in (3, 0, 4, 2, 1, 7, 6, 5):
        bits.write_bits(1 if raw_guid[index] else 0, 1)
    bits.write_bits(len(node_mask), 24)

    payload = bytearray(bits.getvalue())
    _append_xor_guid_bytes(payload, raw_guid, (0, 3))
    payload.extend(struct.pack("<I", current_node_id & 0xFFFFFFFF))
    _append_xor_guid_bytes(payload, raw_guid, (5, 2, 6, 1, 7, 4))
    payload.extend(node_mask)
    return bytes(payload)


def build_activate_taxi_reply_payload(result: int = _TAXI_ACTIVATE_OK) -> bytes:
    return struct.pack("<I", int(result) & 0xFFFFFFFF)


def _flight_paths_disabled_responses() -> list[tuple[str, bytes]]:
    return [
        ("SMSG_ACTIVATE_TAXI_REPLY", build_activate_taxi_reply_payload()),
        (
            "SMSG_MESSAGECHAT",
            encode_skyfire_messagechat_system_payload(
                "Flight paths are disabled on this server."
            ),
        ),
    ]


def _taxi_destination_position(node_id: int) -> tuple[int, float, float, float, float] | None:
    node = _load_taxi_nodes().get(int(node_id))
    if node is None:
        return None
    return int(node.map_id), float(node.x), float(node.y), float(node.z), 0.0


def _taxi_path_points_from_nodes(session, node_ids: tuple[int, ...]) -> tuple[int, list[TaxiPathPoint]]:
    nodes = _load_taxi_nodes()
    map_id = int(getattr(session, "map_id", 0) or 0)
    points = [
        TaxiPathPoint(
            float(getattr(session, "x", 0.0) or 0.0),
            float(getattr(session, "y", 0.0) or 0.0),
            float(getattr(session, "z", 0.0) or 0.0),
            float(getattr(session, "orientation", 0.0) or 0.0),
        )
    ]

    path_lookup = _load_taxi_paths_by_nodes()
    path_points_by_path = _load_taxi_path_points_by_path()
    used_dbc_path = False

    for source_node_id, destination_node_id in zip(node_ids, node_ids[1:]):
        taxi_path = path_lookup.get((int(source_node_id), int(destination_node_id)))
        if taxi_path is None:
            continue
        dbc_points = list(path_points_by_path.get(int(taxi_path.path_id), ()) or ())
        if len(dbc_points) < 2:
            continue
        for point in dbc_points:
            last = points[-1]
            if _taxi_point_distance(last, point) > 1.0:
                points.append(point)
                used_dbc_path = True

    if used_dbc_path:
        resampled = _resample_taxi_points(points, _TAXI_RESAMPLE_DISTANCE_YARDS)
        Logger.info(
            "[TAXI] using DBC path points nodes=%s points=%s resampled=%s step=%.1f",
            list(node_ids),
            len(points),
            len(resampled),
            float(_TAXI_RESAMPLE_DISTANCE_YARDS),
        )
        return map_id, resampled

    _ = nodes
    Logger.warning("[TAXI] missing DBC path nodes=%s; no fallback movement generated", list(node_ids))
    return map_id, points


def _resample_taxi_points(points: list[TaxiPathPoint], step_yards: float) -> list[TaxiPathPoint]:
    if len(points) < 2:
        return list(points)

    step = max(1.0, float(step_yards))
    resampled = [points[0]]
    for start, end in zip(points, points[1:]):
        distance = _taxi_point_distance(start, end)
        if distance <= 0.001:
            continue

        steps = max(1, int(math.ceil(distance / step)))
        for index in range(1, steps + 1):
            progress = float(index) / float(steps)
            candidate = TaxiPathPoint(
                x=float(start.x) + ((float(end.x) - float(start.x)) * progress),
                y=float(start.y) + ((float(end.y) - float(start.y)) * progress),
                z=float(start.z) + ((float(end.z) - float(start.z)) * progress),
                orientation=end.orientation,
            )
            if _taxi_point_distance(resampled[-1], candidate) > 0.01:
                resampled.append(candidate)

    return resampled


def _taxi_point_distance(a: TaxiPathPoint, b: TaxiPathPoint) -> float:
    return math.sqrt(((a.x - b.x) ** 2) + ((a.y - b.y) ** 2) + ((a.z - b.z) ** 2))


def _taxi_mount_display_id_for_source(session, source_node_id: int) -> int:
    node = _load_taxi_nodes().get(int(source_node_id))
    creature_id = 0
    if node is not None:
        creature_id = int(node.mount_creature_id_1 or node.mount_creature_id_2 or 0)

    if creature_id <= 0:
        return 6851

    display_id = int(_TAXI_MOUNT_DISPLAY_BY_CREATURE_ID.get(creature_id, 0) or 0)
    if display_id > 0:
        return display_id

    try:
        from server.modules.database.DatabaseConnection import DatabaseConnection
        from sqlalchemy import text

        row = DatabaseConnection.world().execute(
            text("SELECT modelid1 FROM creature_template WHERE entry = :entry LIMIT 1"),
            {"entry": int(creature_id)},
        ).fetchone()
        if row is not None:
            value = int(getattr(row, "modelid1", row[0]) or 0)
            if value > 0:
                _TAXI_MOUNT_DISPLAY_BY_CREATURE_ID[int(creature_id)] = value
                return value
    except Exception:
        pass

    Logger.warning("[TAXI] mount display fallback creature=%s", int(creature_id))
    return 6851


@register("CMSG_GOSSIP_HELLO")
def handle_gossip_hello(session, ctx):
    data = _payload(ctx)
    guid = _decode_gossip_guid(data)
    is_taxi = _can_use_taxi_interaction(session, guid)
    Logger.info(
        "[Taxi] CMSG_GOSSIP_HELLO guid=0x%016X is_taxi=%s len=%s",
        int(guid),
        int(is_taxi),
        len(data),
    )
    if not is_taxi:
        return 0, [("SMSG_GOSSIP_COMPLETE", b"")]

    return 0, [
        ("SMSG_TAXI_NODE_STATUS", build_taxi_node_status_payload(guid)),
        ("SMSG_SHOW_TAXI_NODES", build_show_taxi_nodes_payload(session, guid)),
    ]


@register("CMSG_TAXI_NODE_STATUS_QUERY")
def handle_taxi_node_status_query(session, ctx):
    data = _payload(ctx)
    guid = _decode_taxi_query_guid(data)
    Logger.info("[Taxi] CMSG_TAXI_NODE_STATUS_QUERY guid=0x%016X len=%s", int(guid), len(data))
    return 0, [("SMSG_TAXI_NODE_STATUS", build_taxi_node_status_payload(guid))]


@register("CMSG_TAXI_QUERY_AVAILABLE_NODES")
def handle_taxi_query_available_nodes(session, ctx):
    data = _payload(ctx)
    guid = _decode_taxi_query_guid(data)
    current = _nearest_taxi_node(session)
    is_taxi = _can_use_taxi_interaction(session, guid)
    Logger.info(
        "[Taxi] CMSG_TAXI_QUERY_AVAILABLE_NODES guid=0x%016X is_taxi=%s current_node=%s",
        int(guid),
        int(is_taxi),
        int(current.node_id) if current is not None else 0,
    )
    if not is_taxi:
        return 0, [("SMSG_GOSSIP_COMPLETE", b"")]

    return 0, [("SMSG_SHOW_TAXI_NODES", build_show_taxi_nodes_payload(session, guid))]


@register("CMSG_ACTIVATE_TAXI")
def handle_activate_taxi(session, ctx):
    data = _payload(ctx)
    guid, source_node, destination_node = _decode_activate_taxi(data)
    Logger.info(
        "[Taxi] CMSG_ACTIVATE_TAXI guid=0x%016X source=%s destination=%s len=%s",
        int(guid),
        int(source_node),
        int(destination_node),
        len(data),
    )
    if not flight_paths_enabled():
        Logger.info("[Taxi] flight paths disabled; rejecting CMSG_ACTIVATE_TAXI")
        return 0, _flight_paths_disabled_responses()

    responses = [("SMSG_ACTIVATE_TAXI_REPLY", build_activate_taxi_reply_payload())]
    destination = _taxi_destination_position(destination_node)
    if destination is None:
        return 0, responses

    destination_map = int(destination[0])
    if destination_map != int(getattr(session, "map_id", 0) or 0):
        Logger.warning("[TAXI] cross-map taxi rejected destination=%s map=%s", int(destination_node), destination_map)
        return 0, responses

    map_id, path_points = _taxi_path_points_from_nodes(session, (source_node, destination_node))
    responses.extend(
        start_taxi_flight(
            session,
            path_points,
            destination_map=map_id,
            destination_node=destination_node,
            mount_display_id=_taxi_mount_display_id_for_source(session, source_node),
        )
    )
    return 0, responses


@register("CMSG_ACTIVATE_TAXI_EXPRESS")
def handle_activate_taxi_express(session, ctx):
    data = _payload(ctx)
    guid, nodes = _decode_activate_taxi_express(data)
    source_node = int(nodes[0]) if nodes else 0
    destination_node = int(nodes[-1]) if nodes else 0
    Logger.info(
        "[Taxi] CMSG_ACTIVATE_TAXI_EXPRESS guid=0x%016X source=%s destination=%s nodes=%s len=%s",
        int(guid),
        int(source_node),
        int(destination_node),
        int(len(nodes)),
        len(data),
    )
    if not flight_paths_enabled():
        Logger.info("[Taxi] flight paths disabled; rejecting CMSG_ACTIVATE_TAXI_EXPRESS")
        return 0, _flight_paths_disabled_responses()

    responses = [("SMSG_ACTIVATE_TAXI_REPLY", build_activate_taxi_reply_payload())]
    if destination_node <= 0:
        return 0, responses

    destination = _taxi_destination_position(destination_node)
    if destination is None:
        return 0, responses

    destination_map = int(destination[0])
    if destination_map != int(getattr(session, "map_id", 0) or 0):
        Logger.warning("[TAXI] cross-map taxi rejected destination=%s map=%s", int(destination_node), destination_map)
        return 0, responses

    map_id, path_points = _taxi_path_points_from_nodes(session, tuple(int(node_id) for node_id in nodes))
    responses.extend(
        start_taxi_flight(
            session,
            path_points,
            destination_map=map_id,
            destination_node=destination_node,
            mount_display_id=_taxi_mount_display_id_for_source(session, source_node),
        )
    )
    return 0, responses
