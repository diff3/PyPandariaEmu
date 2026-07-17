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
from shared.PathUtils import get_dbc_root
from server.modules.dbc.DBCReader import read_dbc
from server.modules.game.guid import GuidHelper
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from server.modules.handlers.world.dispatcher import register
from server.modules.handlers.world.feature_config import (
    flight_paths_enabled,
    taxi_movement_debug_enabled,
)
from server.modules.handlers.world.movements.cache import get_movement_cache
from server.modules.handlers.world.taxi_runtime import (
    TaxiPathPoint,
    complete_taxi_spline,
    continue_taxi_flight,
    is_taxi_active,
    start_taxi_flight,
    sync_taxi_to_current_destination,
)
from server.modules.handlers.world.state.runtime import attach_session_to_world_state
from server.modules.handlers.world.runtime.player_store import (
    sync_player_runtime_from_session,
)
from server.modules.handlers.world.runtime.flight_path_store import (
    sync_flight_path_runtime_from_session,
)
from server.modules.handlers.world.transport_runtime import (
    clear_player_transport_state,
)
from server.modules.protocol.PacketContext import PacketContext
from server.modules.protocol.packet_batch import (
    bind_packet_batch_to_current_transition,
)


_TAXI_NODE_STATUS_KNOWN = 1
_TAXI_NODE_STATUS_UNKNOWN = 3
_TAXI_ACTIVATE_OK = 0
_TAXI_ACTIVATE_NOT_ENOUGH_MONEY = 4
_TAXI_NODE_MASK_BYTES = 256
_TAXI_MASK_WORDS = _TAXI_NODE_MASK_BYTES // 4
_TAXI_NPC_FLAG = 0x00002000
_PLAYER_FIELD_COINAGE = 1149
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
_TAXI_RESAMPLE_DISTANCE_YARDS = 18.0


def _taxi_xmap_debug(message: str, *args) -> None:
    if not taxi_movement_debug_enabled():
        return
    Logger.info(message, *args)


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


_GOSSIP_GUID_DECODE_ORDERS: tuple[tuple[tuple[int, ...], tuple[int, ...]], ...] = (
    (
        (2, 4, 0, 3, 6, 7, 5, 1),
        (4, 7, 1, 0, 5, 3, 6, 2),
    ),
    (
        (5, 2, 0, 4, 7, 1, 6, 3),
        (3, 4, 6, 1, 0, 2, 7, 5),
    ),
)


def _decode_gossip_guid(data: bytes) -> int:
    bit_order, byte_order = _GOSSIP_GUID_DECODE_ORDERS[0]
    return _decode_bitpacked_guid(
        data,
        bit_order=bit_order,
        byte_order=byte_order,
    )


def _decode_gossip_guid_candidates(data: bytes) -> tuple[int, ...]:
    candidates: list[int] = []
    for bit_order, byte_order in _GOSSIP_GUID_DECODE_ORDERS:
        guid = _decode_bitpacked_guid(data, bit_order=bit_order, byte_order=byte_order)
        if guid not in candidates:
            candidates.append(guid)
    return tuple(candidates)


def _select_gossip_guid(session, data: bytes) -> int:
    candidates = _decode_gossip_guid_candidates(data)
    for guid in candidates:
        if _is_taxi_npc(session, guid):
            return guid
    return candidates[0] if candidates else 0


def _decode_taxi_available_nodes_guid(data: bytes) -> int:
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


def _decode_taxi_node_status_guid(data: bytes) -> int:
    if len(data) == 8:
        try:
            return GuidHelper.unpack(data)
        except Exception:
            pass

    return _decode_bitpacked_guid(
        data,
        bit_order=(7, 4, 1, 3, 0, 5, 2, 6),
        byte_order=(7, 1, 5, 2, 4, 0, 6, 3),
    )


def _decode_enable_taxi_guid(data: bytes) -> int:
    if len(data) == 8:
        try:
            return GuidHelper.unpack(data)
        except Exception:
            pass

    return _decode_bitpacked_guid(
        data,
        bit_order=(3, 1, 6, 0, 4, 7, 2, 5),
        byte_order=(1, 6, 3, 0, 4, 5, 7, 2),
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
    dbc_root = get_dbc_root()
    if dbc_root is not None:
        return str(dbc_root)
    config = ConfigLoader.load_config()
    return str(config.get("dbc_path") or "data/client/dbc")


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
                    map_id=int(getattr(node, "map_id", 0) or 0),
                )
            )
        if len(points) >= 2:
            paths[int(path_id)] = tuple(points)

    _TAXI_PATH_POINTS_BY_PATH = paths
    return _TAXI_PATH_POINTS_BY_PATH


def _nearest_taxi_node_at(map_id: int, x: float, y: float, z: float) -> TaxiNode | None:
    best_node = None
    best_distance = float("inf")
    for node in _load_taxi_nodes().values():
        if node.map_id != int(map_id):
            continue
        dx = float(node.x) - float(x)
        dy = float(node.y) - float(y)
        dz = float(node.z) - float(z)
        distance = math.sqrt((dx * dx) + (dy * dy) + (dz * dz))
        if distance < best_distance:
            best_node = node
            best_distance = distance

    return best_node


def _nearest_taxi_node(session) -> TaxiNode | None:
    return _nearest_taxi_node_at(
        int(getattr(session, "map_id", 0) or 0),
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
    )


def _taxi_node_for_npc_guid(session, guid: int) -> TaxiNode | None:
    positions = getattr(session, "npc_positions_by_guid", None)
    if not isinstance(positions, dict):
        return _nearest_taxi_node(session)

    position = positions.get(int(guid))
    if position is None:
        try:
            low_guid = int(GuidHelper.decode(int(guid)).low)
        except Exception:
            low_guid = 0
        position = positions.get(low_guid)

    if position is None or len(position) < 4:
        return _nearest_taxi_node(session)

    return _nearest_taxi_node_at(
        int(position[0]),
        float(position[1]),
        float(position[2]),
        float(position[3]),
    )


def _taxi_mask_words(raw_mask: str | None) -> list[int]:
    words: list[int] = []
    for token in str(raw_mask or "").replace(",", " ").split():
        try:
            words.append(int(token) & 0xFFFFFFFF)
        except ValueError:
            continue

    if len(words) < _TAXI_MASK_WORDS:
        words.extend([0] * (_TAXI_MASK_WORDS - len(words)))
    return words[:_TAXI_MASK_WORDS]


def _serialize_taxi_mask_words(words: list[int]) -> str:
    normalized = [(int(word) & 0xFFFFFFFF) for word in list(words)[:_TAXI_MASK_WORDS]]
    if len(normalized) < _TAXI_MASK_WORDS:
        normalized.extend([0] * (_TAXI_MASK_WORDS - len(normalized)))
    return " ".join(str(word) for word in normalized)


def _taxi_node_ids_from_mask(raw_mask: str | None) -> set[int]:
    node_ids: set[int] = set()
    for word_index, word in enumerate(_taxi_mask_words(raw_mask)):
        value = int(word) & 0xFFFFFFFF
        for bit_index in range(32):
            if value & (1 << bit_index):
                node_id = (word_index * 32) + bit_index + 1
                if node_id > 0:
                    node_ids.add(node_id)
    return node_ids


def _mark_taxi_node_discovered(session, node_id: int) -> bool:
    node_id = int(node_id or 0)
    if node_id <= 0:
        return False

    protocol_bit = node_id - 1
    word_index = protocol_bit // 32
    bit_index = protocol_bit % 32
    if word_index >= _TAXI_MASK_WORDS:
        Logger.warning("[TaxiDiscovery] node id out of mask range node=%s", node_id)
        return False

    words = _taxi_mask_words(getattr(session, "taximask_raw", ""))
    previous = int(words[word_index]) & 0xFFFFFFFF
    words[word_index] = previous | (1 << bit_index)
    if words[word_index] == previous:
        return False

    session.taximask_raw = _serialize_taxi_mask_words(words)
    return True


def _save_character_taximask(char_guid: int, realm_id: int, taximask: str) -> bool:
    from server.modules.database.DatabaseConnection import DatabaseConnection

    return DatabaseConnection.save_character_taximask(char_guid, realm_id, taximask)


def _discover_taxi_node(session, node: TaxiNode | None, *, reason: str = "interaction") -> int:
    if node is None:
        return 0

    node_id = int(node.node_id)
    if not _mark_taxi_node_discovered(session, node_id):
        return node_id

    char_guid = int(getattr(session, "char_guid", 0) or 0)
    realm_id = int(getattr(session, "realm_id", 1) or 1)
    if char_guid > 0:
        _save_character_taximask(
            char_guid,
            realm_id,
            str(getattr(session, "taximask_raw", "") or ""),
        )

    Logger.info(
        "[TaxiDiscovery] player_guid=%s node=%s reason=%s",
        char_guid,
        node_id,
        str(reason),
    )
    return node_id


def discover_current_taxi_node(session, *, reason: str = "interaction") -> int:
    return _discover_taxi_node(session, _nearest_taxi_node(session), reason=reason)


def _known_taxi_node_ids(session) -> tuple[int, ...]:
    if bool(getattr(session, "taxi_cheat_enabled", False)):
        return tuple(sorted(int(node_id) for node_id in _load_taxi_nodes()))

    return tuple(sorted(_taxi_node_ids_from_mask(getattr(session, "taximask_raw", ""))))


def _taxi_route_nodes_known(session, node_ids: tuple[int, ...]) -> bool:
    known_nodes = set(_known_taxi_node_ids(session))
    return all(int(node_id or 0) in known_nodes for node_id in node_ids)


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
        protocol_bit = int(node_id) - 1
        byte_index = protocol_bit // 8
        bit_index = protocol_bit % 8
        if byte_index >= len(mask):
            continue
        mask[byte_index] |= 1 << bit_index
    return bytes(mask)


def build_taxi_node_status_payload(guid: int, *, known: int = _TAXI_NODE_STATUS_KNOWN) -> bytes:
    raw_guid = int(guid or 0).to_bytes(8, "little", signed=False)
    status = int(known) & 0x03

    bits = BitWriter()
    for index in (6, 2, 7, 5, 4, 1):
        bits.write_bits(1 if raw_guid[index] else 0, 1)
    bits.write_bits(status, 2)
    for index in (3, 0):
        bits.write_bits(1 if raw_guid[index] else 0, 1)

    payload = bytearray(bits.getvalue())
    _append_xor_guid_bytes(payload, raw_guid, (0, 5, 2, 1, 4, 6, 7, 3))
    return bytes(payload)


def _taxi_node_status_for_guid(session, guid: int) -> int:
    node = _taxi_node_for_npc_guid(session, int(guid))
    if node is None:
        return _TAXI_NODE_STATUS_KNOWN
    if int(node.node_id) in set(_known_taxi_node_ids(session)):
        return _TAXI_NODE_STATUS_KNOWN
    return _TAXI_NODE_STATUS_UNKNOWN


def _build_taxi_node_status_response(session, guid: int) -> tuple[str, bytes]:
    status = _taxi_node_status_for_guid(session, int(guid))
    return ("SMSG_TAXI_NODE_STATUS", build_taxi_node_status_payload(guid, known=status))


def _learn_current_taxi_node_responses(session, *, reason: str, guid: int = 0) -> list[tuple[str, bytes]]:
    current = _taxi_node_for_npc_guid(session, int(guid)) if int(guid or 0) else _nearest_taxi_node(session)
    current_node_id = int(current.node_id) if current is not None else 0
    known_before = current_node_id in set(_known_taxi_node_ids(session))

    discovered_node_id = _discover_taxi_node(session, current, reason=reason)
    if current_node_id <= 0 or int(discovered_node_id) != current_node_id or known_before:
        return []
    if current_node_id not in set(_known_taxi_node_ids(session)):
        return []
    return [("SMSG_NEW_TAXI_PATH", b"")]


def build_show_taxi_nodes_payload(session, guid: int) -> bytes:
    raw_guid = int(guid or 0).to_bytes(8, "little", signed=False)
    current = _taxi_node_for_npc_guid(session, int(guid)) if int(guid or 0) else _nearest_taxi_node(session)
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


def _player_update_guid(session) -> int:
    return int(
        getattr(session, "char_guid", 0)
        or getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or 0
    )


def _build_money_update_response(session) -> tuple[str, bytes]:
    from server.modules.handlers.world.bootstrap.playerobjects import build_multi_u32_update_object_payload

    money_value = int(getattr(session, "money", 0) or 0) & 0xFFFFFFFFFFFFFFFF
    return (
        "SMSG_UPDATE_OBJECT",
        build_multi_u32_update_object_payload(
            map_id=int(getattr(session, "map_id", 0) or 0),
            guid=_player_update_guid(session),
            field_updates=[
                (_PLAYER_FIELD_COINAGE, money_value & 0xFFFFFFFF),
                (_PLAYER_FIELD_COINAGE + 1, (money_value >> 32) & 0xFFFFFFFF),
            ],
        ),
    )


def _persist_player_money(session) -> None:
    from server.modules.database.DatabaseConnection import DatabaseConnection

    DatabaseConnection.update_character_money(
        int(getattr(session, "char_guid", 0) or 0),
        int(getattr(session, "realm_id", 0) or 0),
        int(getattr(session, "money", 0) or 0),
    )


def _taxi_route_fare(node_ids: tuple[int, ...]) -> int | None:
    if len(node_ids) < 2:
        return 0

    paths = _load_taxi_paths_by_nodes()
    total = 0
    for source_node, destination_node in zip(node_ids, node_ids[1:]):
        taxi_path = paths.get((int(source_node), int(destination_node)))
        if taxi_path is None:
            return None
        total += max(0, int(taxi_path.price or 0))
    return int(total)


def _charge_taxi_fare(session, fare: int) -> tuple[bool, list[tuple[str, bytes]]]:
    fare = max(0, int(fare or 0))
    if fare <= 0:
        return True, []

    current_money = max(0, int(getattr(session, "money", 0) or 0))
    if current_money < fare:
        Logger.info(
            "[TaxiFare] insufficient player=%s fare=%s money=%s",
            int(getattr(session, "char_guid", 0) or 0),
            int(fare),
            int(current_money),
        )
        return False, []

    session.money = current_money - fare
    try:
        _persist_player_money(session)
    except Exception as exc:
        Logger.warning(
            "[TaxiFare] DB update failed player=%s fare=%s money=%s error=%s",
            int(getattr(session, "char_guid", 0) or 0),
            int(fare),
            int(getattr(session, "money", 0) or 0),
            exc,
        )
    return True, [_build_money_update_response(session)]


def _insufficient_taxi_fare_response() -> list[tuple[str, bytes]]:
    return [(
        "SMSG_ACTIVATE_TAXI_REPLY",
        build_activate_taxi_reply_payload(_TAXI_ACTIVATE_NOT_ENOUGH_MONEY),
    )]


def _validate_and_charge_taxi_fare(
    session,
    route_nodes: tuple[int, ...],
) -> tuple[bool, list[tuple[str, bytes]]]:
    fare = _taxi_route_fare(route_nodes)
    if fare is None:
        Logger.warning("[TaxiFare] missing route fare nodes=%s", list(route_nodes))
        return False, []

    fare_ok, money_responses = _charge_taxi_fare(session, fare)
    if not fare_ok:
        return False, _insufficient_taxi_fare_response()

    return True, money_responses


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


def _taxi_destination_landing_point(node_id: int) -> TaxiPathPoint | None:
    destination = _taxi_destination_position(int(node_id))
    if destination is None:
        return None
    return TaxiPathPoint(
        float(destination[1]),
        float(destination[2]),
        float(destination[3]),
        None,
        int(destination[0]),
    )


def _taxi_node_point(node_id: int) -> TaxiPathPoint | None:
    destination = _taxi_destination_position(int(node_id))
    if destination is None:
        return None
    return TaxiPathPoint(
        float(destination[1]),
        float(destination[2]),
        float(destination[3]),
        None,
        int(destination[0]),
    )


def _taxi_transfer_point_for_leg(
    source_node: int,
    destination_node: int,
    destination_map: int,
) -> TaxiPathPoint | None:
    taxi_path = _load_taxi_paths_by_nodes().get((int(source_node), int(destination_node)))
    if taxi_path is None:
        return None

    path_points = _load_taxi_path_points_by_path().get(int(taxi_path.path_id), ()) or ()
    for point in path_points:
        if point.map_id is not None and int(point.map_id) == int(destination_map):
            return point
    return None


def _taxi_path_points_for_map_leg(
    session,
    source_node: int,
    destination_node: int,
    map_id: int,
) -> list[TaxiPathPoint]:
    taxi_path = _load_taxi_paths_by_nodes().get((int(source_node), int(destination_node)))
    if taxi_path is None:
        return []

    path_points = _load_taxi_path_points_by_path().get(int(taxi_path.path_id), ()) or ()
    points = [
        TaxiPathPoint(
            float(getattr(session, "x", 0.0) or 0.0),
            float(getattr(session, "y", 0.0) or 0.0),
            float(getattr(session, "z", 0.0) or 0.0),
            float(getattr(session, "orientation", 0.0) or 0.0),
            int(map_id),
        )
    ]
    for point in path_points:
        if point.map_id is None or int(point.map_id) != int(map_id):
            continue
        last = points[-1]
        if _taxi_point_distance(last, point) > 1.0:
            points.append(point)

    if len(points) < 2:
        return points
    return _resample_taxi_points(points, _TAXI_RESAMPLE_DISTANCE_YARDS)


def _taxi_path_points_from_nodes(session, node_ids: tuple[int, ...]) -> tuple[int, list[TaxiPathPoint]]:
    nodes = _load_taxi_nodes()
    map_id = int(getattr(session, "map_id", 0) or 0)
    points = [
        TaxiPathPoint(
            float(getattr(session, "x", 0.0) or 0.0),
            float(getattr(session, "y", 0.0) or 0.0),
            float(getattr(session, "z", 0.0) or 0.0),
            float(getattr(session, "orientation", 0.0) or 0.0),
            map_id,
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
                map_id=end.map_id,
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


def _begin_cross_map_taxi_transfer(
    session,
    *,
    source_node: int,
    destination_node: int,
) -> list[tuple[str, bytes]]:
    state = getattr(session, "taxi_state", None)
    _taxi_xmap_debug(
        "[TAXI_XMAP_DEBUG] transfer_begin_enter player=%s route=%s leg=%s "
        "source=%s destination=%s current_map=%s phase=%s pending=%s",
        int(getattr(session, "char_guid", 0) or 0),
        list(getattr(state, "route_nodes", ()) or ()) if state is not None else [],
        int(getattr(state, "current_leg_index", -1) if state is not None else -1),
        int(source_node),
        int(destination_node),
        int(getattr(session, "map_id", 0) or 0),
        str(getattr(state, "phase", "")) if state is not None else "",
        getattr(session, "pending_taxi_transfer", None),
    )
    destination = _taxi_destination_position(int(destination_node))
    if destination is None:
        Logger.warning(
            "[TAXI] cross-map transfer rejected reason=missing_destination source=%s destination=%s",
            int(source_node),
            int(destination_node),
        )
        complete_taxi_spline(session)
        return []

    source_map = int(getattr(session, "map_id", 0) or 0)
    destination_map = int(destination[0])
    if destination_map == source_map:
        _taxi_xmap_debug(
            "[TAXI_XMAP_DEBUG] transfer_begin_noop player=%s source=%s destination=%s "
            "map=%s phase=%s pending=%s",
            int(getattr(session, "char_guid", 0) or 0),
            int(source_node),
            int(destination_node),
            int(source_map),
            str(getattr(state, "phase", "")) if state is not None else "",
            getattr(session, "pending_taxi_transfer", None),
        )
        return []

    transfer_point = _taxi_transfer_point_for_leg(
        int(source_node),
        int(destination_node),
        int(destination_map),
    )
    if transfer_point is None:
        transfer_point = _taxi_node_point(int(destination_node))
        Logger.warning(
            "[TAXI] cross-map transfer using destination fallback "
            "source=%s destination=%s destination_map=%s",
            int(source_node),
            int(destination_node),
            int(destination_map),
        )
    if transfer_point is None or transfer_point.map_id is None:
        Logger.warning(
            "[TAXI] cross-map transfer rejected reason=missing_transfer_point "
            "source=%s destination=%s destination_map=%s",
            int(source_node),
            int(destination_node),
            int(destination_map),
        )
        complete_taxi_spline(session)
        return []

    sync_taxi_to_current_destination(session)
    state = getattr(session, "taxi_state", None)
    if state is not None:
        state.active = True
        state.phase = "TAXI_TRANSFER"

    from server.modules.handlers.world.teleport.lifecycle import get_teleport_lifecycle

    transition_generation = get_teleport_lifecycle().begin_owned_transition(
        session,
        owner="taxi_worldport",
    )
    session.pending_taxi_transfer = {
        "source_map": int(source_map),
        "destination_map": int(destination_map),
        "source_node": int(source_node),
        "destination_node": int(destination_node),
        "world_transition_generation": int(transition_generation),
    }

    clear_player_transport_state(
        session,
        reason="teleport",
        opcode_name="taxi_map_transfer",
    )
    from server.modules.handlers.world.teleport.map_transfer import TeleportDestination

    responses = get_teleport_lifecycle().perform_owned_worldport(
        session,
        TeleportDestination(
            map_id=int(destination_map),
            x=float(transfer_point.x),
            y=float(transfer_point.y),
            z=float(transfer_point.z),
            orientation=float(getattr(session, "orientation", 0.0) or 0.0),
            name=f"taxi:{int(source_node)}->{int(destination_node)}",
        ),
        reason="taxi",
        synchronize_membership=False,
        resolve_area=False,
        _attach_world=attach_session_to_world_state,
    )
    sync_flight_path_runtime_from_session(session)
    Logger.info(
        "[TAXI] cross-map transfer player=%s source_node=%s destination_node=%s map=%s->%s",
        int(getattr(session, "char_guid", 0) or 0),
        int(source_node),
        int(destination_node),
        int(source_map),
        int(destination_map),
    )
    _taxi_xmap_debug(
        "[TAXI_XMAP_DEBUG] transfer_begin_packets player=%s route=%s leg=%s "
        "source=%s destination=%s source_map=%s destination_map=%s phase=%s "
        "pending=%s packets=%s",
        int(getattr(session, "char_guid", 0) or 0),
        list(getattr(state, "route_nodes", ()) or ()) if state is not None else [],
        int(getattr(state, "current_leg_index", -1) if state is not None else -1),
        int(source_node),
        int(destination_node),
        int(source_map),
        int(destination_map),
        str(getattr(state, "phase", "")) if state is not None else "",
        getattr(session, "pending_taxi_transfer", None),
        [opcode for opcode, _payload in responses],
    )
    return bind_packet_batch_to_current_transition(session, responses)


def continue_pending_cross_map_taxi(session) -> list[tuple[str, bytes]]:
    pending = getattr(session, "pending_taxi_transfer", None)
    state = getattr(session, "taxi_state", None)
    _taxi_xmap_debug(
        "[TAXI_XMAP_DEBUG] continue_pending_enter player=%s route=%s leg=%s "
        "map=%s phase=%s pending=%s",
        int(getattr(session, "char_guid", 0) or 0),
        list(getattr(state, "route_nodes", ()) or ()) if state is not None else [],
        int(getattr(state, "current_leg_index", -1) if state is not None else -1),
        int(getattr(session, "map_id", 0) or 0),
        str(getattr(state, "phase", "")) if state is not None else "",
        pending,
    )
    if not isinstance(pending, dict):
        return []

    source_node = int(pending.get("source_node", 0) or 0)
    destination_node = int(pending.get("destination_node", 0) or 0)
    destination = _taxi_destination_position(destination_node)
    if source_node <= 0 or destination is None:
        session.pending_taxi_transfer = None
        complete_taxi_spline(session)
        return []

    destination_map = int(destination[0])
    if destination_map != int(getattr(session, "map_id", 0) or 0):
        Logger.warning(
            "[TAXI] cross-map continuation rejected destination=%s map=%s current_map=%s",
            int(destination_node),
            int(destination_map),
            int(getattr(session, "map_id", 0) or 0),
        )
        session.pending_taxi_transfer = None
        complete_taxi_spline(session)
        return []

    session.pending_taxi_transfer = None
    map_id = int(destination_map)
    path_points = _taxi_path_points_for_map_leg(session, source_node, destination_node, map_id)
    if len(path_points) < 2:
        Logger.warning(
            "[TAXI] cross-map continuation missing destination-map path points "
            "source=%s destination=%s map=%s",
            int(source_node),
            int(destination_node),
            int(map_id),
        )
        complete_taxi_spline(session)
        return []
    Logger.info(
        "[TAXI] cross-map continuation player=%s source=%s destination=%s map=%s",
        int(getattr(session, "char_guid", 0) or 0),
        int(source_node),
        int(destination_node),
        int(map_id),
    )
    responses = continue_taxi_flight(
        session,
        path_points,
        destination_map=map_id,
        destination_node=destination_node,
        source_node=source_node,
        destination_landing_point=_taxi_destination_landing_point(destination_node),
    )
    state = getattr(session, "taxi_state", None)
    _taxi_xmap_debug(
        "[TAXI_XMAP_DEBUG] continue_pending_exit player=%s route=%s leg=%s "
        "source=%s destination=%s map=%s phase=%s pending=%s packets=%s",
        int(getattr(session, "char_guid", 0) or 0),
        list(getattr(state, "route_nodes", ()) or ()) if state is not None else [],
        int(getattr(state, "current_leg_index", -1) if state is not None else -1),
        int(source_node),
        int(destination_node),
        int(map_id),
        str(getattr(state, "phase", "")) if state is not None else "",
        getattr(session, "pending_taxi_transfer", None),
        [opcode for opcode, _payload in responses],
    )
    return responses


@register("CMSG_GOSSIP_HELLO")
def handle_gossip_hello(session, ctx):
    data = _payload(ctx)
    guid = _select_gossip_guid(session, data)
    is_taxi = _can_use_taxi_interaction(session, guid)
    Logger.info(
        "[Taxi] CMSG_GOSSIP_HELLO guid=0x%016X is_taxi=%s len=%s",
        int(guid),
        int(is_taxi),
        len(data),
    )
    if not is_taxi:
        try:
            from server.modules.handlers.world.opcodes import npc_interaction

            npc_responses = npc_interaction.handle_gossip_hello_for_npc(session, guid, data)
            if npc_responses is not None:
                return 0, npc_responses
        except Exception as exc:
            Logger.warning("[Taxi] NPC gossip fallback unavailable err=%s", exc)
        return 0, [("SMSG_GOSSIP_COMPLETE", b"")]

    responses = _learn_current_taxi_node_responses(session, reason="gossip", guid=guid)
    if responses:
        responses.append(_build_taxi_node_status_response(session, guid))
        return 0, responses

    responses.extend([
        _build_taxi_node_status_response(session, guid),
        ("SMSG_SHOW_TAXI_NODES", build_show_taxi_nodes_payload(session, guid)),
    ])
    return 0, responses


@register("CMSG_TAXI_NODE_STATUS_QUERY")
def handle_taxi_node_status_query(session, ctx):
    data = _payload(ctx)
    guid = _decode_taxi_node_status_guid(data)
    Logger.info("[Taxi] CMSG_TAXI_NODE_STATUS_QUERY guid=0x%016X len=%s", int(guid), len(data))
    return 0, [_build_taxi_node_status_response(session, guid)]


@register("CMSG_ENABLE_TAXI")
def handle_enable_taxi(session, ctx):
    data = _payload(ctx)
    guid = _decode_enable_taxi_guid(data)
    is_taxi = _can_use_taxi_interaction(session, guid)
    Logger.info(
        "[Taxi] CMSG_ENABLE_TAXI guid=0x%016X is_taxi=%s len=%s",
        int(guid),
        int(is_taxi),
        len(data),
    )
    if not is_taxi:
        return 0, []

    responses = _learn_current_taxi_node_responses(session, reason="enable_taxi", guid=guid)
    if responses:
        responses.append(_build_taxi_node_status_response(session, guid))
    return 0, responses


@register("CMSG_TAXI_QUERY_AVAILABLE_NODES")
def handle_taxi_query_available_nodes(session, ctx):
    data = _payload(ctx)
    guid = _decode_taxi_available_nodes_guid(data)
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

    responses = _learn_current_taxi_node_responses(session, reason="query", guid=guid)
    if responses:
        responses.append(_build_taxi_node_status_response(session, guid))
        return 0, responses

    responses.extend([
        _build_taxi_node_status_response(session, guid),
        ("SMSG_SHOW_TAXI_NODES", build_show_taxi_nodes_payload(session, guid)),
    ])
    return 0, responses


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
    if not _taxi_route_nodes_known(session, (source_node, destination_node)):
        Logger.info(
            "[TaxiDiscovery] reject unknown route source=%s destination=%s",
            int(source_node),
            int(destination_node),
        )
        return 0, responses
    route_nodes = (source_node, destination_node)
    if is_taxi_active(session):
        Logger.info(
            "[Taxi] reject activation while taxi active source=%s destination=%s",
            source_node,
            destination_node,
        )
        return 0, responses

    source_map = int(getattr(session, "map_id", 0) or 0)
    destination_map = int(destination[0])
    current_leg_index = 0
    if destination_map != source_map:
        map_id = int(source_map)
        path_points = _taxi_path_points_for_map_leg(
            session,
            source_node,
            destination_node,
            map_id,
        )
        current_leg_index = -1
    else:
        map_id, path_points = _taxi_path_points_from_nodes(session, route_nodes)
    if len(path_points) < 2:
        return 0, responses
    fare_ok, money_responses = _validate_and_charge_taxi_fare(session, route_nodes)
    if not fare_ok:
        return 0, money_responses or responses
    responses.extend(money_responses)
    responses.extend(
        start_taxi_flight(
            session,
            path_points,
            destination_map=map_id,
            destination_node=destination_node,
            source_node=source_node,
            mount_display_id=_taxi_mount_display_id_for_source(session, source_node),
            route_nodes=route_nodes,
            current_leg_index=current_leg_index,
            destination_landing_point=_taxi_destination_landing_point(destination_node),
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
    route_nodes = tuple(int(node_id) for node_id in nodes)
    if not _taxi_route_nodes_known(session, route_nodes):
        Logger.info("[TaxiDiscovery] reject unknown express route nodes=%s", list(route_nodes))
        return 0, responses
    if is_taxi_active(session):
        Logger.info(
            "[Taxi] reject express activation while taxi active nodes=%s",
            list(route_nodes),
        )
        return 0, responses

    first_destination_node = int(nodes[1]) if len(nodes) > 1 else destination_node
    destination = _taxi_destination_position(first_destination_node)
    if destination is None:
        return 0, responses

    source_map = int(getattr(session, "map_id", 0) or 0)
    destination_map = int(destination[0])
    current_leg_index = 0
    if destination_map != source_map:
        map_id = int(source_map)
        path_points = _taxi_path_points_for_map_leg(
            session,
            source_node,
            first_destination_node,
            map_id,
        )
        current_leg_index = -1
    else:
        map_id, path_points = _taxi_path_points_from_nodes(session, route_nodes[:2])
    if len(path_points) < 2:
        return 0, responses
    fare_ok, money_responses = _validate_and_charge_taxi_fare(session, route_nodes)
    if not fare_ok:
        return 0, money_responses or responses
    responses.extend(money_responses)
    responses.extend(
        start_taxi_flight(
            session,
            path_points,
            destination_map=map_id,
            destination_node=first_destination_node,
            source_node=source_node,
            mount_display_id=_taxi_mount_display_id_for_source(session, source_node),
            route_nodes=route_nodes,
            current_leg_index=current_leg_index,
            destination_landing_point=_taxi_destination_landing_point(first_destination_node),
        )
    )
    return 0, responses


@register("CMSG_MOVE_SPLINE_DONE")
def handle_move_spline_done(session, ctx):
    state = getattr(session, "taxi_state", None)
    _taxi_xmap_debug(
        "[TAXI_XMAP_DEBUG] spline_done_enter player=%s map=%s state_exists=%s "
        "active=%s completed=%s route=%s leg=%s phase=%s pending=%s",
        int(getattr(session, "char_guid", 0) or 0),
        int(getattr(session, "map_id", 0) or 0),
        int(state is not None),
        int(bool(getattr(state, "active", False))) if state is not None else 0,
        int(bool(getattr(state, "completed", False))) if state is not None else 0,
        list(getattr(state, "route_nodes", ()) or ()) if state is not None else [],
        int(getattr(state, "current_leg_index", -1) if state is not None else -1),
        str(getattr(state, "phase", "")) if state is not None else "",
        getattr(session, "pending_taxi_transfer", None),
    )
    if state is None or not bool(getattr(state, "active", False)):
        return 0, None

    route_nodes = tuple(int(node) for node in getattr(state, "route_nodes", ()) or ())
    current_leg_index = int(getattr(state, "current_leg_index", 0) or 0)
    next_source_index = current_leg_index + 1
    next_destination_index = current_leg_index + 2
    _taxi_xmap_debug(
        "[TAXI_XMAP_DEBUG] spline_done_indices player=%s route=%s leg=%s "
        "next_source_index=%s next_destination_index=%s route_len=%s",
        int(getattr(session, "char_guid", 0) or 0),
        list(route_nodes),
        int(current_leg_index),
        int(next_source_index),
        int(next_destination_index),
        int(len(route_nodes)),
    )
    if route_nodes and next_destination_index < len(route_nodes):
        source_node = int(route_nodes[next_source_index])
        destination_node = int(route_nodes[next_destination_index])
        destination = _taxi_destination_position(destination_node)
        if destination is None:
            _taxi_xmap_debug(
                "[TAXI_XMAP_DEBUG] spline_done_missing_destination player=%s "
                "source=%s destination=%s route=%s leg=%s",
                int(getattr(session, "char_guid", 0) or 0),
                int(source_node),
                int(destination_node),
                list(route_nodes),
                int(current_leg_index),
            )
            complete_taxi_spline(session)
            return 0, None
        destination_map = int(destination[0])
        _taxi_xmap_debug(
            "[TAXI_XMAP_DEBUG] spline_done_next_leg player=%s source=%s "
            "destination=%s current_map=%s destination_map=%s route=%s leg=%s "
            "phase=%s pending=%s",
            int(getattr(session, "char_guid", 0) or 0),
            int(source_node),
            int(destination_node),
            int(getattr(session, "map_id", 0) or 0),
            int(destination_map),
            list(route_nodes),
            int(current_leg_index),
            str(getattr(state, "phase", "")),
            getattr(session, "pending_taxi_transfer", None),
        )
        if destination_map != int(getattr(session, "map_id", 0) or 0):
            return 0, _begin_cross_map_taxi_transfer(
                session,
                source_node=source_node,
                destination_node=destination_node,
            )
        sync_taxi_to_current_destination(session)
        map_id, path_points = _taxi_path_points_from_nodes(session, (source_node, destination_node))
        responses = continue_taxi_flight(
            session,
            path_points,
            destination_map=map_id,
            destination_node=destination_node,
            source_node=source_node,
            destination_landing_point=_taxi_destination_landing_point(destination_node),
        )
        _taxi_xmap_debug(
            "[TAXI_XMAP_DEBUG] spline_done_same_map_continue player=%s "
            "source=%s destination=%s map=%s packets=%s",
            int(getattr(session, "char_guid", 0) or 0),
            int(source_node),
            int(destination_node),
            int(map_id),
            [opcode for opcode, _payload in responses],
        )
        return 0, responses

    _taxi_xmap_debug(
        "[TAXI_XMAP_DEBUG] spline_done_final_complete player=%s route=%s leg=%s "
        "map=%s phase=%s pending=%s",
        int(getattr(session, "char_guid", 0) or 0),
        list(route_nodes),
        int(current_leg_index),
        int(getattr(session, "map_id", 0) or 0),
        str(getattr(state, "phase", "")),
        getattr(session, "pending_taxi_transfer", None),
    )
    complete_taxi_spline(session)
    return 0, None
