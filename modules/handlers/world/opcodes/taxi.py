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
from server.modules.handlers.world.dispatcher import register
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


_TAXI_NODES: dict[int, TaxiNode] | None = None


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
            )
    except Exception as exc:
        Logger.warning("[Taxi] failed to load TaxiNodes.dbc: %s", exc)

    _TAXI_NODES = nodes
    return _TAXI_NODES


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
    if bool(getattr(session, "taxi_cheat_enabled", False)):
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


def _taxi_destination_position(node_id: int) -> tuple[int, float, float, float, float] | None:
    node = _load_taxi_nodes().get(int(node_id))
    if node is None:
        return None
    return int(node.map_id), float(node.x), float(node.y), float(node.z), 0.0


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

    responses = [("SMSG_ACTIVATE_TAXI_REPLY", build_activate_taxi_reply_payload())]
    destination = _taxi_destination_position(destination_node)
    if destination is None:
        return 0, responses

    from server.modules.handlers.world.opcodes import chat as chat_handlers

    map_id, x, y, z, orientation = destination
    responses.extend(
        chat_handlers.apply_player_state_change(
            session,
            map_id=map_id,
            position=(x, y, z, orientation),
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

    responses = [("SMSG_ACTIVATE_TAXI_REPLY", build_activate_taxi_reply_payload())]
    if destination_node <= 0:
        return 0, responses

    destination = _taxi_destination_position(destination_node)
    if destination is None:
        return 0, responses

    from server.modules.handlers.world.opcodes import chat as chat_handlers

    map_id, x, y, z, orientation = destination
    responses.extend(
        chat_handlers.apply_player_state_change(
            session,
            map_id=map_id,
            position=(x, y, z, orientation),
        )
    )
    return 0, responses
