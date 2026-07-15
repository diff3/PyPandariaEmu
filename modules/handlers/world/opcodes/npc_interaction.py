#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Minimal NPC interaction support for innkeepers and Hearthstone binding."""

from __future__ import annotations

import math
import struct
from typing import Optional

from DSL.modules.bitsHandler import BitInterPreter, BitWriter
from shared.Logger import Logger
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.game.guid import GuidHelper
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from server.modules.handlers.world.dispatcher import register
from server.modules.handlers.world.login.packets import build_login_packet
from server.modules.protocol.PacketContext import PacketContext


UNIT_NPC_FLAG_INNKEEPER = 0x00010000
HEARTHSTONE_SPELL_ID = 8690
HEARTHSTONE_ITEM_ID = 6948
_NEARBY_INNKEEPER_RANGE = 8.0
_GOSSIP_BIND_OPTION_TEXT = "Make this inn your home."
_GOSSIP_ICON_INTERACT_1 = 4


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
) -> int:
    if not data:
        return 0

    byte_pos = 0
    bit_pos = 0
    mask: dict[int, int] = {}
    for index in bit_order:
        if byte_pos >= len(data):
            return 0
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


def decode_gossip_guid(data: bytes) -> int:
    return _decode_bitpacked_guid(
        data,
        bit_order=(2, 4, 0, 3, 6, 7, 5, 1),
        byte_order=(4, 7, 1, 0, 5, 3, 6, 2),
    )


def decode_binder_activate_guid(data: bytes) -> int:
    return _decode_bitpacked_guid(
        data,
        bit_order=(0, 5, 4, 7, 6, 2, 1, 3),
        byte_order=(0, 4, 2, 3, 7, 1, 5, 6),
    )


def decode_list_inventory_guid(data: bytes) -> int:
    return _decode_bitpacked_guid(
        data,
        bit_order=(6, 7, 3, 1, 2, 0, 4, 5),
        byte_order=(0, 7, 1, 6, 4, 3, 5, 2),
    )


def _npc_flags(session, guid: int) -> int:
    npc_flags_by_guid = getattr(session, "npc_flags_by_guid", None)
    if not isinstance(npc_flags_by_guid, dict):
        return 0

    flags = int(npc_flags_by_guid.get(int(guid), 0) or 0)
    if flags:
        return flags

    try:
        low_guid = int(GuidHelper.decode(int(guid)).low)
    except Exception:
        low_guid = 0
    return int(npc_flags_by_guid.get(low_guid, 0) or 0)


def _is_innkeeper_npc(session, guid: int) -> bool:
    if _npc_flags(session, int(guid)) & UNIT_NPC_FLAG_INNKEEPER:
        return True

    names_by_guid = getattr(session, "npc_names_by_guid", None)
    if not isinstance(names_by_guid, dict):
        return False

    name = str(names_by_guid.get(int(guid), "") or "").strip().lower()
    return "barkeep" in name or "barkeeper" in name


def _nearest_innkeeper_guid(session) -> int:
    positions = getattr(session, "npc_positions_by_guid", None)
    flags_by_guid = getattr(session, "npc_flags_by_guid", None)
    if not isinstance(positions, dict) or not isinstance(flags_by_guid, dict):
        return 0

    map_id = int(getattr(session, "map_id", 0) or 0)
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)
    z = float(getattr(session, "z", 0.0) or 0.0)
    best_guid = 0
    best_distance = float("inf")

    for guid, position in positions.items():
        if not _is_innkeeper_npc(session, int(guid)):
            continue
        if len(position) < 4:
            continue
        npc_map, npc_x, npc_y, npc_z = int(position[0]), float(position[1]), float(position[2]), float(position[3])
        if npc_map != map_id:
            continue
        dx = npc_x - x
        dy = npc_y - y
        dz = npc_z - z
        distance = math.sqrt((dx * dx) + (dy * dy) + (dz * dz))
        if distance < best_distance:
            best_guid = int(guid)
            best_distance = distance

    if best_distance > _NEARBY_INNKEEPER_RANGE:
        return 0
    return int(best_guid)


def _resolve_innkeeper_guid(session, guid: int) -> int:
    if int(guid or 0) > 0 and _is_innkeeper_npc(session, int(guid)):
        return int(guid)

    gossip_guid = int(getattr(session, "gossip_npc_guid", 0) or 0)
    if gossip_guid > 0 and _is_innkeeper_npc(session, gossip_guid):
        return gossip_guid

    return _nearest_innkeeper_guid(session)


def build_gossip_message_payload(npc_guid: int) -> bytes:
    raw_guid = int(npc_guid or 0).to_bytes(8, "little", signed=False)
    option_text = _GOSSIP_BIND_OPTION_TEXT.encode("utf-8")
    box_text = b""

    bits = BitWriter()
    bits.write_bits(0, 19)  # quest gossip count
    for index in (5, 7, 4, 0):
        bits.write_bits(1 if raw_guid[index] else 0, 1)
    bits.write_bits(1, 20)  # option count
    for index in (6, 2):
        bits.write_bits(1 if raw_guid[index] else 0, 1)
    bits.write_bits(len(box_text), 12)
    bits.write_bits(len(option_text), 12)
    for index in (3, 1):
        bits.write_bits(1 if raw_guid[index] else 0, 1)

    payload = bytearray(bits.getvalue())
    _append_xor_guid_bytes(payload, raw_guid, (1, 0))
    payload.extend(struct.pack("<I", 0))  # box money
    payload.extend(box_text)
    payload.extend(struct.pack("<I", 0))  # client gossip option index
    payload.extend(struct.pack("<B", 0))  # box coded
    payload.extend(option_text)
    payload.extend(struct.pack("<B", _GOSSIP_ICON_INTERACT_1))
    _append_xor_guid_bytes(payload, raw_guid, (5, 3))
    payload.extend(struct.pack("<I", 0))  # menu id
    _append_xor_guid_bytes(payload, raw_guid, (2, 6, 4))
    payload.extend(struct.pack("<I", 0))  # friendship faction id
    _append_xor_guid_bytes(payload, raw_guid, (7,))
    payload.extend(struct.pack("<I", 0))  # text id
    return bytes(payload)


def build_binder_confirm_payload(npc_guid: int) -> bytes:
    raw_guid = int(npc_guid or 0).to_bytes(8, "little", signed=False)
    bits = BitWriter()
    for index in (4, 6, 2, 1, 5, 3, 0, 7):
        bits.write_bits(1 if raw_guid[index] else 0, 1)
    payload = bytearray(bits.getvalue())
    _append_xor_guid_bytes(payload, raw_guid, (6, 2, 5, 0, 4, 7, 1, 3))
    return bytes(payload)


def build_playerbound_payload(npc_guid: int, area_id: int) -> bytes:
    raw_guid = int(npc_guid or 0).to_bytes(8, "little", signed=False)
    bits = BitWriter()
    for index in (2, 4, 0, 3, 6, 7, 5, 1):
        bits.write_bits(1 if raw_guid[index] else 0, 1)
    payload = bytearray(bits.getvalue())
    _append_xor_guid_bytes(payload, raw_guid, (6, 1, 2, 3, 4, 5, 7, 0))
    payload.extend(struct.pack("<I", int(area_id or 0) & 0xFFFFFFFF))
    return bytes(payload)


def _bind_context_from_session(session):
    return type(
        "BindContext",
        (),
        {
            "bind_map_id": int(getattr(session, "bind_map_id", 0) or 0),
            "bind_area_id": int(getattr(session, "bind_area_id", 0) or 0),
            "bind_x": float(getattr(session, "bind_x", 0.0) or 0.0),
            "bind_y": float(getattr(session, "bind_y", 0.0) or 0.0),
            "bind_z": float(getattr(session, "bind_z", 0.0) or 0.0),
            "x": float(getattr(session, "x", 0.0) or 0.0),
            "y": float(getattr(session, "y", 0.0) or 0.0),
            "z": float(getattr(session, "z", 0.0) or 0.0),
            "map_id": int(getattr(session, "map_id", 0) or 0),
            "zone": int(getattr(session, "zone", 0) or 0),
        },
    )()


def restore_homebind_from_database(session) -> None:
    char_guid = int(getattr(session, "char_guid", 0) or 0)
    realm_id = int(getattr(session, "realm_id", 0) or 0)
    row = DatabaseConnection.load_character_homebind(char_guid, realm_id)
    if not row:
        session.bind_map_id = int(getattr(session, "map_id", 0) or 0)
        session.bind_area_id = int(getattr(session, "zone", 0) or 0)
        session.bind_x = float(getattr(session, "x", 0.0) or 0.0)
        session.bind_y = float(getattr(session, "y", 0.0) or 0.0)
        session.bind_z = float(getattr(session, "z", 0.0) or 0.0)
        session.bind_o = float(getattr(session, "orientation", 0.0) or 0.0)
        return

    session.bind_map_id = int(row.get("mapId", 0) or 0)
    session.bind_area_id = int(row.get("zoneId", 0) or 0)
    session.bind_x = float(row.get("posX", 0.0) or 0.0)
    session.bind_y = float(row.get("posY", 0.0) or 0.0)
    session.bind_z = float(row.get("posZ", 0.0) or 0.0)
    session.bind_o = float(row.get("orientation", 0.0) or 0.0)
    Logger.info(
        "[Innkeeper] bind restore guid=%s map=%s zone=%s pos=(%.3f %.3f %.3f %.3f)",
        int(char_guid),
        int(session.bind_map_id),
        int(session.bind_area_id),
        float(session.bind_x),
        float(session.bind_y),
        float(session.bind_z),
        float(session.bind_o),
    )


def handle_gossip_hello_for_npc(session, guid: int, data: bytes) -> Optional[list[tuple[str, bytes]]]:
    try:
        from server.modules.handlers.world.features.halfhill_farming.farmer_yoon import (
            handle_farmer_yoon_interaction,
        )

        names = getattr(session, "npc_names_by_guid", None)
        if isinstance(names, dict):
            target_guid = int(guid or 0)
            candidate_guids = [target_guid]
            try:
                candidate_guids.append(int(GuidHelper.decode(target_guid).low))
            except Exception:
                pass
            for candidate_guid in candidate_guids:
                name = str(names.get(int(candidate_guid or 0), "") or "").strip().lower()
                if name != "farmer yoon":
                    continue
                session.gossip_npc_guid = int(target_guid or candidate_guid)
                session.gossip_npc_flags = int(_npc_flags(session, session.gossip_npc_guid))
                return handle_farmer_yoon_interaction(session, int(target_guid or candidate_guid))
    except Exception as exc:
        Logger.warning("[HalfhillFarm] Farmer Yoon gossip failed: %s", exc)

    innkeeper_guid = _resolve_innkeeper_guid(session, int(guid or 0))
    if innkeeper_guid <= 0:
        return None

    # TODO: Future NPC systems can add merchant/RP options here without changing taxi flow.
    flags = _npc_flags(session, innkeeper_guid)
    session.gossip_npc_guid = int(innkeeper_guid)
    session.gossip_npc_flags = int(flags)
    Logger.info(
        "[Innkeeper] gossip open guid=0x%016X flags=0x%X len=%s",
        int(innkeeper_guid),
        int(flags),
        len(data),
    )
    return [("SMSG_BINDER_CONFIRM", build_binder_confirm_payload(innkeeper_guid))]


@register("CMSG_GOSSIP_SELECT_OPTION")
def handle_gossip_select_option(session, ctx: PacketContext):
    # TODO: Parse selected option id when more than one gossip action exists.
    npc_guid = int(getattr(session, "gossip_npc_guid", 0) or 0)
    innkeeper_guid = _resolve_innkeeper_guid(session, npc_guid)
    Logger.info(
        "[Innkeeper] gossip select guid=0x%016X innkeeper=%s len=%s",
        int(innkeeper_guid or npc_guid),
        int(innkeeper_guid > 0),
        len(_payload(ctx)),
    )
    if innkeeper_guid <= 0:
        return 0, [("SMSG_GOSSIP_COMPLETE", b"")]
    return 0, [("SMSG_BINDER_CONFIRM", build_binder_confirm_payload(innkeeper_guid))]


@register("CMSG_LIST_INVENTORY")
def handle_list_inventory_for_barkeep(session, ctx: PacketContext):
    data = _payload(ctx)
    decoded_guid = decode_list_inventory_guid(data)
    innkeeper_guid = _resolve_innkeeper_guid(session, decoded_guid)
    Logger.info(
        "[Innkeeper] list inventory guid=0x%016X resolved=0x%016X len=%s",
        int(decoded_guid),
        int(innkeeper_guid),
        len(data),
    )
    if innkeeper_guid <= 0:
        return 0, None

    session.gossip_npc_guid = int(innkeeper_guid)
    session.gossip_npc_flags = int(_npc_flags(session, innkeeper_guid))
    return 0, [("SMSG_BINDER_CONFIRM", build_binder_confirm_payload(innkeeper_guid))]


def _use_item_bag_slot(data: bytes) -> tuple[int, int]:
    if len(data) < 2:
        return 0, 0
    return int(data[1]) & 0xFF, int(data[0]) & 0xFF


def _inventory_item_at_client_slot(session, bag: int, slot: int):
    state = getattr(session, "inventory_state", None)
    if state is None:
        return None

    internal_bag = 0 if int(bag) in (0, 255) else int(bag)
    getter = getattr(state, "get", None)
    if not callable(getter):
        return None
    return getter(int(internal_bag), int(slot))


def _session_has_hearthstone(session) -> bool:
    state = getattr(session, "inventory_state", None)
    if state is not None:
        items = getattr(state, "items_by_pos", {})
        if isinstance(items, dict):
            for item in items.values():
                if int(getattr(item, "entry", 0) or 0) == HEARTHSTONE_ITEM_ID:
                    return True

    items_by_guid = getattr(session, "inventory_by_guid", {})
    if isinstance(items_by_guid, dict):
        for item in items_by_guid.values():
            if int(getattr(item, "entry", 0) or 0) == HEARTHSTONE_ITEM_ID:
                return True

    return False


@register("CMSG_USE_ITEM")
def handle_use_item(session, ctx: PacketContext):
    try:
        from server.modules.handlers.world.taxi_runtime import is_taxi_active
    except Exception:
        is_taxi_active = None
    if callable(is_taxi_active) and is_taxi_active(session):
        Logger.warning(
            "[TAXI] blocked item use while in flight player=%s",
            int(getattr(session, "char_guid", 0) or 0),
        )
        return 0, None

    data = _payload(ctx)
    bag, slot = _use_item_bag_slot(data)
    item = _inventory_item_at_client_slot(session, bag, slot)
    item_entry = int(getattr(item, "entry", 0) or 0) if item is not None else 0

    Logger.info(
        "[Innkeeper] use item bag=%s slot=%s entry=%s len=%s",
        int(bag),
        int(slot),
        int(item_entry),
        len(data),
    )
    try:
        from server.modules.handlers.world.features.halfhill_farming import (
            get_halfhill_farm_manager,
        )

        farm_responses = get_halfhill_farm_manager().select_seed(
            session,
            item_entry=int(item_entry),
            bag=int(bag),
            slot=int(slot),
        )
        if farm_responses:
            return 0, farm_responses
    except Exception as exc:
        Logger.warning("[HalfhillFarm] seed selection failed: %s", exc)

    if item_entry != HEARTHSTONE_ITEM_ID and not _session_has_hearthstone(session):
        return 0, None

    from server.modules.handlers.world.spell_cast import SpellSource
    from server.modules.handlers.world.spell_cast.service import get_spell_cast_service

    return 0, get_spell_cast_service().begin_cast(
        session,
        spell_id=HEARTHSTONE_SPELL_ID,
        source=SpellSource.ITEM,
        source_item_entry=HEARTHSTONE_ITEM_ID,
    )


@register("CMSG_BINDER_ACTIVATE")
def handle_binder_activate(session, ctx: PacketContext):
    data = _payload(ctx)
    decoded_guid = decode_binder_activate_guid(data)
    innkeeper_guid = _resolve_innkeeper_guid(session, decoded_guid)
    if innkeeper_guid <= 0:
        Logger.warning(
            "[Innkeeper] invalid binder activate guid=0x%016X len=%s",
            int(decoded_guid),
            len(data),
        )
        return 0, [("SMSG_GOSSIP_COMPLETE", b"")]

    map_id = int(getattr(session, "map_id", 0) or 0)
    zone_id = int(getattr(session, "current_area", 0) or getattr(session, "zone", 0) or 0)
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)
    z = float(getattr(session, "z", 0.0) or 0.0)
    orientation = float(getattr(session, "orientation", 0.0) or 0.0)

    saved = DatabaseConnection.save_character_homebind(
        int(getattr(session, "char_guid", 0) or 0),
        int(getattr(session, "realm_id", 0) or 0),
        map_id=map_id,
        zone_id=zone_id,
        x=x,
        y=y,
        z=z,
        orientation=orientation,
    )
    if not saved:
        return 1, None

    session.bind_map_id = map_id
    session.bind_area_id = zone_id
    session.bind_x = x
    session.bind_y = y
    session.bind_z = z
    session.bind_o = orientation
    Logger.info(
        "[Innkeeper] bind save player=%s npc=0x%016X map=%s zone=%s pos=(%.3f %.3f %.3f %.3f)",
        int(getattr(session, "char_guid", 0) or 0),
        int(innkeeper_guid),
        int(map_id),
        int(zone_id),
        x,
        y,
        z,
        orientation,
    )

    bind_update = build_login_packet("SMSG_BIND_POINT_UPDATE", _bind_context_from_session(session))
    return 0, [
        ("SMSG_BIND_POINT_UPDATE", bind_update),
        ("SMSG_PLAYERBOUND", build_playerbound_payload(innkeeper_guid, zone_id)),
        ("SMSG_GOSSIP_COMPLETE", b""),
        ("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload("Your home is now set.")),
    ]


def execute_hearthstone_teleport(session) -> list[tuple[str, bytes]]:
    bind_map = int(getattr(session, "bind_map_id", 0) or getattr(session, "map_id", 0) or 0)
    bind_area = int(getattr(session, "bind_area_id", 0) or getattr(session, "zone", 0) or 0)
    bind_x = float(getattr(session, "bind_x", getattr(session, "x", 0.0)) or 0.0)
    bind_y = float(getattr(session, "bind_y", getattr(session, "y", 0.0)) or 0.0)
    bind_z = float(getattr(session, "bind_z", getattr(session, "z", 0.0)) or 0.0)
    bind_o = float(getattr(session, "bind_o", getattr(session, "orientation", 0.0)) or 0.0)

    session.teleport_destination = f"hearthstone:{bind_map}:{bind_x:.2f}:{bind_y:.2f}:{bind_z:.2f}:{bind_o:.2f}"
    Logger.info(
        "[Innkeeper] hearthstone player=%s map=%s zone=%s pos=(%.3f %.3f %.3f %.3f)",
        int(getattr(session, "char_guid", 0) or 0),
        int(bind_map),
        int(bind_area),
        bind_x,
        bind_y,
        bind_z,
        bind_o,
    )
    from server.modules.handlers.world.opcodes import chat

    teleport_responses = chat.apply_player_state_change(
        session,
        position=(bind_x, bind_y, bind_z, bind_o),
        map_id=bind_map,
    )
    session.current_area = bind_area
    return teleport_responses


def handle_hearthstone_cast(session) -> list[tuple[str, bytes]]:
    """Compatibility entrypoint routed through canonical cast ownership."""
    from server.modules.handlers.world.spell_cast import SpellSource
    from server.modules.handlers.world.spell_cast.service import get_spell_cast_service

    return get_spell_cast_service().begin_cast(session, spell_id=HEARTHSTONE_SPELL_ID, source=SpellSource.SPELL)
