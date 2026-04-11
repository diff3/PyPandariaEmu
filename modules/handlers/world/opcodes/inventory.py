from __future__ import annotations

import struct
from typing import Optional, Tuple

from DSL.modules.bitsHandler import BitInterPreter, BitWriter
from shared.Logger import Logger
from server.modules.game.inventory import (
    auto_equip_item,
    auto_store_item,
    destroy_character_item,
    move_item_to_root_slot_by_guid,
    swap_character_item,
)
from server.modules.game.guid import GuidHelper
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from server.modules.handlers.world.dispatcher import register
from server.modules.handlers.world.inventory_sync import (
    build_login_inventory_sync_responses,
    build_inventory_delta_responses,
    build_container_open_responses,
    trigger_inventory_activation,
)
from server.modules.handlers.world.packet_logging import log_cmsg
from server.modules.protocol.PacketContext import PacketContext
from server.modules.handlers.world.state.runtime import (
    resync_player_appearance,
)


def _system_message(message: str) -> list[tuple[str, bytes]]:
    return [("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(message))]


def _coerce_guid_int(value) -> int:
    if value is None:
        return 0
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0
        try:
            return int(text, 0)
        except ValueError:
            return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _coerce_int(value, default: int = 0) -> int:
    if value is None:
        return int(default)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return int(default)
        try:
            return int(text, 0)
        except ValueError:
            return int(default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _decoded_first_int(decoded: dict, *keys: str) -> int | None:
    for key in keys:
        if key not in decoded:
            continue
        value = decoded.get(key)
        if value is None or value == "":
            continue
        return _coerce_int(value)
    return None


_ITEM_HIGHGUID = 0x400
_EQUIP_ERR_OK = 0
_EQUIP_ERR_WRONG_SLOT = 3
_EQUIP_ERR_BAG_FULL = 4
_EQUIP_ERR_BAG_IN_BAG = 5
_EQUIP_ERR_CANT_SWAP = 21
_EQUIP_ERR_ITEM_NOT_FOUND = 23
_EQUIP_ERR_DESTROY_NONEMPTY_BAG = 31


def _make_skyfire_guid(low: int, entry: int, high: int) -> int:
    shift = 48 if int(high) in {0xF101, 0xF102} else 52
    return (
        (int(low) & 0xFFFFFFFF)
        | ((int(entry) & 0xFFFFF) << 32)
        | ((int(high) & 0xFFFFF) << shift)
    )


def _make_item_world_guid(item_low_guid: int) -> int:
    return _make_skyfire_guid(int(item_low_guid), 0, _ITEM_HIGHGUID)


def _write_guid_mask_bits(bits: BitWriter, raw_guid: bytes, order: tuple[int, ...]) -> None:
    for index in order:
        bits.write_bits(1 if raw_guid[index] else 0, 1)


def _append_guid_byte_seq(payload: bytearray, raw_guid: bytes, order: tuple[int, ...]) -> None:
    for index in order:
        value = raw_guid[index]
        if value:
            payload.append((value ^ 1) & 0xFF)


def build_inventory_change_failure_payload(
    *,
    error_code: int,
    item_guid: int = 0,
    item_guid2: int = 0,
    bag_type_subclass: int = 0,
) -> bytes:
    raw_guid = int(item_guid or 0).to_bytes(8, "little", signed=False)
    raw_guid2 = int(item_guid2 or 0).to_bytes(8, "little", signed=False)

    bits = BitWriter()
    _write_guid_mask_bits(bits, raw_guid2, (4,))
    _write_guid_mask_bits(bits, raw_guid, (3,))
    _write_guid_mask_bits(bits, raw_guid2, (6, 2))
    _write_guid_mask_bits(bits, raw_guid, (4,))
    _write_guid_mask_bits(bits, raw_guid2, (5,))
    _write_guid_mask_bits(bits, raw_guid, (1, 6))
    _write_guid_mask_bits(bits, raw_guid2, (0, 3, 1))
    _write_guid_mask_bits(bits, raw_guid, (0, 2, 7, 5))
    _write_guid_mask_bits(bits, raw_guid2, (7,))
    bits.flush_to_byte()

    payload = bytearray(bits.buffer)
    _append_guid_byte_seq(payload, raw_guid2, (0,))
    payload.extend(struct.pack("<B", int(bag_type_subclass) & 0xFF))
    _append_guid_byte_seq(payload, raw_guid2, (6,))
    _append_guid_byte_seq(payload, raw_guid, (4, 0, 7, 3))
    _append_guid_byte_seq(payload, raw_guid2, (1, 5))
    _append_guid_byte_seq(payload, raw_guid, (5,))
    _append_guid_byte_seq(payload, raw_guid2, (7, 2))
    _append_guid_byte_seq(payload, raw_guid, (1, 6, 2))
    _append_guid_byte_seq(payload, raw_guid2, (3, 4))
    payload.extend(struct.pack("<B", int(error_code) & 0xFF))
    return bytes(payload)


def _decode_swap_item_payload(raw: bytes) -> tuple[int, int, int, int] | None:
    if len(raw) < 9:
        return None

    src_slot_alt = int(raw[0])
    src_bag_alt = int(raw[1])
    dst_bag_alt = int(raw[2])
    dst_slot_alt = int(raw[3])

    byte_pos = 4
    bit_pos = 0
    count, byte_pos, bit_pos = BitInterPreter.read_bits(raw, byte_pos, bit_pos, 2)
    if int(count) != 2:
        return None

    has_slot: list[bool] = []
    has_bag: list[bool] = []
    for _ in range(2):
        slot_bit, byte_pos, bit_pos = BitInterPreter.read_bit(raw, byte_pos, bit_pos)
        bag_bit, byte_pos, bit_pos = BitInterPreter.read_bit(raw, byte_pos, bit_pos)
        has_slot.append(not bool(slot_bit))
        has_bag.append(not bool(bag_bit))

    if bit_pos != 0:
        byte_pos += 1
        bit_pos = 0

    def _read_u8() -> int | None:
        nonlocal byte_pos
        if byte_pos >= len(raw):
            return None
        value = int(raw[byte_pos])
        byte_pos += 1
        return value

    dst_bag = _read_u8() if has_bag[0] else dst_bag_alt
    dst_slot = _read_u8() if has_slot[0] else dst_slot_alt
    src_bag = _read_u8() if has_bag[1] else src_bag_alt
    src_slot = _read_u8() if has_slot[1] else src_slot_alt

    if None in (src_bag, src_slot, dst_bag, dst_slot):
        return None
    return int(src_bag), int(src_slot), int(dst_bag), int(dst_slot)


def _inventory_error_code_for_message(message: str) -> int:
    text = str(message or "")
    mapping = {
        "cannot move non-empty equipped bag there yet": _EQUIP_ERR_DESTROY_NONEMPTY_BAG,
        "cannot place bag inside another bag": _EQUIP_ERR_BAG_IN_BAG,
        "destination bag full": _EQUIP_ERR_BAG_FULL,
        "destination slot does not fit item": _EQUIP_ERR_WRONG_SLOT,
        "swap target cannot move to source slot": _EQUIP_ERR_CANT_SWAP,
        "source item not found": _EQUIP_ERR_ITEM_NOT_FOUND,
        "source bag not found": _EQUIP_ERR_ITEM_NOT_FOUND,
        "destination bag not found": _EQUIP_ERR_ITEM_NOT_FOUND,
    }
    return int(mapping.get(text, _EQUIP_ERR_CANT_SWAP))


def _resolve_internal_bag(state, client_bag: int) -> int | None:
    client_bag = int(client_bag)
    if client_bag in (0, 255):
        return 0
    if 1 <= client_bag <= 4:
        client_bag = 18 + client_bag
    bag_item = state.get(0, client_bag) if state is not None else None
    if bag_item and bool(getattr(bag_item, "is_bag", False)):
        return int(getattr(bag_item, "item_guid", 0) or 0)
    return None


def _inventory_item_world_guid(state, client_bag: int, slot: int) -> int:
    if state is None:
        return 0
    internal_bag = _resolve_internal_bag(state, int(client_bag))
    if internal_bag is None:
        return 0
    item = state.get(int(internal_bag), int(slot))
    if item is None:
        return 0
    return _make_item_world_guid(int(getattr(item, "item_guid", 0) or 0))


def _result_to_response(
    session,
    prefix: str,
    result,
    *,
    failure_payload: bytes | None = None,
) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    level = "info" if result.ok else "warning"
    getattr(Logger, level)(f"[Inventory] {prefix} -> {result.message}")
    if result.ok:
        responses = build_inventory_delta_responses(session, result)
        return 0, responses or None
    responses: list[tuple[str, bytes]] = []

    if failure_payload:
        responses.append(("SMSG_INVENTORY_CHANGE_FAILURE", failure_payload))

    # Force full resync (already exists, keep it)
    responses.extend(build_login_inventory_sync_responses(session))
    responses.extend(trigger_inventory_activation(session))

    # IMPORTANT: force client UI reset (fixes grey/locked items)
    resync_player_appearance(session)

    return 0, responses


@register("CMSG_AUTOEQUIP_ITEM")
def handle_autoequip_item(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    log_cmsg(ctx)
    raw = bytes(ctx.payload or b"")
    if len(raw) < 2:
        return 0, _system_message("[Inventory] malformed autoequip packet")

    src_slot = int(raw[0])
    src_bag = int(raw[1])
    result = auto_equip_item(session, src_bag, src_slot)
    return _result_to_response(session, f"autoequip src=({src_bag},{src_slot})", result)


@register("CMSG_AUTOEQUIP_ITEM_SLOT")
def handle_autoequip_item_slot(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    log_cmsg(ctx)
    decoded = ctx.decoded or {}
    raw = bytes(ctx.payload or b"")

    slot = int(
        decoded.get("slot")
        or decoded.get("dst_slot")
        or decoded.get("equipment_slot")
        or (raw[0] if raw else 0)
        or 0
    )
    item_guid = _coerce_guid_int(
        decoded.get("guid")
        or decoded.get("item_guid")
        or decoded.get("item")
        or decoded.get("itemGuid")
    )

    if item_guid <= 0:
        return 0, _system_message("[Inventory] malformed autoequip-slot packet")

    result = move_item_to_root_slot_by_guid(session, int(item_guid) & 0xFFFFFFFF, slot)
    return _result_to_response(session, f"autoequip-slot guid={item_guid} dst={slot}", result)


@register("CMSG_AUTOSTORE_BAG_ITEM")
def handle_autostore_bag_item(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    log_cmsg(ctx)
    decoded = ctx.decoded or {}
    raw = bytes(ctx.payload or b"")
    src_slot = _decoded_first_int(decoded, "src_slot", "srcSlot", "source_slot", "slot")
    src_bag = _decoded_first_int(decoded, "src_bag", "srcBag", "source_bag", "bag")
    dst_bag = _decoded_first_int(decoded, "dst_bag", "dstBag", "dest_bag", "target_bag")

    if src_slot is None and len(raw) >= 1:
        src_slot = int(raw[0])
    if src_bag is None and len(raw) >= 2:
        src_bag = int(raw[1])
    if dst_bag is None and len(raw) >= 3:
        dst_bag = int(raw[2])

    if src_slot is None or src_bag is None or dst_bag is None:
        return 0, _system_message("[Inventory] malformed autostore packet")

    state = getattr(session, "inventory_state", None)
    source_guid = _inventory_item_world_guid(state, int(src_bag), int(src_slot))
    result = auto_store_item(session, int(src_bag), int(src_slot), int(dst_bag))
    failure_payload = None
    if not result.ok:
        failure_payload = build_inventory_change_failure_payload(
            error_code=_inventory_error_code_for_message(str(getattr(result, "message", ""))),
            item_guid=source_guid,
        )
    return _result_to_response(
        session,
        f"autostore src=({src_bag},{src_slot}) dstBag={dst_bag}",
        result,
        failure_payload=failure_payload,
    )


@register("CMSG_SWAP_INV_ITEM")
def handle_swap_inv_item(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    log_cmsg(ctx)
    decoded = ctx.decoded or {}
    raw = bytes(ctx.payload or b"")
    src_slot = _decoded_first_int(decoded, "src_slot", "srcSlot", "source_slot", "slot")
    dst_slot = _decoded_first_int(decoded, "dst_slot", "dstSlot", "dest_slot", "target_slot")

    if src_slot is None and len(raw) >= 1:
        src_slot = int(raw[0])
    if dst_slot is None and len(raw) >= 2:
        dst_slot = int(raw[1])

    if src_slot is None or dst_slot is None:
        return 0, _system_message("[Inventory] malformed swap-inv packet")

    state = getattr(session, "inventory_state", None)
    source_guid = _inventory_item_world_guid(state, 0, int(src_slot))
    target_guid = _inventory_item_world_guid(state, 0, int(dst_slot))
    result = swap_character_item(session, 0, int(src_slot), 0, int(dst_slot))
    failure_payload = None
    if not result.ok:
        failure_payload = build_inventory_change_failure_payload(
            error_code=_inventory_error_code_for_message(str(getattr(result, "message", ""))),
            item_guid=source_guid,
            item_guid2=target_guid,
        )
    return _result_to_response(
        session,
        f"swapinv src={src_slot} dst={dst_slot}",
        result,
        failure_payload=failure_payload,
    )


@register("CMSG_SWAP_ITEM")
def handle_swap_item(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    log_cmsg(ctx)
    decoded = ctx.decoded or {}
    raw = bytes(ctx.payload or b"")
    src_slot = _decoded_first_int(decoded, "src_slot", "srcSlot", "source_slot")
    src_bag = _decoded_first_int(decoded, "src_bag", "srcBag", "source_bag")
    dst_bag = _decoded_first_int(decoded, "dst_bag", "dstBag", "dest_bag", "target_bag")
    dst_slot = _decoded_first_int(decoded, "dst_slot", "dstSlot", "dest_slot", "target_slot")

    if None in (src_slot, src_bag, dst_bag, dst_slot):
        parsed = _decode_swap_item_payload(raw)
        if parsed is not None:
            parsed_src_bag, parsed_src_slot, parsed_dst_bag, parsed_dst_slot = parsed
            if src_bag is None:
                src_bag = parsed_src_bag
            if src_slot is None:
                src_slot = parsed_src_slot
            if dst_bag is None:
                dst_bag = parsed_dst_bag
            if dst_slot is None:
                dst_slot = parsed_dst_slot

    if src_slot is None and len(raw) >= 1:
        src_slot = int(raw[0])
    if src_bag is None and len(raw) >= 2:
        src_bag = int(raw[1])
    if dst_bag is None and len(raw) >= 3:
        dst_bag = int(raw[2])
    if dst_slot is None and len(raw) >= 4:
        dst_slot = int(raw[3])

    if src_slot is None or src_bag is None or dst_bag is None or dst_slot is None:
        return 0, _system_message("[Inventory] malformed swap packet")

    state = getattr(session, "inventory_state", None)
    source_guid = _inventory_item_world_guid(state, int(src_bag), int(src_slot))
    target_guid = _inventory_item_world_guid(state, int(dst_bag), int(dst_slot))
    result = swap_character_item(session, int(src_bag), int(src_slot), int(dst_bag), int(dst_slot))
    failure_payload = None
    if not result.ok:
        failure_payload = build_inventory_change_failure_payload(
            error_code=_inventory_error_code_for_message(str(getattr(result, "message", ""))),
            item_guid=source_guid,
            item_guid2=target_guid,
        )
    return _result_to_response(
        session,
        f"swap src=({src_bag},{src_slot}) dst=({dst_bag},{dst_slot})",
        result,
        failure_payload=failure_payload,
    )


@register("CMSG_DESTROY_ITEM")
def handle_destroy_item(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    log_cmsg(ctx)
    decoded = ctx.decoded or {}
    raw = bytes(ctx.payload or b"")
    slot = _decoded_first_int(decoded, "slot", "src_slot", "srcSlot")
    bag = _decoded_first_int(decoded, "bag", "bag_index", "bagIndex", "src_bag")
    count = _decoded_first_int(decoded, "count", "destroy_count", "stack_count")

    if slot is None and len(raw) >= 5:
        slot = int(raw[4])
    if bag is None and len(raw) >= 6:
        bag = int(raw[5])
    if count is None and len(raw) >= 4:
        count = int(struct.unpack_from("<I", raw, 0)[0])

    if slot is None or bag is None:
        return 0, _system_message("[Inventory] malformed destroy-item packet")
    if count is None:
        count = 0
    result = destroy_character_item(session, bag, slot, count)
    return _result_to_response(session, f"destroy bag={bag} slot={slot} count={count}", result)


@register("CMSG_OPEN_ITEM")
def handle_open_item(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    log_cmsg(ctx)
    decoded = ctx.decoded or {}
    raw = bytes(ctx.payload or b"")
    bag_index = _decoded_first_int(decoded, "bag", "bag_index", "bagIndex", "src_bag")
    slot = _decoded_first_int(decoded, "slot", "src_slot", "srcSlot")

    if bag_index is None and len(raw) >= 1:
        bag_index = int(raw[0])
    if slot is None and len(raw) >= 2:
        slot = int(raw[1])

    if bag_index is None or slot is None:
        return 0, _system_message("[Inventory] malformed open-item packet")

    state = getattr(session, "inventory_state", None)
    if state is None:
        return 0, _system_message("[Inventory] inventory not loaded")

    if bag_index not in (0, 255):
        return 0, None

    item = state.get(0, slot)
    if not item or not bool(getattr(item, "is_bag", False)):
        return 0, None

    responses = build_container_open_responses(session, item)
    Logger.info(f"[Inventory] open-item bagSlot={slot} item={int(item.item_guid)} responses={len(responses)}")
    return 0, responses or None
