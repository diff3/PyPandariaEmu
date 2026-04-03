from __future__ import annotations

from typing import Optional, Tuple

from shared.Logger import Logger
from server.modules.game.inventory import (
    auto_equip_item,
    auto_store_item,
    move_item_to_root_slot_by_guid,
    swap_character_item,
)
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from server.modules.handlers.world.dispatcher import register
from server.modules.handlers.world.inventory_sync import (
    build_container_open_responses,
    build_login_inventory_sync_responses,
)
from server.modules.handlers.world.packet_logging import log_cmsg
from server.modules.protocol.PacketContext import PacketContext
from server.modules.handlers.world.state.runtime import (
    build_self_player_appearance_responses,
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


def _result_to_response(session, prefix: str, result) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    level = "info" if result.ok else "warning"
    getattr(Logger, level)(f"[Inventory] {prefix} -> {result.message}")
    if result.ok:
        resync_player_appearance(session)
        responses = build_self_player_appearance_responses(session)
        responses.extend(build_login_inventory_sync_responses(session))
        return 0, responses or None
    return 0, _system_message(f"[Inventory] {result.message}")


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
    raw = bytes(ctx.payload or b"")
    if len(raw) < 3:
        return 0, _system_message("[Inventory] malformed autostore packet")

    src_slot = int(raw[0])
    src_bag = int(raw[1])
    dst_bag = int(raw[2])
    result = auto_store_item(session, src_bag, src_slot, dst_bag)
    return _result_to_response(
        session,
        f"autostore src=({src_bag},{src_slot}) dstBag={dst_bag}",
        result,
    )


@register("CMSG_SWAP_INV_ITEM")
def handle_swap_inv_item(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    log_cmsg(ctx)
    raw = bytes(ctx.payload or b"")
    if len(raw) < 2:
        return 0, _system_message("[Inventory] malformed swap-inv packet")

    src_slot = int(raw[0])
    dst_slot = int(raw[1])
    result = swap_character_item(session, 0, src_slot, 0, dst_slot)
    return _result_to_response(session, f"swapinv src={src_slot} dst={dst_slot}", result)


@register("CMSG_SWAP_ITEM")
def handle_swap_item(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    log_cmsg(ctx)
    raw = bytes(ctx.payload or b"")
    if len(raw) < 4:
        return 0, _system_message("[Inventory] malformed swap packet")

    src_slot = int(raw[0])
    src_bag = int(raw[1])
    dst_bag = int(raw[2])
    dst_slot = int(raw[3])
    result = swap_character_item(session, src_bag, src_slot, dst_bag, dst_slot)
    return _result_to_response(
        session,
        f"swap src=({src_bag},{src_slot}) dst=({dst_bag},{dst_slot})",
        result,
    )


@register("CMSG_OPEN_ITEM")
def handle_open_item(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    log_cmsg(ctx)
    raw = bytes(ctx.payload or b"")
    if len(raw) < 2:
        return 0, _system_message("[Inventory] malformed open-item packet")

    bag_index = int(raw[0])
    slot = int(raw[1])

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
