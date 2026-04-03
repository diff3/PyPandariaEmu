from __future__ import annotations

import struct

from server.modules.game.guid import GuidHelper
from server.modules.handlers.world.bootstrap.replay import build_single_u32_update_object_payload

_ITEM_HIGHGUID = 0x400
_ITEM_FIELD_STACK_COUNT = 0x10
_CONTAINER_FIELD_SLOTS = 0x45
_CONTAINER_FIELD_NUM_SLOTS = 0x8D
_PLAYER_FIELD_INV_SLOTS = (0x8 + 0x98) + 0x325
_PLAYER_FIELD_PACK_SLOTS = (0x8 + 0x98) + 0x353
_ITEM_CREATE_FLAGS = b"\x00\x00\x00\x00\x00\x00"
_ITEM_CREATE_MASK = bytes.fromhex("f30581000000000000000000")


def _make_skyfire_guid(low: int, entry: int, high: int) -> int:
    shift = 48 if int(high) in {0xF101, 0xF102} else 52
    return (
        (int(low) & 0xFFFFFFFF)
        | ((int(entry) & 0xFFFFF) << 32)
        | ((int(high) & 0xFFFFF) << shift)
    )


def _make_item_world_guid(item_low_guid: int) -> int:
    return _make_skyfire_guid(int(item_low_guid), 0, _ITEM_HIGHGUID)


def _build_item_create_update_payload(session, item) -> bytes:
    item_guid = _make_item_world_guid(int(item.item_guid))
    object_type_mask = 7 if bool(getattr(item, "is_bag", False)) else 3
    object_type_id = 2 if bool(getattr(item, "is_bag", False)) else 1
    field_values = (
        int(item_guid & 0xFFFFFFFF),
        int((item_guid >> 32) & 0xFFFFFFFF),
        object_type_mask,
        int(item.entry),
        0,
        0x3F800000,
        int(getattr(session, "char_guid", 0) or 0),
        int(getattr(session, "char_guid", 0) or 0),
        int(item.count),
        1,
    )

    entry = bytearray()
    entry += struct.pack("<B", 1)
    entry += GuidHelper.pack(int(item_guid))
    entry += struct.pack("<B", object_type_id)
    entry += _ITEM_CREATE_FLAGS
    entry += struct.pack("<B", len(_ITEM_CREATE_MASK) // 4)
    entry += _ITEM_CREATE_MASK
    for value in field_values:
        entry += struct.pack("<I", int(value) & 0xFFFFFFFF)
    entry += struct.pack("<B", 0)

    payload = bytearray()
    payload += struct.pack("<HI", int(getattr(session, "map_id", 0) or 0) & 0xFFFF, 1)
    payload += entry
    return bytes(payload)


def _inventory_slot_field_index(bag: int, slot: int) -> int | None:
    bag = int(bag)
    slot = int(slot)
    if bag != 0:
        return None
    if 0 <= slot < 23:
        return _PLAYER_FIELD_INV_SLOTS + (slot * 2)
    if 23 <= slot < 39:
        return _PLAYER_FIELD_PACK_SLOTS + ((slot - 23) * 2)
    return None


def _build_inventory_slot_update_responses(session, item) -> list[tuple[str, bytes]]:
    field_index = _inventory_slot_field_index(int(item.bag), int(item.slot))
    if field_index is None:
        return []

    item_guid = _make_item_world_guid(int(item.item_guid))
    player_guid = int(getattr(session, "char_guid", 0) or 0)
    map_id = int(getattr(session, "map_id", 0) or 0)
    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_single_u32_update_object_payload(
                map_id=map_id,
                guid=player_guid,
                field_index=field_index,
                value=int(item_guid & 0xFFFFFFFF),
            ),
        ),
        (
            "SMSG_UPDATE_OBJECT",
            build_single_u32_update_object_payload(
                map_id=map_id,
                guid=player_guid,
                field_index=field_index + 1,
                value=int((item_guid >> 32) & 0xFFFFFFFF),
            ),
        ),
    ]


def _build_inventory_count_update_response(session, item) -> tuple[str, bytes]:
    return (
        "SMSG_UPDATE_OBJECT",
        build_single_u32_update_object_payload(
            map_id=int(getattr(session, "map_id", 0) or 0),
            guid=_make_item_world_guid(int(item.item_guid)),
            field_index=_ITEM_FIELD_STACK_COUNT,
            value=int(item.count),
        ),
    )


def build_item_snapshot_responses(session, item) -> list[tuple[str, bytes]]:
    responses = [("SMSG_UPDATE_OBJECT", _build_item_create_update_payload(session, item))]
    responses.append(_build_inventory_count_update_response(session, item))
    responses.extend(_build_container_field_update_responses(session, item))
    return responses


def _build_container_field_update_responses(session, bag_item) -> list[tuple[str, bytes]]:
    if not bool(getattr(bag_item, "is_bag", False)):
        return []

    state = getattr(session, "inventory_state", None)
    if state is None:
        return []

    bag_guid = _make_item_world_guid(int(bag_item.item_guid))
    map_id = int(getattr(session, "map_id", 0) or 0)
    responses: list[tuple[str, bytes]] = [
        (
            "SMSG_UPDATE_OBJECT",
            build_single_u32_update_object_payload(
                map_id=map_id,
                guid=bag_guid,
                field_index=_CONTAINER_FIELD_NUM_SLOTS,
                value=int(getattr(bag_item, "container_slots", 0) or 0),
            ),
        )
    ]

    for slot in range(int(getattr(bag_item, "container_slots", 0) or 0)):
        contained = state.get(int(bag_item.item_guid), slot)
        contained_guid = _make_item_world_guid(int(contained.item_guid)) if contained else 0
        field_index = _CONTAINER_FIELD_SLOTS + (slot * 2)
        responses.append(
            (
                "SMSG_UPDATE_OBJECT",
                build_single_u32_update_object_payload(
                    map_id=map_id,
                    guid=bag_guid,
                    field_index=field_index,
                    value=int(contained_guid & 0xFFFFFFFF),
                ),
            )
        )
        responses.append(
            (
                "SMSG_UPDATE_OBJECT",
                build_single_u32_update_object_payload(
                    map_id=map_id,
                    guid=bag_guid,
                    field_index=field_index + 1,
                    value=int((contained_guid >> 32) & 0xFFFFFFFF),
                ),
            )
        )
    return responses


def build_login_inventory_sync_responses(session) -> list[tuple[str, bytes]]:
    state = getattr(session, "inventory_state", None)
    if state is None:
        return []

    root_items = sorted(
        (
            item
            for item in getattr(state, "items_by_pos", {}).values()
            if int(getattr(item, "bag", -1)) == 0
        ),
        key=lambda item: (int(getattr(item, "slot", 0) or 0), int(getattr(item, "item_guid", 0) or 0)),
    )

    responses: list[tuple[str, bytes]] = []
    responses.extend(build_root_inventory_slot_sync_responses(session))
    responses.extend(build_equipped_bag_sync_responses(session))
    for item in root_items:
        responses.extend(build_item_snapshot_responses(session, item))
    return responses


def build_root_inventory_slot_sync_responses(session) -> list[tuple[str, bytes]]:
    state = getattr(session, "inventory_state", None)
    if state is None:
        return []

    responses: list[tuple[str, bytes]] = []
    for slot in range(39):
        field_index = _inventory_slot_field_index(0, slot)
        if field_index is None:
            continue

        item = state.get(0, slot)
        item_guid = _make_item_world_guid(int(item.item_guid)) if item else 0
        player_guid = int(getattr(session, "char_guid", 0) or 0)
        map_id = int(getattr(session, "map_id", 0) or 0)

        responses.append(
            (
                "SMSG_UPDATE_OBJECT",
                build_single_u32_update_object_payload(
                    map_id=map_id,
                    guid=player_guid,
                    field_index=field_index,
                    value=int(item_guid & 0xFFFFFFFF),
                ),
            )
        )
        responses.append(
            (
                "SMSG_UPDATE_OBJECT",
                build_single_u32_update_object_payload(
                    map_id=map_id,
                    guid=player_guid,
                    field_index=field_index + 1,
                    value=int((item_guid >> 32) & 0xFFFFFFFF),
                ),
            )
        )
    return responses


def build_container_open_responses(session, bag_item) -> list[tuple[str, bytes]]:
    if not bool(getattr(bag_item, "is_bag", False)):
        return []

    state = getattr(session, "inventory_state", None)
    if state is None:
        return []

    responses: list[tuple[str, bytes]] = []
    responses.extend(build_item_snapshot_responses(session, bag_item))

    for slot in range(int(getattr(bag_item, "container_slots", 0) or 0)):
        item = state.get(int(bag_item.item_guid), slot)
        if item is None:
            continue
        responses.extend(build_item_snapshot_responses(session, item))

    return responses


def build_equipped_bag_sync_responses(session) -> list[tuple[str, bytes]]:
    state = getattr(session, "inventory_state", None)
    if state is None:
        return []

    responses: list[tuple[str, bytes]] = []
    for slot in range(19, 23):
        bag_item = state.get(0, slot)
        if bag_item is None or not bool(getattr(bag_item, "is_bag", False)):
            continue
        responses.extend(build_item_snapshot_responses(session, bag_item))
        for bag_slot in range(int(getattr(bag_item, "container_slots", 0) or 0)):
            item = state.get(int(bag_item.item_guid), bag_slot)
            if item is None:
                continue
            responses.extend(build_item_snapshot_responses(session, item))
    return responses
