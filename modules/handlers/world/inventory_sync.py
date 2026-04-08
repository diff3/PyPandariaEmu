from __future__ import annotations

import struct

from server.modules.game.guid import GuidHelper
from server.modules.handlers.world.bootstrap.replay import (
    build_multi_u32_update_object_payload,
    build_single_u32_update_object_payload,
)

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
    return _build_inventory_position_update_responses(session, int(item.bag), int(item.slot))


def _build_inventory_position_update_responses(session, bag: int, slot: int) -> list[tuple[str, bytes]]:
    field_index = _inventory_slot_field_index(int(bag), int(slot))
    if field_index is None:
        return []

    state = getattr(session, "inventory_state", None)
    if state is None:
        return []

    item = state.get(int(bag), int(slot))
    item_guid = _make_item_world_guid(int(item.item_guid)) if item else 0
    player_guid = int(getattr(session, "char_guid", 0) or 0)
    map_id = int(getattr(session, "map_id", 0) or 0)
    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_multi_u32_update_object_payload(
                map_id=map_id,
                guid=player_guid,
                field_updates=[
                    (field_index, int(item_guid & 0xFFFFFFFF)),
                    (field_index + 1, int((item_guid >> 32) & 0xFFFFFFFF)),
                ],
            ),
        ),
    ]


def _build_container_slot_update_responses(session, bag_guid: int, slot: int) -> list[tuple[str, bytes]]:
    state = getattr(session, "inventory_state", None)
    if state is None:
        return []

    bag_guid = int(bag_guid)
    slot = int(slot)
    contained = state.get(bag_guid, slot)
    contained_guid = _make_item_world_guid(int(contained.item_guid)) if contained else 0
    field_index = _CONTAINER_FIELD_SLOTS + (slot * 2)
    map_id = int(getattr(session, "map_id", 0) or 0)
    item_world_guid = _make_item_world_guid(bag_guid)
    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_multi_u32_update_object_payload(
                map_id=map_id,
                guid=item_world_guid,
                field_updates=[
                    (field_index, int(contained_guid & 0xFFFFFFFF)),
                    (field_index + 1, int((contained_guid >> 32) & 0xFFFFFFFF)),
                ],
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
    field_updates: list[tuple[int, int]] = [
        (_CONTAINER_FIELD_NUM_SLOTS, int(getattr(bag_item, "container_slots", 0) or 0)),
    ]

    for slot in range(int(getattr(bag_item, "container_slots", 0) or 0)):
        contained = state.get(int(bag_item.item_guid), slot)
        contained_guid = _make_item_world_guid(int(contained.item_guid)) if contained else 0
        field_index = _CONTAINER_FIELD_SLOTS + (slot * 2)
        field_updates.append((field_index, int(contained_guid & 0xFFFFFFFF)))
        field_updates.append((field_index + 1, int((contained_guid >> 32) & 0xFFFFFFFF)))
    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_multi_u32_update_object_payload(
                map_id=map_id,
                guid=bag_guid,
                field_updates=field_updates,
            ),
        )
    ]


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


def _build_root_slot_range_sync_responses(session, start_slot: int, end_slot: int) -> list[tuple[str, bytes]]:
    state = getattr(session, "inventory_state", None)
    if state is None:
        return []

    responses: list[tuple[str, bytes]] = []
    sent_item_guids: set[int] = set()
    field_updates: list[tuple[int, int]] = []
    for slot in range(int(start_slot), int(end_slot)):
        field_index = _inventory_slot_field_index(0, slot)
        if field_index is None:
            continue

        item = state.get(0, slot)
        item_guid = _make_item_world_guid(int(item.item_guid)) if item else 0
        player_guid = int(getattr(session, "char_guid", 0) or 0)
        map_id = int(getattr(session, "map_id", 0) or 0)

        field_updates.append((field_index, int(item_guid & 0xFFFFFFFF)))
        field_updates.append((field_index + 1, int((item_guid >> 32) & 0xFFFFFFFF)))

        if item is None:
            continue
        low_guid = int(item.item_guid)
        if low_guid in sent_item_guids:
            continue
        sent_item_guids.add(low_guid)
        responses.extend(build_item_snapshot_responses(session, item))
    if field_updates:
        responses.insert(
            0,
            (
                "SMSG_UPDATE_OBJECT",
                build_multi_u32_update_object_payload(
                    map_id=map_id,
                    guid=player_guid,
                    field_updates=field_updates,
                ),
            ),
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


def inventory_result_affects_equipment(result) -> bool:
    for bag, slot in getattr(result, "changed_positions", ()) or ():
        if int(bag) == 0 and 0 <= int(slot) < 19:
            return True
    return False


def inventory_result_equips_item(result) -> bool:
    return int(getattr(result, "equip_dst_slot", -1) or -1) >= 0


def _build_item_remove_responses(session, item_low_guids: list[int]) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.login.context import WorldLoginContext
    from server.modules.handlers.world.login.packets import build_login_packet

    world_guids = [_make_item_world_guid(int(item_guid)) for item_guid in item_low_guids if int(item_guid) > 0]
    if not world_guids:
        return []

    ctx = WorldLoginContext.from_session(session)
    ctx.exact_0007_map_id = int(getattr(session, "map_id", 0) or 0)
    ctx.exact_0007_out_of_range_guids = world_guids
    payload = build_login_packet("SMSG_UPDATE_OBJECT_1773613205_0007", ctx)
    if payload is None:
        return []
    return [("SMSG_UPDATE_OBJECT", payload)]


def build_inventory_delta_responses(session, result) -> list[tuple[str, bytes]]:
    state = getattr(session, "inventory_state", None)
    if state is None:
        return []

    responses: list[tuple[str, bytes]] = []
    changed_positions = list(
        dict.fromkeys((int(bag), int(slot)) for bag, slot in (getattr(result, "changed_positions", ()) or ()))
    )
    removed_item_guids = [
        int(item_guid) for item_guid in (getattr(result, "removed_item_guids", ()) or ()) if int(item_guid) > 0
    ]

    root_equipment_changed = any(int(bag) == 0 and 0 <= int(slot) < 23 for bag, slot in changed_positions)
    root_backpack_changed = any(int(bag) == 0 and 23 <= int(slot) < 39 for bag, slot in changed_positions)
    affected_bag_guids: set[int] = {int(bag) for bag, _slot in changed_positions if int(bag) != 0}

    for _bag, slot in changed_positions:
        if not (int(_bag) == 0 and 19 <= int(slot) < 23):
            continue
        bag_item = state.get(0, int(slot))
        if bag_item is not None and bool(getattr(bag_item, "is_bag", False)):
            affected_bag_guids.add(int(bag_item.item_guid))

    if root_equipment_changed:
        responses.extend(_build_root_slot_range_sync_responses(session, 0, 23))
    if root_backpack_changed:
        responses.extend(_build_root_slot_range_sync_responses(session, 23, 39))

    synced_bag_guids: set[int] = set()
    for bag_guid in sorted(affected_bag_guids):
        if int(bag_guid) <= 0 or int(bag_guid) in synced_bag_guids:
            continue
        bag_item = state.items_by_guid.get(int(bag_guid))
        if bag_item is None or not bool(getattr(bag_item, "is_bag", False)):
            continue
        responses.extend(build_container_open_responses(session, bag_item))
        synced_bag_guids.add(int(bag_guid))

    if inventory_result_affects_equipment(result):
        from server.modules.handlers.world.state.runtime import build_self_player_appearance_responses

        responses.extend(build_self_player_appearance_responses(session))

    responses.extend(_build_item_remove_responses(session, removed_item_guids))
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
