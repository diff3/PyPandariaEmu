from __future__ import annotations

import struct

from shared.Logger import Logger
from server.modules.game.guid import GuidHelper
from server.modules.handlers.world.bootstrap.replay import (
    build_multi_u32_update_object_payload,
    build_single_u32_update_object_payload,
)

_ITEM_HIGHGUID = 0x400
_ITEM_FIELD_OWNER = 0x8
_ITEM_FIELD_CONTAINED = 0xA
_ITEM_FIELD_STACK_COUNT = 0x10
_CONTAINER_FIELD_SLOTS = 0x45
_CONTAINER_FIELD_NUM_SLOTS = 0x8D
_PLAYER_FIELD_VISIBLE_ITEMS = (0x8 + 0x98) + 0x2F9
_PLAYER_FIELD_INV_SLOTS = (0x8 + 0x98) + 0x325
_PLAYER_FIELD_PACK_SLOTS = (0x8 + 0x98) + 0x353
_PLAYER_VISIBLE_ITEM_SLOT_COUNT = 19
_ITEM_CREATE_FLAGS = b"\x00\x00\x00\x00\x00\x00"


def _make_skyfire_guid(low: int, entry: int, high: int) -> int:
    shift = 48 if int(high) in {0xF101, 0xF102} else 52
    return (
        (int(low) & 0xFFFFFFFF)
        | ((int(entry) & 0xFFFFF) << 32)
        | ((int(high) & 0xFFFFF) << shift)
    )


def _make_item_world_guid(item_low_guid: int) -> int:
    return _make_skyfire_guid(int(item_low_guid), 0, _ITEM_HIGHGUID)


def _pack_update_mask(field_indices: list[int], *, min_blocks: int = 3) -> bytes:
    block_count = max(int(min_blocks), ((max(field_indices, default=-1) // 32) + 1))
    mask = bytearray(block_count * 4)
    for field_index in sorted({int(index) for index in field_indices if int(index) >= 0}):
        mask[field_index // 8] |= 1 << (field_index % 8)
    return bytes(mask)


def _known_inventory_guids(session) -> set[int]:
    known = getattr(session, "known_inventory_guids", None)
    if isinstance(known, set):
        return known
    known = set()
    session.known_inventory_guids = known
    return known


def _clear_known_inventory_guids(session) -> None:
    _known_inventory_guids(session).clear()


def _mark_known_inventory_guid(session, guid: int) -> None:
    _known_inventory_guids(session).add(int(guid))


def _equipped_bag_items(state) -> list:
    bags = []
    for item in getattr(state, "items_by_pos", {}).values():
        if int(getattr(item, "bag", -1)) != 0:
            continue
        if not bool(getattr(item, "is_bag", False)):
            continue
        slot = int(getattr(item, "slot", -1))
        if not (19 <= slot < 23):
            continue
        bags.append(item)
    bags.sort(key=lambda item: (int(getattr(item, "slot", 0) or 0), int(getattr(item, "item_guid", 0) or 0)))
    return bags


def _find_inventory_activation_bag(session) -> tuple[int, int] | None:
    state = getattr(session, "inventory_state", None)
    if state is None or not hasattr(state, "get"):
        return None

    for item in _equipped_bag_items(state):
        return int(getattr(item, "slot", 0) or 0), int(getattr(item, "item_guid", 0) or 0)

    for slot in range(39):
        item = state.get(0, slot)
        if item is not None and bool(getattr(item, "is_bag", False)):
            return int(slot), int(getattr(item, "item_guid", 0) or 0)

    return None


def trigger_inventory_activation(session) -> list[tuple[str, bytes]]:
    if bool(getattr(session, "inventory_activated", False)):
        Logger.debug("[INV_ACTIVATE] skipped (already active)")
        return []

    player_guid = int(getattr(session, "char_guid", 0) or 0)
    map_id = int(getattr(session, "map_id", 0) or 0)
    if player_guid <= 0:
        Logger.debug("[INV_ACTIVATE] no valid bag found")
        return []

    selected = _find_inventory_activation_bag(session)
    if selected is None:
        Logger.debug("[INV_ACTIVATE] no valid bag found")
        return []

    slot, item_low_guid = selected
    field_index = _inventory_slot_field_index(0, slot)
    if field_index is None or item_low_guid <= 0:
        Logger.debug("[INV_ACTIVATE] no valid bag found")
        return []

    item_guid = _make_item_world_guid(int(item_low_guid))
    responses = [
        (
            "SMSG_UPDATE_OBJECT",
            build_multi_u32_update_object_payload(
                map_id=map_id,
                guid=player_guid,
                field_updates=[
                    (field_index, 0),
                    (field_index + 1, 0),
                ],
            ),
        ),
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
    session.inventory_activated = True
    Logger.debug("[INV_ACTIVATE] triggered slot=%s guid=%s", int(slot), int(item_guid))
    return responses


def maybe_trigger_inventory_activation(session, src_container: int, dst_container: int) -> list[tuple[str, bytes]]:
    if int(src_container) == int(dst_container):
        return []
    Logger.debug(
        "[INV_ACTIVATE] triggered after move src=%s dst=%s",
        int(src_container),
        int(dst_container),
    )
    return trigger_inventory_activation(session)


def _append_bag_container_field_values(field_values: dict[int, int], session, bag_item) -> None:
    field_values[_CONTAINER_FIELD_NUM_SLOTS] = int(getattr(bag_item, "container_slots", 0) or 0)
    state = getattr(session, "inventory_state", None)
    if state is None:
        return

    for slot in range(int(getattr(bag_item, "container_slots", 0) or 0)):
        contained = state.get(int(bag_item.item_guid), slot)
        if contained is None:
            continue
        contained_item_guid = _make_item_world_guid(int(contained.item_guid))
        field_index = _CONTAINER_FIELD_SLOTS + (slot * 2)
        field_values[field_index] = int(contained_item_guid & 0xFFFFFFFF)
        field_values[field_index + 1] = int((contained_item_guid >> 32) & 0xFFFFFFFF)


def _build_item_create_update_payload_old(session, item) -> bytes:
    item_guid = _make_item_world_guid(int(item.item_guid))
    object_type_mask = 7 if bool(getattr(item, "is_bag", False)) else 3
    object_type_id = 2 if bool(getattr(item, "is_bag", False)) else 1
    owner_guid = int(getattr(session, "char_guid", 0) or 0)
    contained_guid = owner_guid if int(getattr(item, "bag", 0) or 0) == 0 else _make_item_world_guid(int(item.bag))

    field_values: dict[int, int] = {
        0: int(item_guid & 0xFFFFFFFF),
        1: int((item_guid >> 32) & 0xFFFFFFFF),
        4: int(object_type_mask),
        5: int(item.entry),
        6: 0,
        7: 0x3F800000,
        8: int(owner_guid & 0xFFFFFFFF),
        16: int(item.count),
        23: 1,
    }

    owner_high = int((owner_guid >> 32) & 0xFFFFFFFF)
    if owner_high:
        field_values[9] = owner_high

    contained_low = int(contained_guid & 0xFFFFFFFF)
    contained_high = int((contained_guid >> 32) & 0xFFFFFFFF)
    field_values[10] = contained_low
    if contained_high:
        field_values[11] = contained_high

    if bool(getattr(item, "is_bag", False)):
        _append_bag_container_field_values(field_values, session, item)

    item_create_mask = _pack_update_mask(list(field_values.keys()))

    entry = bytearray()
    entry += struct.pack("<B", 1)
    entry += GuidHelper.pack(int(item_guid))
    entry += struct.pack("<B", object_type_id)
    entry += _ITEM_CREATE_FLAGS
    entry += struct.pack("<B", len(item_create_mask) // 4)
    entry += item_create_mask
    for field_index in sorted(field_values):
        value = field_values[field_index]
        entry += struct.pack("<I", int(value) & 0xFFFFFFFF)
    entry += struct.pack("<B", 0)

    payload = bytearray()
    payload += struct.pack("<HI", int(getattr(session, "map_id", 0) or 0) & 0xFFFF, 1)
    payload += entry
    return bytes(payload)


def _build_item_release_update_payload_old(session, item) -> bytes:
    item_guid = _make_item_world_guid(int(item.item_guid))
    object_type_mask = 7 if bool(getattr(item, "is_bag", False)) else 3
    object_type_id = 2 if bool(getattr(item, "is_bag", False)) else 1
    owner_guid = int(getattr(session, "char_guid", 0) or 0)

    field_values: dict[int, int] = {
        0: int(item_guid & 0xFFFFFFFF),
        1: int((item_guid >> 32) & 0xFFFFFFFF),
        4: int(object_type_mask),
        5: int(item.entry),
        6: 0,
        7: 0x3F800000,
        8: int(owner_guid & 0xFFFFFFFF),
        16: int(item.count),
        23: 1,
    }

    owner_high = int((owner_guid >> 32) & 0xFFFFFFFF)
    if owner_high:
        field_values[9] = owner_high

    if bool(getattr(item, "is_bag", False)):
        _append_bag_container_field_values(field_values, session, item)

    item_create_mask = _pack_update_mask(list(field_values.keys()))

    entry = bytearray()
    entry += struct.pack("<B", 1)
    entry += GuidHelper.pack(int(item_guid))
    entry += struct.pack("<B", object_type_id)
    entry += _ITEM_CREATE_FLAGS
    entry += struct.pack("<B", len(item_create_mask) // 4)
    entry += item_create_mask
    for field_index in sorted(field_values):
        entry += struct.pack("<I", int(field_values[field_index]) & 0xFFFFFFFF)
    entry += struct.pack("<B", 0)

    payload = bytearray()
    payload += struct.pack("<HI", int(getattr(session, "map_id", 0) or 0) & 0xFFFF, 1)
    payload += entry
    return bytes(payload)


def build_create_object(session, obj) -> bytes:
    return _build_item_create_update_payload_old(session, obj)


def build_values_update(session, guid: int, changed_fields: list[tuple[int, int]]) -> bytes:
    return build_multi_u32_update_object_payload(
        map_id=int(getattr(session, "map_id", 0) or 0),
        guid=int(guid),
        field_updates=[(int(field_index), int(value)) for field_index, value in (changed_fields or [])],
    )


def build_update_batch() -> list[tuple[str, bytes]]:
    return []


def add_update(batch: list[tuple[str, bytes]], update_kind: str, responses: list[tuple[str, bytes]] | tuple[str, bytes] | None) -> None:
    if not responses:
        return
    normalized = [responses] if isinstance(responses, tuple) else list(responses)
    for opcode, payload in normalized:
        if opcode != "SMSG_UPDATE_OBJECT" or not payload:
            continue
        batch.append((str(update_kind), bytes(payload)))


def add_out_of_range(batch: list[tuple[str, bytes]], session, item_low_guid: int) -> None:
    add_update(batch, "OUT_OF_RANGE", _build_item_remove_responses(session, [int(item_low_guid)]))


def send_update_batch(_session, batch: list[tuple[str, bytes]]) -> list[tuple[str, bytes]]:
    if not batch:
        return []

    map_id: int | None = None
    update_count = 0
    payload_entries = bytearray()
    update_types: list[str] = []
    for update_type, payload in batch:
        if len(payload) < 6:
            continue
        current_map_id = int(struct.unpack_from("<H", payload, 0)[0])
        current_count = int(struct.unpack_from("<I", payload, 2)[0])
        if current_count <= 0:
            continue
        if map_id is None:
            map_id = current_map_id
        elif map_id != current_map_id:
            raise ValueError("cannot batch SMSG_UPDATE_OBJECT payloads from different maps")
        update_count += current_count
        payload_entries.extend(payload[6:])
        update_types.append(str(update_type))

    if update_count <= 0 or map_id is None:
        return []

    Logger.debug("[BATCH] updates=%s includes=%s", int(update_count), update_types)
    return [("SMSG_UPDATE_OBJECT", struct.pack("<HI", int(map_id) & 0xFFFF, int(update_count)) + bytes(payload_entries))]


def _contained_guid_for_item(session, item) -> int:
    owner_guid = int(getattr(session, "char_guid", 0) or 0)
    return owner_guid if int(getattr(item, "bag", 0) or 0) == 0 else _make_item_world_guid(int(item.bag))


def _build_item_values_field_updates(session, item, changed_fields: list[int] | tuple[int, ...] | None = None) -> list[tuple[int, int]]:
    contained_guid = _contained_guid_for_item(session, item)
    owner_guid = int(getattr(session, "char_guid", 0) or 0)
    updates_by_field: dict[int, int] = {}
    for field_index in sorted({int(field) for field in (changed_fields or [])}):
        if field_index == _ITEM_FIELD_OWNER:
            updates_by_field[field_index] = int(owner_guid & 0xFFFFFFFF)
        elif field_index == (_ITEM_FIELD_OWNER + 1):
            updates_by_field[field_index] = int((owner_guid >> 32) & 0xFFFFFFFF)
        elif field_index == _ITEM_FIELD_CONTAINED:
            updates_by_field[field_index] = int(contained_guid & 0xFFFFFFFF)
        elif field_index == (_ITEM_FIELD_CONTAINED + 1):
            updates_by_field[field_index] = int((contained_guid >> 32) & 0xFFFFFFFF)
        elif field_index == _ITEM_FIELD_STACK_COUNT:
            updates_by_field[field_index] = int(getattr(item, "count", 0) or 0)
    return [(field_index, updates_by_field[field_index]) for field_index in sorted(updates_by_field)]


def _determine_item_changed_fields(session, item, previous_item=None, *, default_to_stack: bool = False) -> list[int]:
    changed_fields: list[int] = []
    if previous_item is not None:
        if _contained_guid_for_item(session, previous_item) != _contained_guid_for_item(session, item):
            changed_fields.extend([_ITEM_FIELD_CONTAINED, _ITEM_FIELD_CONTAINED + 1])
        if int(getattr(previous_item, "count", 0) or 0) != int(getattr(item, "count", 0) or 0):
            changed_fields.append(_ITEM_FIELD_STACK_COUNT)
        return changed_fields
    if default_to_stack:
        changed_fields.append(_ITEM_FIELD_STACK_COUNT)
    return changed_fields


def _forced_equipment_item_fields() -> list[int]:
    return [
        _ITEM_FIELD_OWNER,
        _ITEM_FIELD_OWNER + 1,
        _ITEM_FIELD_CONTAINED,
        _ITEM_FIELD_CONTAINED + 1,
    ]


def _merge_item_fields(*field_groups: list[int] | tuple[int, ...] | None) -> list[int]:
    merged: set[int] = set()
    for group in field_groups:
        for field in group or ():
            merged.add(int(field))
    return sorted(merged)


def validate_item_links(item, player, container=None) -> bool:
    owner_guid = int(getattr(player, "char_guid", 0) or 0)
    contained_guid = owner_guid if int(getattr(item, "bag", 0) or 0) == 0 else _make_item_world_guid(int(item.bag))
    valid = True
    if int(getattr(item, "bag", 0) or 0) == 0 and contained_guid != owner_guid:
        valid = False
    if owner_guid <= 0:
        valid = False
    if container is not None and contained_guid != _make_item_world_guid(int(getattr(container, "item_guid", 0) or 0)):
        valid = False
    if not valid:
        Logger.debug(
            "[INV_VALIDATE_FAIL] item=%s owner=%s contained_in=%s",
            int(getattr(item, "item_guid", 0) or 0),
            int(owner_guid),
            int(contained_guid),
        )
    return valid


def validate_inventory(session) -> bool:
    state = getattr(session, "inventory_state", None)
    owner_guid = int(getattr(session, "char_guid", 0) or 0)
    if state is None or not hasattr(state, "items_by_guid"):
        return True

    valid = True
    for item in getattr(state, "items_by_guid", {}).values():
        item_guid = int(getattr(item, "item_guid", 0) or 0)
        item_bag = int(getattr(item, "bag", 0) or 0)
        item_slot = int(getattr(item, "slot", 0) or 0)

        if owner_guid <= 0:
            Logger.warning("[INV ERROR] owner mismatch item=%s owner=%s", item_guid, owner_guid)
            valid = False

        if item_bag != 0:
            container = state.items_by_guid.get(int(item_bag))
            if container is None or not bool(getattr(container, "is_bag", False)):
                Logger.warning("[INV ERROR] invalid container item=%s container=%s", item_guid, item_bag)
                valid = False
                continue
            contained = state.get(int(item_bag), int(item_slot))
            if contained is None or int(getattr(contained, "item_guid", 0) or 0) != item_guid:
                Logger.warning("[INV ERROR] slot mismatch item=%s container=%s slot=%s", item_guid, item_bag, item_slot)
                valid = False
            continue

        if state.get(0, int(item_slot)) is not item:
            Logger.warning("[INV ERROR] invalid contained_in item=%s slot=%s", item_guid, item_slot)
            valid = False

    return valid


def build_item_values_update(session, item, changed_fields: list[int] | tuple[int, ...] | None = None) -> bytes | None:
    field_updates = _build_item_values_field_updates(session, item, changed_fields)
    if not field_updates:
        return None
    return build_values_update(session, _make_item_world_guid(int(item.item_guid)), field_updates)


def _build_container_values_field_updates(session, bag_item, changed_slots: list[int] | tuple[int, ...] | None = None) -> list[tuple[int, int]]:
    state = getattr(session, "inventory_state", None)
    if state is None:
        return []

    field_updates: list[tuple[int, int]] = []
    for slot in sorted({int(slot) for slot in (changed_slots or [])}):
        contained = state.get(int(bag_item.item_guid), slot)
        contained_guid = _make_item_world_guid(int(contained.item_guid)) if contained else 0
        field_index = _CONTAINER_FIELD_SLOTS + (slot * 2)
        field_updates.append((field_index, int(contained_guid & 0xFFFFFFFF)))
        field_updates.append((field_index + 1, int((contained_guid >> 32) & 0xFFFFFFFF)))
    return field_updates


def build_container_values_update(session, bag_item, changed_slots: list[int] | tuple[int, ...] | None = None) -> bytes | None:
    changed_fields = _build_container_values_field_updates(session, bag_item, changed_slots)
    if not changed_fields:
        return None
    return build_values_update(session, _make_item_world_guid(int(bag_item.item_guid)), changed_fields)


def sync_known_item(session, item, changed_fields: list[int] | tuple[int, ...] | None = None) -> list[tuple[str, bytes]]:
    item_guid = _make_item_world_guid(int(item.item_guid))
    payload = build_item_values_update(session, item, changed_fields)
    if payload is None:
        return []
    Logger.debug(f"[INV] VALUES item guid={item_guid} fields={sorted({int(field) for field in (changed_fields or [])})}")
    return [("SMSG_UPDATE_OBJECT", payload)]


def sync_item(session, item, changed_fields: list[int] | tuple[int, ...] | None = None) -> list[tuple[str, bytes]]:
    item_guid = _make_item_world_guid(int(item.item_guid))
    known_guids = _known_inventory_guids(session)
    if item_guid not in known_guids:
        _mark_known_inventory_guid(session, item_guid)
        Logger.debug(f"[INV] CREATE guid={item_guid} type=item")
        return [("SMSG_UPDATE_OBJECT", build_create_object(session, item))]
    return sync_known_item(session, item, changed_fields)


def sync_known_container(session, bag_item, changed_slots: list[int] | tuple[int, ...] | None = None) -> list[tuple[str, bytes]]:
    bag_guid = _make_item_world_guid(int(bag_item.item_guid))
    payload = build_container_values_update(session, bag_item, changed_slots)
    if payload is None:
        return []
    Logger.debug(f"[INV] VALUES container guid={bag_guid} slots={sorted({int(slot) for slot in (changed_slots or [])})}")
    return [("SMSG_UPDATE_OBJECT", payload)]


def sync_container(session, bag_item, changed_slots: list[int] | tuple[int, ...] | None = None) -> list[tuple[str, bytes]]:
    bag_guid = _make_item_world_guid(int(bag_item.item_guid))
    known_guids = _known_inventory_guids(session)
    if bag_guid not in known_guids:
        _mark_known_inventory_guid(session, bag_guid)
        Logger.debug(f"[INV] CREATE guid={bag_guid} type=container")
        return [("SMSG_UPDATE_OBJECT", build_create_object(session, bag_item))]
    return sync_known_container(session, bag_item, changed_slots)


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


def _is_equipment_position(bag: int, slot: int) -> bool:
    return int(bag) == 0 and 0 <= int(slot) < 19


def _visible_item_cache_raw(session) -> list[int]:
    required = _PLAYER_VISIBLE_ITEM_SLOT_COUNT * 2
    if bool(getattr(session, "is_morphed", False)):
        return [0] * required

    cached = [int(value) for value in (getattr(session, "equipment_cache_raw", []) or [])]
    if len(cached) >= required:
        return cached[:required]

    values = [0] * required
    state = getattr(session, "inventory_state", None)
    if state is None:
        return values

    for slot in range(_PLAYER_VISIBLE_ITEM_SLOT_COUNT):
        item = state.get(0, slot)
        if item is None:
            continue
        values[slot * 2] = int(getattr(item, "display_id", 0) or 0)
    return values


def build_self_visible_item_update_responses(session) -> list[tuple[str, bytes]]:
    player_guid = int(getattr(session, "char_guid", 0) or 0)
    map_id = int(getattr(session, "map_id", 0) or 0)
    if player_guid <= 0:
        return []

    equipment_cache_raw = _visible_item_cache_raw(session)
    field_updates: list[tuple[int, int]] = []
    for slot in range(_PLAYER_VISIBLE_ITEM_SLOT_COUNT):
        field_index = _PLAYER_FIELD_VISIBLE_ITEMS + (slot * 2)
        display_id = int(equipment_cache_raw[slot * 2]) if (slot * 2) < len(equipment_cache_raw) else 0
        field_updates.append((field_index, display_id))
        field_updates.append((field_index + 1, 0))

    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_multi_u32_update_object_payload(
                map_id=map_id,
                guid=player_guid,
                field_updates=field_updates,
            ),
        )
    ]


def _build_self_visible_item_slot_update_responses(session, slot: int, display_id: int = 0) -> list[tuple[str, bytes]]:
    if not (0 <= int(slot) < _PLAYER_VISIBLE_ITEM_SLOT_COUNT):
        return []

    cached = list(getattr(session, "equipment_cache_raw", []) or [])
    required = _PLAYER_VISIBLE_ITEM_SLOT_COUNT * 2
    if len(cached) < required:
        cached.extend([0] * (required - len(cached)))
    cached[int(slot) * 2] = int(display_id)
    cached[int(slot) * 2 + 1] = 0
    session.equipment_cache_raw = cached

    field_index = _PLAYER_FIELD_VISIBLE_ITEMS + (int(slot) * 2)
    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_multi_u32_update_object_payload(
                map_id=int(getattr(session, "map_id", 0) or 0),
                guid=int(getattr(session, "char_guid", 0) or 0),
                field_updates=[
                    (field_index, int(display_id)),
                    (field_index + 1, 0),
                ],
            ),
        )
    ]


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


def _build_player_slot_values_responses(session, slot: int, item_world_guid: int) -> list[tuple[str, bytes]]:
    field_index = _inventory_slot_field_index(0, int(slot))
    if field_index is None:
        return []

    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_multi_u32_update_object_payload(
                map_id=int(getattr(session, "map_id", 0) or 0),
                guid=int(getattr(session, "char_guid", 0) or 0),
                field_updates=[
                    (field_index, int(item_world_guid) & 0xFFFFFFFF),
                    (field_index + 1, int((int(item_world_guid) >> 32) & 0xFFFFFFFF)),
                ],
            ),
        )
    ]


def _build_player_equip_values_responses(
    session,
    slot: int,
    item_world_guid: int,
    visible_entry: int,
) -> list[tuple[str, bytes]]:
    field_index = _inventory_slot_field_index(0, int(slot))
    if field_index is None or not _is_equipment_position(0, int(slot)):
        return []

    visible_field_index = _PLAYER_FIELD_VISIBLE_ITEMS + (int(slot) * 2)
    Logger.debug(
        "[EQUIP_VISIBLE] slot=%s entry=%s field=%s",
        int(slot),
        int(visible_entry),
        int(visible_field_index),
    )
    field_updates = [
        (visible_field_index, int(visible_entry)),
        (visible_field_index + 1, 0),
        (field_index, int(item_world_guid) & 0xFFFFFFFF),
        (field_index + 1, int((int(item_world_guid) >> 32) & 0xFFFFFFFF)),
    ]
    field_updates.sort(key=lambda item: int(item[0]))
    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_multi_u32_update_object_payload(
                map_id=int(getattr(session, "map_id", 0) or 0),
                guid=int(getattr(session, "char_guid", 0) or 0),
                field_updates=field_updates,
            ),
        )
    ]


def _build_login_player_inventory_sync_responses(session) -> list[tuple[str, bytes]]:
    state = getattr(session, "inventory_state", None)
    if state is None:
        return []

    responses: list[tuple[str, bytes]] = []
    for slot in range(39):
        item = state.get(0, slot)
        item_world_guid = _make_item_world_guid(int(item.item_guid)) if item else 0
        if _is_equipment_position(0, slot):
            visible_entry = int(getattr(item, "entry", 0) or 0) if item else 0
            responses.extend(
                _build_player_equip_values_responses(
                    session,
                    int(slot),
                    int(item_world_guid),
                    int(visible_entry),
                )
            )
            continue
        responses.extend(_build_player_slot_values_responses(session, int(slot), int(item_world_guid)))
    return responses


def _build_storage_slot_update_responses(session, bag: int, slot: int, item_world_guid: int | None = None) -> list[tuple[str, bytes]]:
    if int(bag) == 0:
        return _build_player_slot_values_responses(session, int(slot), int(item_world_guid or 0))

    state = getattr(session, "inventory_state", None)
    if state is None:
        return []
    bag_item = state.items_by_guid.get(int(bag))
    if bag_item is None or not bool(getattr(bag_item, "is_bag", False)):
        return []
    return sync_container(session, bag_item, [int(slot)])


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
    return [("SMSG_UPDATE_OBJECT", build_create_object(session, item))]


def build_item_release_responses(session, item) -> list[tuple[str, bytes]]:
    return [("SMSG_UPDATE_OBJECT", _build_item_release_update_payload_old(session, item))]


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


def _position_snapshot(item, *, bag: int, slot: int):
    return type(
        "_InventoryPositionSnapshot",
        (),
        {
            "item_guid": int(getattr(item, "item_guid", 0) or 0),
            "bag": int(bag),
            "slot": int(slot),
            "count": int(getattr(item, "count", 0) or 0),
        },
    )()


def _build_simple_equipment_transition_responses(session, moved_item, old_bag: int, old_slot: int, new_bag: int, new_slot: int) -> list[tuple[str, bytes]]:
    item_guid = _make_item_world_guid(int(getattr(moved_item, "item_guid", 0) or 0))
    item_fields = _merge_item_fields(
        _forced_equipment_item_fields(),
        _determine_item_changed_fields(
            session,
            moved_item,
            _position_snapshot(moved_item, bag=old_bag, slot=old_slot),
        ),
    )
    Logger.debug(
        "[MOVE] item=%s src=(%s,%s) dst=(%s,%s)",
        int(getattr(moved_item, "item_guid", 0) or 0),
        int(old_bag),
        int(old_slot),
        int(new_bag),
        int(new_slot),
    )
    Logger.debug(
        "[ITEM_STATE] owner=%s contained_in=%s",
        int(getattr(session, "char_guid", 0) or 0),
        int(_contained_guid_for_item(session, moved_item)),
    )
    if _is_equipment_position(old_bag, old_slot):
        Logger.debug(f"[UNEQUIP] slot={int(old_slot)} item={int(getattr(moved_item, 'item_guid', 0) or 0)}")
        Logger.debug("[UNEQUIP_ORDER] player→item→container")
        Logger.debug("[UNEQUIP_VISUAL] slot=%s cleared", int(old_slot))
        Logger.debug("[PLAYER_UPDATE] slot=%s -> 0", int(old_slot))
        state = getattr(session, "inventory_state", None)
        bag_item = state.items_by_guid.get(int(new_bag)) if (state is not None and int(new_bag) != 0) else None
        validate_inventory(session)
        validate_item_links(moved_item, session, bag_item)
        batch = build_update_batch()
        add_update(batch, "PLAYER", _build_player_slot_values_responses(session, int(old_slot), 0))
        add_update(batch, "PLAYER_VISIBLE", _build_self_visible_item_slot_update_responses(session, int(old_slot), 0))
        add_update(batch, "ITEM", sync_known_item(session, moved_item, item_fields))
        if int(new_bag) == 0:
            add_update(batch, "CONTAINER", _build_storage_slot_update_responses(session, int(new_bag), int(new_slot), int(item_guid)))
        elif bag_item is not None:
            add_update(batch, "CONTAINER", sync_known_container(session, bag_item, [int(new_slot)]))
        return send_update_batch(session, batch)

    Logger.debug(f"[EQUIP] slot={int(new_slot)} item={int(getattr(moved_item, 'item_guid', 0) or 0)}")
    Logger.debug("[EQUIP_ORDER] container→item→player")
    state = getattr(session, "inventory_state", None)
    source_bag_item = state.items_by_guid.get(int(old_bag)) if (state is not None and int(old_bag) != 0) else None
    validate_inventory(session)
    validate_item_links(moved_item, session, None)
    batch = build_update_batch()
    if int(old_bag) == 0:
        add_update(batch, "CONTAINER", _build_storage_slot_update_responses(session, int(old_bag), int(old_slot), 0))
    elif source_bag_item is not None:
        add_update(batch, "CONTAINER", sync_known_container(session, source_bag_item, [int(old_slot)]))
    add_update(batch, "ITEM", sync_known_item(session, moved_item, item_fields))
    add_update(
        batch,
        "PLAYER",
        _build_player_equip_values_responses(
            session,
            int(new_slot),
            int(item_guid),
            int(getattr(moved_item, "entry", 0) or 0),
        ),
    )
    return send_update_batch(session, batch)


def _build_equipment_swap_responses(session, equip_slot: int, storage_bag: int, storage_slot: int) -> list[tuple[str, bytes]]:
    state = getattr(session, "inventory_state", None)
    if state is None:
        return []

    equipped_item = state.get(0, int(equip_slot))
    storage_item = state.get(int(storage_bag), int(storage_slot))
    if equipped_item is None or storage_item is None:
        return []

    equipped_guid = _make_item_world_guid(int(getattr(equipped_item, "item_guid", 0) or 0))
    equipped_fields = _merge_item_fields(
        _forced_equipment_item_fields(),
        _determine_item_changed_fields(
            session,
            equipped_item,
            _position_snapshot(equipped_item, bag=int(storage_bag), slot=int(storage_slot)),
        ),
    )
    storage_fields = _merge_item_fields(
        _forced_equipment_item_fields(),
        _determine_item_changed_fields(
            session,
            storage_item,
            _position_snapshot(storage_item, bag=0, slot=int(equip_slot)),
        ),
    )

    Logger.debug(f"[EQUIP] slot={int(equip_slot)} item={int(getattr(equipped_item, 'item_guid', 0) or 0)}")
    Logger.debug("[EQUIP_ORDER] player-clear→old-item→container→new-item→player-set")
    Logger.debug(
        "[MOVE] item=%s src=(%s,%s) dst=(%s,%s)",
        int(getattr(equipped_item, "item_guid", 0) or 0),
        int(storage_bag),
        int(storage_slot),
        0,
        int(equip_slot),
    )
    Logger.debug(
        "[ITEM_STATE] owner=%s contained_in=%s",
        int(getattr(session, "char_guid", 0) or 0),
        int(_contained_guid_for_item(session, equipped_item)),
    )
    bag_item = state.items_by_guid.get(int(storage_bag)) if int(storage_bag) != 0 else None
    validate_inventory(session)
    validate_item_links(equipped_item, session, bag_item)
    validate_item_links(storage_item, session, None)

    batch = build_update_batch()
    add_update(batch, "PLAYER", _build_player_slot_values_responses(session, int(equip_slot), 0))
    add_update(batch, "ITEM", sync_known_item(session, storage_item, storage_fields))
    if int(storage_bag) == 0:
        add_update(
            batch,
            "CONTAINER",
            _build_storage_slot_update_responses(
                session,
                int(storage_bag),
                int(storage_slot),
                int(_make_item_world_guid(int(getattr(storage_item, "item_guid", 0) or 0))),
            )
        )
    elif bag_item is not None:
        add_update(batch, "CONTAINER", sync_known_container(session, bag_item, [int(storage_slot)]))
    add_update(batch, "ITEM", sync_known_item(session, equipped_item, equipped_fields))
    add_update(
        batch,
        "PLAYER",
        _build_player_equip_values_responses(
            session,
            int(equip_slot),
            int(equipped_guid),
            int(getattr(equipped_item, "entry", 0) or 0),
        ),
    )
    return send_update_batch(session, batch)


def build_login_inventory_sync_responses(session) -> list[tuple[str, bytes]]:
    state = getattr(session, "inventory_state", None)
    if state is None or not hasattr(state, "get") or not hasattr(state, "items_by_pos"):
        return []
    cleared_known_guids = len(_known_inventory_guids(session))
    _clear_known_inventory_guids(session)
    session.inventory_activated = False
    Logger.debug("[LOGIN_SYNC] syncing inventory + equip + visible")
    equipped_bag_slots = {
        int(getattr(item, "slot", 0) or 0)
        for item in _equipped_bag_items(state)
    }

    root_items = sorted(
        (
            item
            for item in getattr(state, "items_by_pos", {}).values()
            if int(getattr(item, "bag", -1)) == 0
            and not (
                bool(getattr(item, "is_bag", False))
                and int(getattr(item, "slot", -1) or -1) in equipped_bag_slots
            )
        ),
        key=lambda item: (int(getattr(item, "slot", 0) or 0), int(getattr(item, "item_guid", 0) or 0)),
    )

    responses: list[tuple[str, bytes]] = []
    responses.extend(_build_login_player_inventory_sync_responses(session))
    responses.extend(build_equipped_bag_sync_responses(session))
    for item in root_items:
        responses.extend(sync_item(session, item))
    Logger.debug(
        f"[INV] FULL_RESYNC cleared_known_guids={cleared_known_guids} rebuilt={len(_known_inventory_guids(session))}"
    )
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

    known_guids = _known_inventory_guids(session)
    bag_world_guid = _make_item_world_guid(int(bag_item.item_guid))
    bag_known = bag_world_guid in known_guids
    created_items = 0
    values_items = 0
    responses: list[tuple[str, bytes]] = []
    responses.extend(sync_container(session, bag_item))

    for slot in range(int(getattr(bag_item, "container_slots", 0) or 0)):
        item = state.get(int(bag_item.item_guid), slot)
        if item is None:
            continue
        item_world_guid = _make_item_world_guid(int(item.item_guid))
        item_known = item_world_guid in known_guids
        item_responses = sync_item(session, item)
        if item_responses:
            if item_known:
                values_items += 1
            else:
                created_items += 1
        responses.extend(item_responses)

    Logger.debug(
        f"[INV] BAG_OPEN bag={int(bag_item.item_guid)} known={bag_known} "
        f"create_items={created_items} values_items={values_items}"
    )

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
    known_guids = _known_inventory_guids(session)
    for world_guid in world_guids:
        known_guids.discard(int(world_guid))

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
    known_guids = _known_inventory_guids(session)
    changed_positions = list(
        dict.fromkeys((int(bag), int(slot)) for bag, slot in (getattr(result, "changed_positions", ()) or ()))
    )
    changed_items = list(
        dict.fromkeys(
            int(getattr(item, "item_guid", 0) or 0)
            for item in (getattr(result, "changed_items", ()) or ())
            if int(getattr(item, "item_guid", 0) or 0) > 0
        )
    )
    released_items = [
        item for item in (getattr(result, "released_items", ()) or ()) if int(getattr(item, "item_guid", 0) or 0) > 0
    ]
    removed_item_guids = [
        int(item_guid) for item_guid in (getattr(result, "removed_item_guids", ()) or ()) if int(item_guid) > 0
    ]
    created_item_guids = {
        int(item_guid) for item_guid in (getattr(result, "created_item_guids", ()) or ()) if int(item_guid) > 0
    }
    released_by_guid = {
        int(getattr(item, "item_guid", 0) or 0): item
        for item in released_items
        if int(getattr(item, "item_guid", 0) or 0) > 0
    }

    if len(released_items) == 1 and len(changed_items) == 1 and len(changed_positions) >= 2:
        released_item = released_items[0]
        moved_item = state.items_by_guid.get(int(changed_items[0]))
        old_bag = int(getattr(released_item, "bag", 0) or 0)
        old_slot = int(getattr(released_item, "slot", 0) or 0)
        new_bag = int(getattr(moved_item, "bag", 0) or 0) if moved_item is not None else old_bag
        new_slot = int(getattr(moved_item, "slot", 0) or 0) if moved_item is not None else old_slot
        item_fields = _determine_item_changed_fields(session, moved_item, released_item) if moved_item is not None else []
        if moved_item is not None and not _is_equipment_position(old_bag, old_slot) and _is_equipment_position(new_bag, new_slot):
            Logger.debug(
                f"[INV] EQUIP item={int(getattr(moved_item, 'item_guid', 0) or 0)} "
                f"src=({old_bag},{old_slot}) equip_slot={new_slot} fields={item_fields}"
            )
        elif moved_item is not None and _is_equipment_position(old_bag, old_slot) and not _is_equipment_position(new_bag, new_slot):
            Logger.debug(
                f"[INV] UNEQUIP item={int(getattr(moved_item, 'item_guid', 0) or 0)} "
                f"equip_slot={old_slot} dst=({new_bag},{new_slot}) fields={item_fields}"
            )
        else:
            Logger.debug(
                f"[INV] MOVE item={int(getattr(moved_item, 'item_guid', 0) or 0)} "
                f"src=({old_bag},{old_slot}) dst=({new_bag},{new_slot}) "
                f"item_fields={item_fields} src_slot_clear=True dst_slot_set=True"
            )
        if moved_item is not None and (_is_equipment_position(old_bag, old_slot) or _is_equipment_position(new_bag, new_slot)):
            responses.extend(
                _build_simple_equipment_transition_responses(
                    session,
                    moved_item,
                    old_bag,
                    old_slot,
                    new_bag,
                    new_slot,
                )
            )
        else:
            if old_bag == 0:
                responses.extend(_build_inventory_position_update_responses(session, old_bag, old_slot))
            else:
                bag_item = state.items_by_guid.get(old_bag)
                if bag_item is not None and bool(getattr(bag_item, "is_bag", False)):
                    responses.extend(sync_container(session, bag_item, [old_slot]))

            if moved_item is not None:
                if new_bag == 0:
                    responses.extend(_build_inventory_position_update_responses(session, new_bag, new_slot))
                else:
                    bag_item = state.items_by_guid.get(new_bag)
                    if bag_item is None or not bool(getattr(bag_item, "is_bag", False)):
                        pass
                    else:
                        responses.extend(sync_container(session, bag_item, [new_slot]))

                responses.extend(sync_item(session, moved_item, item_fields))
                responses.extend(maybe_trigger_inventory_activation(session, old_bag, new_bag))
    else:
        if len(changed_items) == 2 and len(changed_positions) == 2:
            equip_positions = [(int(bag), int(slot)) for bag, slot in changed_positions if _is_equipment_position(int(bag), int(slot))]
            storage_positions = [(int(bag), int(slot)) for bag, slot in changed_positions if not _is_equipment_position(int(bag), int(slot))]
            if len(equip_positions) == 1 and len(storage_positions) == 1:
                equip_slot = int(equip_positions[0][1])
                storage_bag, storage_slot = storage_positions[0]
                responses.extend(_build_equipment_swap_responses(session, equip_slot, storage_bag, storage_slot))
            else:
                changed_slots_by_bag: dict[int, list[int]] = {}
                for bag, slot in changed_positions:
                    if int(bag) == 0:
                        responses.extend(_build_inventory_position_update_responses(session, bag, slot))
                    else:
                        changed_slots_by_bag.setdefault(int(bag), []).append(int(slot))

                for bag_guid, slots in sorted(changed_slots_by_bag.items()):
                    bag_item = state.items_by_guid.get(int(bag_guid))
                    if bag_item is None or not bool(getattr(bag_item, "is_bag", False)):
                        continue
                    responses.extend(sync_container(session, bag_item, sorted(dict.fromkeys(int(slot) for slot in slots))))

                for item_guid in changed_items:
                    item = state.items_by_guid.get(int(item_guid))
                    if item is None:
                        continue
                    item_world_guid = _make_item_world_guid(int(item_guid))
                    if int(item_guid) in created_item_guids:
                        Logger.debug(
                            f"[INV] ADDITEM item={int(item_guid)} dst=({int(getattr(item, 'bag', 0) or 0)},{int(getattr(item, 'slot', 0) or 0)}) "
                            f"create={item_world_guid not in known_guids}"
                        )
                    previous_item = released_by_guid.get(int(item_guid))
                    changed_fields = _determine_item_changed_fields(
                        session,
                        item,
                        previous_item,
                        default_to_stack=(previous_item is None and not changed_positions),
                    )
                    responses.extend(sync_item(session, item, changed_fields))
                    if previous_item is not None and not (
                        _is_equipment_position(int(getattr(previous_item, "bag", 0) or 0), int(getattr(previous_item, "slot", 0) or 0))
                        or _is_equipment_position(int(getattr(item, "bag", 0) or 0), int(getattr(item, "slot", 0) or 0))
                    ):
                        responses.extend(
                            maybe_trigger_inventory_activation(
                                session,
                                int(getattr(previous_item, "bag", 0) or 0),
                                int(getattr(item, "bag", 0) or 0),
                            )
                        )
        else:
            changed_slots_by_bag: dict[int, list[int]] = {}
            if not removed_item_guids:
                for bag, slot in changed_positions:
                    if int(bag) == 0:
                        responses.extend(_build_inventory_position_update_responses(session, bag, slot))
                    else:
                        changed_slots_by_bag.setdefault(int(bag), []).append(int(slot))

                for bag_guid, slots in sorted(changed_slots_by_bag.items()):
                    bag_item = state.items_by_guid.get(int(bag_guid))
                    if bag_item is None or not bool(getattr(bag_item, "is_bag", False)):
                        continue
                    responses.extend(sync_container(session, bag_item, sorted(dict.fromkeys(int(slot) for slot in slots))))

            for item_guid in changed_items:
                item = state.items_by_guid.get(int(item_guid))
                if item is None:
                    continue
                item_world_guid = _make_item_world_guid(int(item_guid))
                if int(item_guid) in created_item_guids:
                    Logger.debug(
                        f"[INV] ADDITEM item={int(item_guid)} dst=({int(getattr(item, 'bag', 0) or 0)},{int(getattr(item, 'slot', 0) or 0)}) "
                        f"create={item_world_guid not in known_guids}"
                    )
                previous_item = released_by_guid.get(int(item_guid))
                changed_fields = _determine_item_changed_fields(
                    session,
                    item,
                    previous_item,
                    default_to_stack=(previous_item is None and not changed_positions),
                )
                responses.extend(sync_item(session, item, changed_fields))
                if previous_item is not None and not (
                    _is_equipment_position(int(getattr(previous_item, "bag", 0) or 0), int(getattr(previous_item, "slot", 0) or 0))
                    or _is_equipment_position(int(getattr(item, "bag", 0) or 0), int(getattr(item, "slot", 0) or 0))
                ):
                    responses.extend(
                        maybe_trigger_inventory_activation(
                            session,
                            int(getattr(previous_item, "bag", 0) or 0),
                            int(getattr(item, "bag", 0) or 0),
                        )
                    )

    removed_known_before = {int(item_guid): (int(_make_item_world_guid(int(item_guid))) in known_guids) for item_guid in removed_item_guids}
    if removed_item_guids:
        for index, item_guid in enumerate(removed_item_guids):
            bag, slot = changed_positions[index] if index < len(changed_positions) else (-1, -1)
            Logger.debug(
                "[DESTROY] item=%s slot=%s container=%s",
                int(item_guid),
                int(slot),
                int(bag),
            )
            if int(bag) >= 0 and int(slot) >= 0:
                clear_batch = build_update_batch()
                add_update(clear_batch, "CONTAINER", _build_storage_slot_update_responses(session, int(bag), int(slot), 0))
                # Destroying equipped items must also clear visible gear immediately.
                if _is_equipment_position(int(bag), int(slot)):
                    add_update(
                        clear_batch,
                        "PLAYER_VISIBLE",
                        _build_self_visible_item_slot_update_responses(session, int(slot), 0),
                    )
                responses.extend(send_update_batch(session, clear_batch))
            remove_batch = build_update_batch()
            add_out_of_range(remove_batch, session, int(item_guid))
            responses.extend(send_update_batch(session, remove_batch))
    for index, item_guid in enumerate(removed_item_guids):
        bag, slot = changed_positions[index] if index < len(changed_positions) else (-1, -1)
        Logger.debug(
            f"[INV] REMOVE item={int(item_guid)} from=({int(bag)},{int(slot)}) "
            f"known_before={removed_known_before.get(int(item_guid), False)} "
            f"known_after={int(_make_item_world_guid(int(item_guid))) in known_guids}"
        )
    return responses


def build_equipped_bag_sync_responses(session) -> list[tuple[str, bytes]]:
    state = getattr(session, "inventory_state", None)
    if state is None:
        return []

    responses: list[tuple[str, bytes]] = []
    for bag_item in _equipped_bag_items(state):
        responses.extend(sync_container(session, bag_item))
        for bag_slot in range(int(getattr(bag_item, "container_slots", 0) or 0)):
            item = state.get(int(bag_item.item_guid), bag_slot)
            if item is None:
                continue
            responses.extend(sync_item(session, item))
    return responses
