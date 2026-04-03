from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import func

from shared.Logger import Logger
from server.modules.database.CharactersModel import CharacterInventory, ItemInstance
from server.modules.database.DatabaseConnection import DatabaseConnection

ITEM_CLASS_CONTAINER = 1
ITEM_SUBCLASS_CONTAINER = 0
INVENTORY_SLOT_BAG_0 = 255

EQUIPMENT_SLOT_END = 19
INVENTORY_SLOT_BAG_START = 19
INVENTORY_SLOT_BAG_END = 23
INVENTORY_SLOT_ITEM_START = 23
INVENTORY_SLOT_ITEM_END = 39

_INVTYPE_SLOT_MAP = {
    1: [0],
    2: [1],
    3: [2],
    4: [3],
    5: [4],
    20: [4],
    6: [5],
    7: [6],
    8: [7],
    9: [8],
    10: [9],
    11: [10, 11],
    12: [12, 13],
    16: [14],
    13: [15],
    17: [15],
    21: [15],
    22: [16],
    14: [16],
    23: [16],
    15: [17],
    25: [17],
    26: [17],
    28: [17],
    19: [18],
    18: [19, 20, 21, 22],
}


@dataclass(slots=True)
class ItemTemplateInfo:
    entry: int
    display_id: int
    inventory_type: int
    stackable: int
    buy_count: int
    bag_family: int
    item_class: int
    subclass: int
    container_slots: int

    @property
    def is_bag(self) -> bool:
        return self.item_class == ITEM_CLASS_CONTAINER


@dataclass(slots=True)
class InventoryItem:
    item_guid: int
    owner_guid: int
    bag: int
    slot: int
    count: int
    template: ItemTemplateInfo
    flags: int = 0
    durability: int = 0
    random_property_id: int = 0

    @property
    def entry(self) -> int:
        return self.template.entry

    @property
    def display_id(self) -> int:
        return self.template.display_id

    @property
    def inventory_type(self) -> int:
        return self.template.inventory_type

    @property
    def is_bag(self) -> bool:
        return self.template.is_bag

    @property
    def container_slots(self) -> int:
        return self.template.container_slots if self.is_bag else 0


@dataclass(slots=True)
class InventoryState:
    items_by_pos: dict[tuple[int, int], InventoryItem] = field(default_factory=dict)
    items_by_guid: dict[int, InventoryItem] = field(default_factory=dict)

    def get(self, bag: int, slot: int) -> Optional[InventoryItem]:
        return self.items_by_pos.get((int(bag), int(slot)))

    def put(self, item: InventoryItem) -> None:
        bag = int(item.bag)
        slot = int(item.slot)
        item_guid = int(item.item_guid)

        existing = self.items_by_guid.get(item_guid)
        if existing is not None:
            self.items_by_pos.pop((int(existing.bag), int(existing.slot)), None)

        occupant = self.items_by_pos.get((bag, slot))
        if occupant is not None and int(occupant.item_guid) != item_guid:
            raise ValueError(f"inventory position already occupied bag={bag} slot={slot}")

        self.items_by_pos[(bag, slot)] = item
        self.items_by_guid[item_guid] = item

    def remove(self, item: InventoryItem) -> None:
        self.items_by_pos.pop((int(item.bag), int(item.slot)), None)
        self.items_by_guid.pop(int(item.item_guid), None)


@dataclass(slots=True)
class InventoryResult:
    ok: bool
    message: str
    added: int = 0
    item: Optional[InventoryItem] = None
    changed_items: tuple[InventoryItem, ...] = ()
    created_item_guids: tuple[int, ...] = ()


def _template_from_dict(data: dict | None) -> Optional[ItemTemplateInfo]:
    if not data:
        return None
    return ItemTemplateInfo(
        entry=int(data.get("entry", 0) or 0),
        display_id=int(data.get("display_id", 0) or 0),
        inventory_type=int(data.get("inventory_type", 0) or 0),
        stackable=max(1, int(data.get("stackable", 1) or 1)),
        buy_count=max(1, int(data.get("buy_count", 1) or 1)),
        bag_family=int(data.get("bag_family", 0) or 0),
        item_class=int(data.get("item_class", 0) or 0),
        subclass=int(data.get("subclass", 0) or 0),
        container_slots=int(data.get("container_slots", 0) or 0),
    )


def get_item_template(entry: int) -> Optional[ItemTemplateInfo]:
    templates = DatabaseConnection.get_item_template_details([int(entry)])
    return _template_from_dict(templates.get(int(entry)))


def load_inventory_state(char_guid: int) -> InventoryState:
    rows = DatabaseConnection.get_character_inventory_rows(int(char_guid))
    entries = sorted({int(row["item_entry"]) for row in rows if int(row.get("item_entry", 0) or 0) > 0})
    templates = DatabaseConnection.get_item_template_details(entries)

    state = InventoryState()
    for row in rows:
        template = _template_from_dict(templates.get(int(row["item_entry"])))
        if not template:
            continue
        item = InventoryItem(
            item_guid=int(row["item_guid"]),
            owner_guid=int(row["owner_guid"]),
            bag=int(row["bag"]),
            slot=int(row["slot"]),
            count=max(1, int(row["count"] or 1)),
            template=template,
            flags=int(row.get("flags", 0) or 0),
            durability=int(row.get("durability", 0) or 0),
            random_property_id=int(row.get("random_property_id", 0) or 0),
        )
        state.put(item)
    return state


def build_equipment_cache_raw(state: InventoryState) -> list[int]:
    pairs = [0] * (23 * 2)
    for slot in range(23):
        item = state.get(0, slot)
        if not item:
            continue
        pairs[slot * 2] = int(item.display_id)
        pairs[slot * 2 + 1] = int(item.inventory_type)
    return pairs


def build_equipment_cache_string(state: InventoryState) -> str:
    return " ".join(str(value) for value in build_equipment_cache_raw(state))


def refresh_session_inventory(session, *, persist: bool = False) -> InventoryState:
    char_guid = int(getattr(session, "char_guid", 0) or 0)
    state = load_inventory_state(char_guid) if char_guid > 0 else InventoryState()
    session.inventory_state = state
    session.inventory_items = dict(state.items_by_pos)
    session.inventory_by_guid = dict(state.items_by_guid)
    equipment_cache = build_equipment_cache_raw(state)
    session.equipment_cache_raw = equipment_cache

    if persist and char_guid > 0:
        equipment_cache_text = " ".join(str(value) for value in equipment_cache)
        realm_id = int(getattr(session, "realm_id", 0) or 0)
        current_cache = str(getattr(getattr(session, "_character_row", None), "equipmentCache", "") or "")
        if equipment_cache_text != current_cache:
            DatabaseConnection.save_character_equipment_cache(char_guid, realm_id, equipment_cache_text)
    return state


def _is_equipment_slot(slot: int) -> bool:
    return 0 <= int(slot) < EQUIPMENT_SLOT_END


def _is_bag_slot(slot: int) -> bool:
    return INVENTORY_SLOT_BAG_START <= int(slot) < INVENTORY_SLOT_BAG_END


def _is_backpack_slot(slot: int) -> bool:
    return INVENTORY_SLOT_ITEM_START <= int(slot) < INVENTORY_SLOT_ITEM_END


def _is_storage_position(bag: int, slot: int) -> bool:
    bag = int(bag)
    slot = int(slot)
    if bag == 0:
        return _is_backpack_slot(slot)
    return slot >= 0


def _bag_item_for_container(state: InventoryState, bag_guid: int) -> Optional[InventoryItem]:
    if int(bag_guid) <= 0:
        return None
    item = state.items_by_guid.get(int(bag_guid))
    if item and item.is_bag:
        return item
    return None


def _resolve_internal_bag(state: InventoryState, client_bag: int) -> Optional[int]:
    client_bag = int(client_bag)
    if client_bag in (0, INVENTORY_SLOT_BAG_0):
        return 0
    bag_item = state.get(0, client_bag)
    if bag_item and bag_item.is_bag:
        return int(bag_item.item_guid)
    return None


def _resolve_client_bag_for_internal(state: InventoryState, internal_bag: int) -> Optional[int]:
    internal_bag = int(internal_bag)
    if internal_bag == 0:
        return 0
    bag_item = state.items_by_guid.get(internal_bag)
    if not bag_item:
        return None
    if int(bag_item.bag) != 0 or not _is_bag_slot(int(bag_item.slot)):
        return None
    return int(bag_item.slot)


def _bag_has_contents(state: InventoryState, bag_guid: int) -> bool:
    bag_guid = int(bag_guid)
    if bag_guid <= 0:
        return False
    for item in state.items_by_pos.values():
        if int(item.bag) == bag_guid:
            return True
    return False


def _is_equippable_bag(item: InventoryItem) -> bool:
    return item.is_bag and int(item.inventory_type) == 18 and int(item.container_slots) > 0


def _can_item_use_bag(item: InventoryItem, container: InventoryItem) -> bool:
    if not container.is_bag:
        return False
    if container.template.bag_family == 0:
        return True
    if item.template.bag_family == 0:
        return False
    return bool(item.template.bag_family & container.template.bag_family)


def _slot_allows_item(state: InventoryState, item: InventoryItem, bag: int, slot: int) -> bool:
    bag = int(bag)
    slot = int(slot)

    if bag == 0:
        if _is_equipment_slot(slot):
            candidates = _INVTYPE_SLOT_MAP.get(int(item.inventory_type), [])
            return slot in candidates
        if _is_bag_slot(slot):
            return _is_equippable_bag(item)
        if _is_backpack_slot(slot):
            return True
        return False

    container = _bag_item_for_container(state, bag)
    if not container:
        return False
    if item.is_bag:
        return False
    if slot < 0 or slot >= int(container.container_slots):
        return False
    return _can_item_use_bag(item, container)


def _first_free_storage_slot(state: InventoryState, item: InventoryItem) -> Optional[tuple[int, int]]:
    for slot in range(INVENTORY_SLOT_ITEM_START, INVENTORY_SLOT_ITEM_END):
        if state.get(0, slot) is None:
            return (0, slot)

    for bag_slot in range(INVENTORY_SLOT_BAG_START, INVENTORY_SLOT_BAG_END):
        bag_item = state.get(0, bag_slot)
        if not bag_item or not bag_item.is_bag:
            continue
        if bag_item.container_slots <= 0:
            continue
        for slot in range(int(bag_item.container_slots)):
            if state.get(bag_item.item_guid, slot) is None and _slot_allows_item(state, item, bag_item.item_guid, slot):
                return (bag_item.item_guid, slot)
    return None


def _find_merge_target(state: InventoryState, entry: int, stackable: int) -> Optional[InventoryItem]:
    if stackable <= 1:
        return None
    for slot in range(INVENTORY_SLOT_ITEM_START, INVENTORY_SLOT_ITEM_END):
        item = state.get(0, slot)
        if item and item.entry == int(entry) and item.count < stackable:
            return item
    for bag_slot in range(INVENTORY_SLOT_BAG_START, INVENTORY_SLOT_BAG_END):
        bag_item = state.get(0, bag_slot)
        if not bag_item or not bag_item.is_bag:
            continue
        for slot in range(int(bag_item.container_slots)):
            item = state.get(bag_item.item_guid, slot)
            if item and item.entry == int(entry) and item.count < stackable:
                return item
    return None


def _find_equip_destination(state: InventoryState, item: InventoryItem) -> Optional[tuple[int, int]]:
    candidates = list(_INVTYPE_SLOT_MAP.get(int(item.inventory_type), []))
    if not candidates:
        return None
    for slot in candidates:
        occupant = state.get(0, slot)
        if occupant is None:
            return (0, slot)
    return (0, candidates[0])


def _allocate_item_instance_guid(db_session) -> int:
    max_guid = db_session.query(func.max(ItemInstance.guid)).scalar()
    return int(max_guid or 0) + 1


def _persist_position(db_session, char_guid: int, item: InventoryItem) -> None:
    row = db_session.query(CharacterInventory).filter(CharacterInventory.item == int(item.item_guid)).one_or_none()
    if row is None:
        row = CharacterInventory(
            guid=int(char_guid),
            bag=int(item.bag),
            slot=int(item.slot),
            item=int(item.item_guid),
        )
        db_session.add(row)
        return
    row.guid = int(char_guid)
    row.bag = int(item.bag)
    row.slot = int(item.slot)


def _remove_position(db_session, item_guid: int) -> None:
    db_session.query(CharacterInventory).filter(CharacterInventory.item == int(item_guid)).delete(synchronize_session=False)


def _set_item_count(db_session, item_guid: int, count: int) -> None:
    row = db_session.query(ItemInstance).filter(ItemInstance.guid == int(item_guid)).one()
    row.count = max(1, int(count))


def _save_equipment_cache_after_mutation(session, state: InventoryState) -> None:
    session.inventory_state = state
    session.inventory_items = dict(state.items_by_pos)
    session.inventory_by_guid = dict(state.items_by_guid)
    equipment_cache = build_equipment_cache_raw(state)
    session.equipment_cache_raw = equipment_cache
    char_guid = int(getattr(session, "char_guid", 0) or 0)
    realm_id = int(getattr(session, "realm_id", 0) or 0)
    if char_guid > 0 and realm_id >= 0:
        DatabaseConnection.save_character_equipment_cache(
            char_guid,
            realm_id,
            " ".join(str(value) for value in equipment_cache),
        )


def add_item_to_character(session, item_entry: int, count: int = 1) -> InventoryResult:
    item_entry = int(item_entry or 0)
    remaining = max(0, int(count or 0))
    if item_entry <= 0 or remaining <= 0:
        return InventoryResult(False, "invalid item request")

    template = get_item_template(item_entry)
    if not template:
        return InventoryResult(False, f"item {item_entry} not found")

    char_guid = int(getattr(session, "char_guid", 0) or 0)
    if char_guid <= 0:
        return InventoryResult(False, "no active character")

    state = getattr(session, "inventory_state", None)
    if not isinstance(state, InventoryState):
        state = refresh_session_inventory(session)

    db_session = DatabaseConnection.chars()
    added = 0
    first_item: Optional[InventoryItem] = None
    changed_items: list[InventoryItem] = []
    created_item_guids: list[int] = []

    def _track_changed(item: InventoryItem, *, created: bool = False) -> None:
        if all(int(existing.item_guid) != int(item.item_guid) for existing in changed_items):
            changed_items.append(item)
        if created and int(item.item_guid) not in created_item_guids:
            created_item_guids.append(int(item.item_guid))

    try:
        while remaining > 0:
            merge_target = _find_merge_target(state, item_entry, template.stackable)
            if merge_target is not None:
                free = max(0, int(template.stackable) - int(merge_target.count))
                move_count = min(remaining, free)
                if move_count <= 0:
                    merge_target = None
                else:
                    merge_target.count += move_count
                    _set_item_count(db_session, merge_target.item_guid, merge_target.count)
                    _track_changed(merge_target)
                    added += move_count
                    remaining -= move_count
                    if first_item is None:
                        first_item = merge_target
                    continue

            placement_probe = InventoryItem(
                item_guid=0,
                owner_guid=char_guid,
                bag=0,
                slot=0,
                count=1,
                template=template,
            )
            destination = _first_free_storage_slot(state, placement_probe)
            if destination is None:
                break

            chunk_count = min(remaining, int(template.stackable))
            item_guid = _allocate_item_instance_guid(db_session)
            row = ItemInstance(
                guid=item_guid,
                itemEntry=item_entry,
                owner_guid=char_guid,
                creatorGuid=0,
                giftCreatorGuid=0,
                count=chunk_count,
                duration=0,
                charges="",
                flags=0,
                enchantments="",
                randomPropertyId=0,
                reforgeID=0,
                durability=0,
                playedTime=0,
                text=None,
            )
            db_session.add(row)

            item = InventoryItem(
                item_guid=item_guid,
                owner_guid=char_guid,
                bag=int(destination[0]),
                slot=int(destination[1]),
                count=chunk_count,
                template=template,
            )
            state.put(item)
            _persist_position(db_session, char_guid, item)
            _track_changed(item, created=True)
            added += chunk_count
            remaining -= chunk_count
            if first_item is None:
                first_item = item

        if added <= 0:
            db_session.rollback()
            return InventoryResult(False, "inventory full")

        db_session.commit()
    except Exception as exc:
        db_session.rollback()
        refresh_session_inventory(session)
        Logger.warning(f"[Inventory] add_item_to_character failed entry={item_entry} count={count}: {exc}")
        return InventoryResult(False, f"db error while adding item {item_entry}")

    _save_equipment_cache_after_mutation(session, state)
    message = f"added {added}x item {item_entry}"
    if remaining > 0:
        message = f"{message} ({remaining} no space)"
    return InventoryResult(
        True,
        message,
        added=added,
        item=first_item,
        changed_items=tuple(changed_items),
        created_item_guids=tuple(created_item_guids),
    )


def swap_character_item(session, src_bag: int, src_slot: int, dst_bag: int, dst_slot: int) -> InventoryResult:
    src_client_bag = int(src_bag)
    src_slot = int(src_slot)
    dst_client_bag = int(dst_bag)
    dst_slot = int(dst_slot)

    state = getattr(session, "inventory_state", None)
    if not isinstance(state, InventoryState):
        state = refresh_session_inventory(session)

    src_bag = _resolve_internal_bag(state, src_client_bag)
    dst_bag = _resolve_internal_bag(state, dst_client_bag)
    if src_bag is None:
        return InventoryResult(False, "source bag not found")
    if dst_bag is None:
        return InventoryResult(False, "destination bag not found")

    src_item = state.get(src_bag, src_slot)
    if not src_item:
        return InventoryResult(False, "source item not found")

    if src_bag == dst_bag and src_slot == dst_slot:
        return InventoryResult(True, "no-op", item=src_item)

    dst_item = state.get(dst_bag, dst_slot)

    if not _slot_allows_item(state, src_item, dst_bag, dst_slot):
        return InventoryResult(False, "destination slot does not fit item")

    if src_item.is_bag and dst_bag != 0:
        return InventoryResult(False, "cannot place bag inside another bag")

    if _bag_has_contents(state, src_item.item_guid) and not _is_bag_slot(dst_slot) and dst_bag == 0:
        return InventoryResult(False, "cannot move non-empty equipped bag there yet")

    if dst_item:
        if dst_item.is_bag and src_bag != 0:
            return InventoryResult(False, "cannot place bag inside another bag")
        if not _slot_allows_item(state, dst_item, src_bag, src_slot):
            return InventoryResult(False, "swap target cannot move to source slot")
        if _bag_has_contents(state, dst_item.item_guid) and not _is_bag_slot(src_slot) and src_bag == 0:
            return InventoryResult(False, "cannot move non-empty equipped bag there yet")

    db_session = DatabaseConnection.chars()
    char_guid = int(getattr(session, "char_guid", 0) or 0)
    try:
        src_old_bag, src_old_slot = src_item.bag, src_item.slot
        dst_old_bag = dst_item.bag if dst_item else None
        dst_old_slot = dst_item.slot if dst_item else None

        state.remove(src_item)
        if dst_item:
            state.remove(dst_item)

        src_item.bag = dst_bag
        src_item.slot = dst_slot
        state.put(src_item)
        _persist_position(db_session, char_guid, src_item)

        if dst_item:
            dst_item.bag = src_old_bag
            dst_item.slot = src_old_slot
            state.put(dst_item)
            _persist_position(db_session, char_guid, dst_item)

        db_session.commit()
    except Exception as exc:
        db_session.rollback()
        src_item.bag = src_old_bag
        src_item.slot = src_old_slot
        if dst_item and dst_old_bag is not None and dst_old_slot is not None:
            dst_item.bag = dst_old_bag
            dst_item.slot = dst_old_slot
        refresh_session_inventory(session)
        Logger.warning(
            f"[Inventory] swap_character_item failed src=({src_client_bag},{src_slot}) dst=({dst_client_bag},{dst_slot}): {exc}"
        )
        return InventoryResult(False, "db error while moving item")

    _save_equipment_cache_after_mutation(session, state)
    return InventoryResult(True, "item moved", item=src_item)


def auto_equip_item(session, src_bag: int, src_slot: int) -> InventoryResult:
    state = getattr(session, "inventory_state", None)
    if not isinstance(state, InventoryState):
        state = refresh_session_inventory(session)

    src_internal_bag = _resolve_internal_bag(state, int(src_bag))
    if src_internal_bag is None:
        return InventoryResult(False, "source bag not found")

    item = state.get(src_internal_bag, int(src_slot))
    if not item:
        return InventoryResult(False, "source item not found")

    destination = _find_equip_destination(state, item)
    if destination is None:
        return InventoryResult(False, "item cannot be equipped")

    return swap_character_item(session, int(src_bag), int(src_slot), int(destination[0]), int(destination[1]))


def auto_store_item(session, src_bag: int, src_slot: int, dst_bag: int) -> InventoryResult:
    state = getattr(session, "inventory_state", None)
    if not isinstance(state, InventoryState):
        state = refresh_session_inventory(session)

    src_internal_bag = _resolve_internal_bag(state, int(src_bag))
    if src_internal_bag is None:
        return InventoryResult(False, "source bag not found")

    item = state.get(src_internal_bag, int(src_slot))
    if not item:
        return InventoryResult(False, "source item not found")

    if int(dst_bag) == 0:
        destination = _first_free_storage_slot(state, item)
        if destination is None:
            return InventoryResult(False, "inventory full")
        dst_client_bag = _resolve_client_bag_for_internal(state, int(destination[0]))
        if dst_client_bag is None:
            return InventoryResult(False, "destination bag not found")
        return swap_character_item(session, int(src_bag), int(src_slot), int(dst_client_bag), int(destination[1]))

    dst_internal_bag = _resolve_internal_bag(state, int(dst_bag))
    if dst_internal_bag is None:
        return InventoryResult(False, "destination bag not found")

    container = _bag_item_for_container(state, dst_internal_bag)
    if not container:
        return InventoryResult(False, "destination bag not found")

    for container_slot in range(int(container.container_slots)):
        if state.get(dst_internal_bag, container_slot) is not None:
            continue
        if not _slot_allows_item(state, item, dst_internal_bag, container_slot):
            continue
        return swap_character_item(session, int(src_bag), int(src_slot), int(dst_bag), container_slot)

    return InventoryResult(False, "destination bag full")


def move_item_to_root_slot_by_guid(session, item_guid: int, dst_slot: int) -> InventoryResult:
    state = getattr(session, "inventory_state", None)
    if not isinstance(state, InventoryState):
        state = refresh_session_inventory(session)

    item = state.items_by_guid.get(int(item_guid))
    if not item:
        return InventoryResult(False, "source item not found")

    src_client_bag = _resolve_client_bag_for_internal(state, int(item.bag))
    if src_client_bag is None:
        return InventoryResult(False, "source bag not found")

    return swap_character_item(session, int(src_client_bag), int(item.slot), 0, int(dst_slot))
