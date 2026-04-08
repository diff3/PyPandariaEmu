import sys
import types


sqlalchemy_module = types.ModuleType("sqlalchemy")
sqlalchemy_module.func = types.SimpleNamespace(max=lambda *args, **kwargs: None)
sys.modules.setdefault("sqlalchemy", sqlalchemy_module)

database_module = types.ModuleType("server.modules.database.DatabaseConnection")


class _DatabaseConnection:
    pass


database_module.DatabaseConnection = _DatabaseConnection
sys.modules.setdefault("server.modules.database.DatabaseConnection", database_module)

models_module = types.ModuleType("server.modules.database.CharactersModel")
models_module.CharacterInventory = type("CharacterInventory", (), {})
models_module.Characters = type("Characters", (), {})
models_module.ItemInstance = type("ItemInstance", (), {})
sys.modules.setdefault("server.modules.database.CharactersModel", models_module)

from server.modules.game.inventory import (
    InventoryItem,
    InventoryState,
    ItemTemplateInfo,
    auto_store_item,
    swap_character_item,
)


class _FakeSession:
    def __init__(self, state: InventoryState):
        self.char_guid = 7
        self.inventory_state = state
        self.inventory_items = dict(state.items_by_pos)
        self.inventory_by_guid = dict(state.items_by_guid)
        self.inventory_dirty = False
        self.equipment_cache_raw = []
        self._character_row = None


def _template(*, entry: int, display_id: int, inventory_type: int, container_slots: int = 0, bag_family: int = 0):
    return ItemTemplateInfo(
        entry=entry,
        display_id=display_id,
        inventory_type=inventory_type,
        stackable=1,
        buy_count=1,
        bag_family=bag_family,
        item_class=1 if container_slots > 0 else 2,
        subclass=0,
        container_slots=container_slots,
    )


def _item(*, guid: int, bag: int, slot: int, template: ItemTemplateInfo, count: int = 1):
    return InventoryItem(
        item_guid=guid,
        owner_guid=7,
        bag=bag,
        slot=slot,
        count=count,
        template=template,
    )


def test_swap_full_equipped_bag_with_empty_backpack_bag_is_rejected():
    bag_small = _template(entry=100, display_id=2000, inventory_type=18, container_slots=6)
    bag_large = _template(entry=101, display_id=2001, inventory_type=18, container_slots=10)
    reagent = _template(entry=200, display_id=3000, inventory_type=0)

    equipped_bag = _item(guid=1000, bag=0, slot=19, template=bag_small)
    backpack_bag = _item(guid=1001, bag=0, slot=23, template=bag_large)
    inner_one = _item(guid=2000, bag=1000, slot=0, template=reagent, count=4)
    inner_two = _item(guid=2001, bag=1000, slot=4, template=reagent, count=7)

    state = InventoryState()
    for item in (equipped_bag, backpack_bag, inner_one, inner_two):
        state.put(item)
    session = _FakeSession(state)

    result = swap_character_item(session, 0, 23, 0, 19)

    assert result.ok is False
    assert "non-empty equipped bag" in result.message
    assert state.get(0, 19).item_guid == 1000
    assert state.get(0, 23).item_guid == 1001
    assert state.get(1000, 0).item_guid == 2000
    assert state.get(1000, 4).item_guid == 2001


def test_swap_empty_equipped_bag_to_backpack_slot_succeeds():
    bag_template = _template(entry=100, display_id=2000, inventory_type=18, container_slots=6)

    equipped_bag = _item(guid=1000, bag=0, slot=19, template=bag_template)

    state = InventoryState()
    state.put(equipped_bag)
    session = _FakeSession(state)

    result = swap_character_item(session, 0, 19, 0, 23)

    assert result.ok is True
    assert state.get(0, 19) is None
    assert state.get(0, 23).item_guid == 1000


def test_swap_non_empty_bag_between_bag_slots_succeeds():
    bag_a = _template(entry=100, display_id=2000, inventory_type=18, container_slots=6)
    bag_b = _template(entry=101, display_id=2001, inventory_type=18, container_slots=8)
    reagent = _template(entry=200, display_id=3000, inventory_type=0)

    first_bag = _item(guid=1000, bag=0, slot=19, template=bag_a)
    second_bag = _item(guid=1001, bag=0, slot=20, template=bag_b)
    inner = _item(guid=2000, bag=1000, slot=0, template=reagent, count=4)

    state = InventoryState()
    for item in (first_bag, second_bag, inner):
        state.put(item)
    session = _FakeSession(state)

    result = swap_character_item(session, 0, 19, 0, 20)

    assert result.ok is True
    assert state.get(0, 19).item_guid == 1001
    assert state.get(0, 20).item_guid == 1000
    assert state.get(1000, 0).item_guid == 2000


def test_auto_store_item_places_item_into_equipped_bag():
    bag_template = _template(entry=100, display_id=2000, inventory_type=18, container_slots=6)
    item_template = _template(entry=201, display_id=3100, inventory_type=0)

    equipped_bag = _item(guid=1000, bag=0, slot=19, template=bag_template)
    backpack_item = _item(guid=2000, bag=0, slot=23, template=item_template)

    state = InventoryState()
    for item in (equipped_bag, backpack_item):
        state.put(item)
    session = _FakeSession(state)

    result = auto_store_item(session, 0, 23, 19)

    assert result.ok is True
    assert state.get(0, 23) is None
    assert state.get(1000, 0).item_guid == 2000


def test_auto_store_item_treats_client_bag_255_as_backpack():
    bag_template = _template(entry=100, display_id=2000, inventory_type=18, container_slots=6)
    bag_item = _item(guid=1000, bag=0, slot=19, template=bag_template)

    state = InventoryState()
    state.put(bag_item)
    session = _FakeSession(state)

    result = auto_store_item(session, 0, 19, 255)

    assert result.ok is True
    assert state.get(0, 19) is None
    assert state.get(0, 23).item_guid == 1000
