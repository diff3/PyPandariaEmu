import sys
import types

from server.modules.interpretation.utils import dsl_decode


database_module = types.ModuleType("server.modules.database.DatabaseConnection")


class _DatabaseConnection:
    pass


database_module.DatabaseConnection = _DatabaseConnection
sys.modules.setdefault("server.modules.database.DatabaseConnection", database_module)

from server.modules.handlers.world import inventory_sync


class _FakeSession:
    def __init__(self):
        self.char_guid = 7
        self.map_id = 1
        self.equipment_cache_raw = [0] * (23 * 2)
        self.inventory_state = None


class _Template:
    def __init__(self, *, entry: int, display_id: int, inventory_type: int, container_slots: int = 0):
        self.entry = entry
        self.display_id = display_id
        self.inventory_type = inventory_type
        self.container_slots = container_slots
        self.item_class = 1 if container_slots > 0 else 2

    @property
    def is_bag(self) -> bool:
        return self.item_class == 1


class _Item:
    def __init__(self, *, item_guid: int, bag: int, slot: int, count: int, template: _Template):
        self.item_guid = item_guid
        self.bag = bag
        self.slot = slot
        self.count = count
        self.template = template

    @property
    def entry(self) -> int:
        return self.template.entry

    @property
    def is_bag(self) -> bool:
        return self.template.is_bag

    @property
    def container_slots(self) -> int:
        return self.template.container_slots


class _InventoryState:
    def __init__(self):
        self.items_by_pos = {}
        self.items_by_guid = {}

    def get(self, bag: int, slot: int):
        return self.items_by_pos.get((int(bag), int(slot)))

    def put(self, item: _Item) -> None:
        self.items_by_pos[(int(item.bag), int(item.slot))] = item
        self.items_by_guid[int(item.item_guid)] = item


def test_self_visible_item_update_writes_all_equipment_slots():
    session = _FakeSession()
    for slot in range(19):
        session.equipment_cache_raw[slot * 2] = 1000 + slot
        session.equipment_cache_raw[slot * 2 + 1] = 77

    responses = inventory_sync.build_self_visible_item_update_responses(session)

    assert len(responses) == 1
    opcode, payload = responses[0]
    assert opcode == "SMSG_UPDATE_OBJECT"

    decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)
    update = decoded["updates"][0]

    assert update["update_type"] == 0
    assert update["guid"] == 7
    assert update["mask"]["set_bits"] == list(range(921, 959))
    assert update["fields"]["u32"] == [value for slot in range(19) for value in (1000 + slot, 0)]


def test_self_visible_item_update_clears_slots_without_equipment():
    session = _FakeSession()

    responses = inventory_sync.build_self_visible_item_update_responses(session)
    payload = responses[0][1]
    decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)
    update = decoded["updates"][0]

    assert update["fields"]["u32"] == [0] * 38


def test_item_snapshot_uses_bag_guid_as_contained_in_for_bag_contents():
    session = _FakeSession()
    state = _InventoryState()
    session.inventory_state = state

    bag = _Item(
        item_guid=1000,
        bag=0,
        slot=19,
        count=1,
        template=_Template(entry=100, display_id=2000, inventory_type=18, container_slots=6),
    )
    contained = _Item(
        item_guid=2000,
        bag=1000,
        slot=0,
        count=4,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    state.put(bag)
    state.put(contained)

    responses = inventory_sync.build_item_snapshot_responses(session, contained)
    payload = responses[0][1]
    decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)
    update = decoded["updates"][0]

    assert update["mask"]["set_bits"] == [0, 1, 4, 5, 6, 7, 8, 10, 11, 16, 23]
    assert update["fields"]["u32"] == [
        2000,
        1073741824,
        3,
        200,
        0,
        1065353216,
        7,
        1000,
        1073741824,
        4,
        1,
    ]


def test_bag_snapshot_create_includes_container_slot_count():
    session = _FakeSession()
    state = _InventoryState()
    session.inventory_state = state

    bag = _Item(
        item_guid=1000,
        bag=0,
        slot=19,
        count=1,
        template=_Template(entry=100, display_id=2000, inventory_type=18, container_slots=6),
    )
    state.put(bag)

    responses = inventory_sync.build_item_snapshot_responses(session, bag)
    payload = responses[0][1]
    decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)
    update = decoded["updates"][0]

    assert update["update_type"] == 1
    assert update["object_type"] == 2
    assert 141 in update["mask"]["set_bits"]
    assert update["fields"]["u32"][-1] == 6


def test_bag_snapshot_create_includes_contained_item_guids():
    session = _FakeSession()
    state = _InventoryState()
    session.inventory_state = state

    bag = _Item(
        item_guid=1000,
        bag=0,
        slot=19,
        count=1,
        template=_Template(entry=100, display_id=2000, inventory_type=18, container_slots=6),
    )
    contained = _Item(
        item_guid=2000,
        bag=1000,
        slot=0,
        count=4,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    state.put(bag)
    state.put(contained)

    responses = inventory_sync.build_item_snapshot_responses(session, bag)
    payload = responses[0][1]
    decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)
    update = decoded["updates"][0]

    assert 69 in update["mask"]["set_bits"]
    assert 70 in update["mask"]["set_bits"]
    assert 141 in update["mask"]["set_bits"]
