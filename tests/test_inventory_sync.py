import sys
import types
from types import SimpleNamespace

from server.modules.interpretation.utils import dsl_decode


database_module = types.ModuleType("server.modules.database.DatabaseConnection")


class _DatabaseConnection:
    pass


database_module.DatabaseConnection = _DatabaseConnection
sys.modules.setdefault("server.modules.database.DatabaseConnection", database_module)

sys.modules.pop("server.modules.handlers.world.bootstrap.replay", None)
sys.modules.pop("server.modules.handlers.world.inventory_sync", None)

from server.modules.handlers.world import inventory_sync


class _FakeSession:
    def __init__(self):
        self.account_id = 1
        self.account_name = "tester"
        self.realm_id = 1
        self.addons = []
        self.addon_trailing_value = 0
        self.banned_addons = []
        self.player_guid = 7
        self.char_guid = 7
        self.world_guid = 7
        self.map_id = 1
        self.zone = 0
        self.instance_id = 0
        self.x = 0.0
        self.y = 0.0
        self.z = 0.0
        self.orientation = 0.0
        self.server_time = 0
        self.account_data_times = {}
        self.account_data_mask = 0
        self.walk_speed = 2.5
        self.run_speed = 7.0
        self.run_back_speed = 4.5
        self.swim_speed = 4.7
        self.swim_back_speed = 2.5
        self.fly_speed = 7.0
        self.fly_back_speed = 4.5
        self.turn_speed = 3.14
        self.pitch_speed = 3.14
        self.level = 1
        self.class_id = 1
        self.race = 1
        self.gender = 0
        self.money = 0
        self.health = 100
        self.display_power = 0
        self.power_primary = 0
        self.max_power_primary = 0
        self.faction_template = 0
        self.player_bytes = 0
        self.player_bytes2 = 0
        self.player_flags = 0
        self.known_spells = []
        self.action_buttons = []
        self.weather = {}
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
    state = _InventoryState()
    session.inventory_state = state
    for slot in range(19):
        state.put(
            _Item(
                item_guid=10000 + slot,
                bag=0,
                slot=slot,
                count=1,
                template=_Template(entry=1000 + slot, display_id=2000 + slot, inventory_type=slot + 1),
            )
        )

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


def test_self_visible_item_update_keeps_slots_when_morphed():
    session = _FakeSession()
    session.is_morphed = True
    state = _InventoryState()
    state.put(
        _Item(
            item_guid=1000,
            bag=0,
            slot=0,
            count=1,
            template=_Template(entry=1234, display_id=9999, inventory_type=1),
        )
    )
    session.inventory_state = state

    responses = inventory_sync.build_self_visible_item_update_responses(session)
    payload = responses[0][1]
    decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)
    update = decoded["updates"][0]

    assert update["fields"]["u32"][:2] == [1234, 0]


def test_self_visible_item_update_uses_equipment_slots_not_raw_cache_order():
    session = _FakeSession()
    session.equipment_cache_raw[0] = 7777  # legacy fallback value that should be ignored
    state = _InventoryState()
    state.put(
        _Item(
            item_guid=2001,
            bag=0,
            slot=1,
            count=1,
            template=_Template(entry=4321, display_id=8765, inventory_type=2),
        )
    )
    session.inventory_state = state

    responses = inventory_sync.build_self_visible_item_update_responses(session)
    payload = responses[0][1]
    decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)
    update = decoded["updates"][0]

    assert update["fields"]["u32"][0:4] == [0, 0, 4321, 0]


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
    assert 71 not in update["mask"]["set_bits"]
    assert 72 not in update["mask"]["set_bits"]


def test_item_release_omits_contained_in_field():
    session = _FakeSession()
    state = _InventoryState()
    session.inventory_state = state

    contained = _Item(
        item_guid=2000,
        bag=1000,
        slot=0,
        count=4,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    state.put(contained)

    responses = inventory_sync.build_item_release_responses(session, contained)
    payload = responses[0][1]
    decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)
    update = decoded["updates"][0]

    assert update["mask"]["set_bits"] == [0, 1, 4, 5, 6, 7, 8, 16, 23]


def test_bag_release_keeps_only_used_container_slot_fields():
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

    responses = inventory_sync.build_item_release_responses(session, bag)
    payload = responses[0][1]
    decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)
    update = decoded["updates"][0]

    assert update["mask"]["set_bits"] == [0, 1, 4, 5, 6, 7, 8, 16, 23, 69, 70, 141]


def test_sync_item_sends_create_then_values_for_known_guid():
    session = _FakeSession()
    state = _InventoryState()
    session.inventory_state = state

    item = _Item(
        item_guid=2000,
        bag=0,
        slot=23,
        count=4,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    state.put(item)

    create_responses = inventory_sync.sync_item(
        session, item, [inventory_sync._ITEM_FIELD_CONTAINED, inventory_sync._ITEM_FIELD_CONTAINED + 1]
    )
    create_update = dsl_decode("SMSG_UPDATE_OBJECT", create_responses[0][1], silent=True)["updates"][0]
    assert create_update["update_type"] == 1

    values_responses = inventory_sync.sync_item(
        session, item, [inventory_sync._ITEM_FIELD_CONTAINED, inventory_sync._ITEM_FIELD_CONTAINED + 1]
    )
    values_update = dsl_decode("SMSG_UPDATE_OBJECT", values_responses[0][1], silent=True)["updates"][0]
    assert values_update["update_type"] == 0
    assert values_update["mask"]["set_bits"] == [10, 11]


def test_inventory_delta_responses_include_container_slot_update_for_bag_insert():
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

    result = SimpleNamespace(
        changed_positions=((0, 23), (1000, 0)),
        removed_item_guids=(),
    )

    responses = inventory_sync.build_inventory_delta_responses(session, result)

    bag_payloads = [
        payload
        for opcode, payload in responses
        if opcode == "SMSG_UPDATE_OBJECT"
        and (dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}).get("updates", [{}])[0].get("guid")
        == inventory_sync._make_item_world_guid(1000)
    ]

    assert bag_payloads
    decoded = dsl_decode("SMSG_UPDATE_OBJECT", bag_payloads[0], silent=True)
    update = decoded["updates"][0]
    assert 69 in update["mask"]["set_bits"]
    assert 70 in update["mask"]["set_bits"]


def test_inventory_delta_responses_include_item_snapshot_for_moved_item():
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

    result = SimpleNamespace(
        changed_positions=((0, 23), (1000, 0)),
        changed_items=(contained,),
        removed_item_guids=(),
    )

    responses = inventory_sync.build_inventory_delta_responses(session, result)

    item_payloads = [
        payload
        for opcode, payload in responses
        if opcode == "SMSG_UPDATE_OBJECT"
        and (dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}).get("updates", [{}])[0].get("guid")
        == inventory_sync._make_item_world_guid(2000)
    ]

    assert item_payloads


def test_inventory_delta_responses_include_release_and_store_item_updates_for_simple_move():
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
    moved = _Item(
        item_guid=2000,
        bag=1000,
        slot=0,
        count=4,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    state.put(bag)
    state.put(moved)
    session.known_inventory_guids = {
        inventory_sync._make_item_world_guid(1000),
        inventory_sync._make_item_world_guid(2000),
    }

    moved.bag = 0
    moved.slot = 23
    state.items_by_pos.pop((1000, 0))
    state.put(moved)

    result = SimpleNamespace(
        changed_positions=((1000, 0), (0, 23)),
        changed_items=(moved,),
        released_items=(
            _Item(
                item_guid=2000,
                bag=1000,
                slot=0,
                count=4,
                template=_Template(entry=200, display_id=3000, inventory_type=0),
            ),
        ),
        removed_item_guids=(),
    )

    responses = inventory_sync.build_inventory_delta_responses(session, result)

    item_updates = [
        dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)["updates"][0]
        for opcode, payload in responses
        if opcode == "SMSG_UPDATE_OBJECT"
        and (dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}).get("updates", [{}])[0].get("guid")
        == inventory_sync._make_item_world_guid(2000)
    ]

    assert any(
        update["update_type"] == 0 and update["mask"]["set_bits"] == [10, 11]
        for update in item_updates
    )


def test_known_container_delta_updates_only_changed_slots():
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
        slot=2,
        count=1,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    state.put(bag)
    state.put(contained)
    session.known_inventory_guids = {inventory_sync._make_item_world_guid(1000)}

    responses = inventory_sync.sync_container(session, bag, [2])
    update = dsl_decode("SMSG_UPDATE_OBJECT", responses[0][1], silent=True)["updates"][0]

    assert update["update_type"] == 0
    assert update["mask"]["set_bits"] == [73, 74]


def test_inventory_delta_backpack_to_bag_updates_root_slot_container_slot_and_contained_field():
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
    moved = _Item(
        item_guid=2000,
        bag=1000,
        slot=1,
        count=4,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    state.put(bag)
    state.put(moved)
    session.known_inventory_guids = {
        inventory_sync._make_item_world_guid(1000),
        inventory_sync._make_item_world_guid(2000),
    }

    released = _Item(
        item_guid=2000,
        bag=0,
        slot=23,
        count=4,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    result = SimpleNamespace(
        changed_positions=((0, 23), (1000, 1)),
        changed_items=(moved,),
        released_items=(released,),
        removed_item_guids=(),
    )

    responses = inventory_sync.build_inventory_delta_responses(session, result)
    updates = []
    for opcode, payload in responses:
        if opcode != "SMSG_UPDATE_OBJECT":
            continue
        decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}
        updates.extend(decoded.get("updates", []))
    player_updates = [u for u in updates if u.get("guid") == session.char_guid]
    bag_updates = [u for u in updates if u.get("guid") == inventory_sync._make_item_world_guid(1000)]
    item_updates = [u for u in updates if u.get("guid") == inventory_sync._make_item_world_guid(2000)]

    root_field = inventory_sync._inventory_slot_field_index(0, 23)
    assert any(update["mask"]["set_bits"] == [root_field, root_field + 1] for update in player_updates)
    assert any(update["mask"]["set_bits"] == [71, 72] for update in bag_updates)
    assert any(update["mask"]["set_bits"] == [10, 11] for update in item_updates)


def test_inventory_delta_bag_to_backpack_updates_container_slot_root_slot_and_contained_field():
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
    moved = _Item(
        item_guid=2000,
        bag=0,
        slot=23,
        count=4,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    state.put(bag)
    state.put(moved)
    session.known_inventory_guids = {
        inventory_sync._make_item_world_guid(1000),
        inventory_sync._make_item_world_guid(2000),
    }

    released = _Item(
        item_guid=2000,
        bag=1000,
        slot=0,
        count=4,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    result = SimpleNamespace(
        changed_positions=((1000, 0), (0, 23)),
        changed_items=(moved,),
        released_items=(released,),
        removed_item_guids=(),
    )

    responses = inventory_sync.build_inventory_delta_responses(session, result)
    updates = []
    for opcode, payload in responses:
        if opcode != "SMSG_UPDATE_OBJECT":
            continue
        decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}
        updates.extend(decoded.get("updates", []))
    player_updates = [u for u in updates if u.get("guid") == session.char_guid]
    bag_updates = [u for u in updates if u.get("guid") == inventory_sync._make_item_world_guid(1000)]
    item_updates = [u for u in updates if u.get("guid") == inventory_sync._make_item_world_guid(2000)]

    root_field = inventory_sync._inventory_slot_field_index(0, 23)
    assert any(update["mask"]["set_bits"] == [69, 70] for update in bag_updates)
    assert any(update["mask"]["set_bits"] == [root_field, root_field + 1] for update in player_updates)
    assert any(update["mask"]["set_bits"] == [10, 11] for update in item_updates)


def test_inventory_delta_swap_within_same_container_updates_only_changed_slots():
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
    item_a = _Item(
        item_guid=2000,
        bag=1000,
        slot=0,
        count=1,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    item_b = _Item(
        item_guid=3000,
        bag=1000,
        slot=1,
        count=1,
        template=_Template(entry=300, display_id=4000, inventory_type=0),
    )
    state.put(bag)
    state.put(item_a)
    state.put(item_b)
    session.known_inventory_guids = {
        inventory_sync._make_item_world_guid(1000),
        inventory_sync._make_item_world_guid(2000),
        inventory_sync._make_item_world_guid(3000),
    }

    item_a.slot = 1
    item_b.slot = 0
    state.items_by_pos[(1000, 0)] = item_b
    state.items_by_pos[(1000, 1)] = item_a
    result = SimpleNamespace(
        changed_positions=((1000, 0), (1000, 1)),
        changed_items=(item_a, item_b),
        released_items=(),
        removed_item_guids=(),
    )

    responses = inventory_sync.build_inventory_delta_responses(session, result)
    updates = []
    for opcode, payload in responses:
        if opcode != "SMSG_UPDATE_OBJECT":
            continue
        decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}
        updates.extend(decoded.get("updates", []))

    bag_updates = [u for u in updates if u.get("guid") == inventory_sync._make_item_world_guid(1000)]
    item_updates = [
        u
        for u in updates
        if u.get("guid") in {
            inventory_sync._make_item_world_guid(2000),
            inventory_sync._make_item_world_guid(3000),
        }
    ]

    assert any(update["mask"]["set_bits"] == [69, 70, 71, 72] for update in bag_updates)
    assert not item_updates


def test_inventory_delta_swap_between_bags_updates_both_containers_and_item_links():
    session = _FakeSession()
    state = _InventoryState()
    session.inventory_state = state

    bag_a = _Item(
        item_guid=1000,
        bag=0,
        slot=19,
        count=1,
        template=_Template(entry=100, display_id=2000, inventory_type=18, container_slots=6),
    )
    bag_b = _Item(
        item_guid=1001,
        bag=0,
        slot=20,
        count=1,
        template=_Template(entry=101, display_id=2001, inventory_type=18, container_slots=6),
    )
    item_a = _Item(
        item_guid=2000,
        bag=1001,
        slot=1,
        count=1,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    item_b = _Item(
        item_guid=3000,
        bag=1000,
        slot=0,
        count=1,
        template=_Template(entry=300, display_id=4000, inventory_type=0),
    )
    state.put(bag_a)
    state.put(bag_b)
    state.put(item_a)
    state.put(item_b)
    session.known_inventory_guids = {
        inventory_sync._make_item_world_guid(1000),
        inventory_sync._make_item_world_guid(1001),
        inventory_sync._make_item_world_guid(2000),
        inventory_sync._make_item_world_guid(3000),
    }
    result = SimpleNamespace(
        changed_positions=((1000, 0), (1001, 1)),
        changed_items=(item_a, item_b),
        released_items=(),
        removed_item_guids=(),
    )

    responses = inventory_sync.build_inventory_delta_responses(session, result)
    updates = []
    for opcode, payload in responses:
        if opcode != "SMSG_UPDATE_OBJECT":
            continue
        decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}
        updates.extend(decoded.get("updates", []))

    assert any(
        update.get("guid") == inventory_sync._make_item_world_guid(1000)
        and update["mask"]["set_bits"] == [69, 70]
        and update["fields"]["u32"] == [
            int(inventory_sync._make_item_world_guid(3000) & 0xFFFFFFFF),
            int((inventory_sync._make_item_world_guid(3000) >> 32) & 0xFFFFFFFF),
        ]
        for update in updates
    )
    assert any(
        update.get("guid") == inventory_sync._make_item_world_guid(1001)
        and update["mask"]["set_bits"] == [71, 72]
        and update["fields"]["u32"] == [
            int(inventory_sync._make_item_world_guid(2000) & 0xFFFFFFFF),
            int((inventory_sync._make_item_world_guid(2000) >> 32) & 0xFFFFFFFF),
        ]
        for update in updates
    )
    assert any(
        update.get("guid") == inventory_sync._make_item_world_guid(2000)
        and update["mask"]["set_bits"] == [10, 11]
        and update["fields"]["u32"] == [
            int(inventory_sync._make_item_world_guid(1001) & 0xFFFFFFFF),
            int((inventory_sync._make_item_world_guid(1001) >> 32) & 0xFFFFFFFF),
        ]
        for update in updates
    )
    assert any(
        update.get("guid") == inventory_sync._make_item_world_guid(3000)
        and update["mask"]["set_bits"] == [10, 11]
        and update["fields"]["u32"] == [
            int(inventory_sync._make_item_world_guid(1000) & 0xFFFFFFFF),
            int((inventory_sync._make_item_world_guid(1000) >> 32) & 0xFFFFFFFF),
        ]
        for update in updates
    )


def test_sync_item_known_stack_count_change_only_resends_stack_field():
    session = _FakeSession()
    state = _InventoryState()
    session.inventory_state = state

    item = _Item(
        item_guid=2000,
        bag=0,
        slot=23,
        count=4,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    state.put(item)
    session.known_inventory_guids = {inventory_sync._make_item_world_guid(2000)}

    responses = inventory_sync.sync_item(session, item, [inventory_sync._ITEM_FIELD_STACK_COUNT])
    update = dsl_decode("SMSG_UPDATE_OBJECT", responses[0][1], silent=True)["updates"][0]

    assert update["update_type"] == 0
    assert update["mask"]["set_bits"] == [16]


def test_inventory_delta_equip_known_item_uses_slot_updates_and_values_only():
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
    moved = _Item(
        item_guid=2000,
        bag=0,
        slot=5,
        count=1,
        template=_Template(entry=200, display_id=3000, inventory_type=13),
    )
    state.put(bag)
    state.put(moved)
    session.known_inventory_guids = {
        inventory_sync._make_item_world_guid(1000),
        inventory_sync._make_item_world_guid(2000),
    }
    released = _Item(
        item_guid=2000,
        bag=1000,
        slot=0,
        count=1,
        template=_Template(entry=200, display_id=3000, inventory_type=13),
    )
    result = SimpleNamespace(
        changed_positions=((1000, 0), (0, 5)),
        changed_items=(moved,),
        released_items=(released,),
        removed_item_guids=(),
    )

    responses = inventory_sync.build_inventory_delta_responses(session, result)
    assert len([opcode for opcode, _payload in responses if opcode == "SMSG_UPDATE_OBJECT"]) >= 1
    updates = []
    for opcode, payload in responses:
        if opcode != "SMSG_UPDATE_OBJECT":
            continue
        decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}
        updates.extend(decoded.get("updates", []))
    item_updates = [u for u in updates if u.get("guid") == inventory_sync._make_item_world_guid(2000)]
    assert all(update["update_type"] == 0 for update in item_updates)
    assert any(update["mask"]["set_bits"] == [8, 9, 10, 11] for update in item_updates)
    equip_field = inventory_sync._inventory_slot_field_index(0, 5)
    visible_field = inventory_sync._PLAYER_FIELD_VISIBLE_ITEMS + (5 * 2)
    player_bits = [visible_field, visible_field + 1, equip_field, equip_field + 1]
    assert any(update["mask"]["set_bits"] == player_bits for update in updates if update.get("guid") == 7)
    relevant = [
        update for update in updates
        if (
            (update.get("guid") == inventory_sync._make_item_world_guid(1000) and update["mask"]["set_bits"] == [69, 70])
            or (update.get("guid") == inventory_sync._make_item_world_guid(2000) and update["mask"]["set_bits"] == [8, 9, 10, 11])
            or (update.get("guid") == 7 and update["mask"]["set_bits"] == player_bits)
        )
    ]
    assert [(update.get("guid"), update["mask"]["set_bits"]) for update in relevant[:3]] == [
        (inventory_sync._make_item_world_guid(1000), [69, 70]),
        (inventory_sync._make_item_world_guid(2000), [8, 9, 10, 11]),
        (7, player_bits),
    ]


def test_inventory_delta_unequip_known_item_clears_equip_slot_and_sets_destination_slot():
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
    moved = _Item(
        item_guid=2000,
        bag=1000,
        slot=1,
        count=1,
        template=_Template(entry=200, display_id=3000, inventory_type=13),
    )
    state.put(bag)
    state.put(moved)
    session.known_inventory_guids = {
        inventory_sync._make_item_world_guid(1000),
        inventory_sync._make_item_world_guid(2000),
    }
    released = _Item(
        item_guid=2000,
        bag=0,
        slot=5,
        count=1,
        template=_Template(entry=200, display_id=3000, inventory_type=13),
    )
    result = SimpleNamespace(
        changed_positions=((0, 5), (1000, 1)),
        changed_items=(moved,),
        released_items=(released,),
        removed_item_guids=(),
    )

    responses = inventory_sync.build_inventory_delta_responses(session, result)
    assert len([opcode for opcode, _payload in responses if opcode == "SMSG_UPDATE_OBJECT"]) == 1
    updates = []
    for opcode, payload in responses:
        if opcode != "SMSG_UPDATE_OBJECT":
            continue
        decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}
        updates.extend(decoded.get("updates", []))
    equip_field = inventory_sync._inventory_slot_field_index(0, 5)
    visible_field = inventory_sync._PLAYER_FIELD_VISIBLE_ITEMS + (5 * 2)
    assert any(update["mask"]["set_bits"] == [equip_field, equip_field + 1] for update in updates if update.get("guid") == 7)
    assert any(update["mask"]["set_bits"] == [visible_field, visible_field + 1] for update in updates if update.get("guid") == 7)
    assert any(update["mask"]["set_bits"] == [71, 72] for update in updates if update.get("guid") == inventory_sync._make_item_world_guid(1000))
    assert not any(update["update_type"] == 1 for update in updates if update.get("guid") == inventory_sync._make_item_world_guid(2000))
    relevant = [
        update for update in updates
        if (
            (update.get("guid") == 7 and update["mask"]["set_bits"] == [equip_field, equip_field + 1])
            or (update.get("guid") == 7 and update["mask"]["set_bits"] == [visible_field, visible_field + 1])
            or (update.get("guid") == inventory_sync._make_item_world_guid(2000) and update["mask"]["set_bits"] == [8, 9, 10, 11])
            or (update.get("guid") == inventory_sync._make_item_world_guid(1000) and update["mask"]["set_bits"] == [71, 72])
        )
    ]
    assert [(update.get("guid"), update["mask"]["set_bits"]) for update in relevant[:4]] == [
        (7, [equip_field, equip_field + 1]),
        (7, [visible_field, visible_field + 1]),
        (inventory_sync._make_item_world_guid(2000), [8, 9, 10, 11]),
        (inventory_sync._make_item_world_guid(1000), [71, 72]),
    ]


def test_inventory_delta_equip_swap_updates_in_expected_order():
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
    new_equipped = _Item(
        item_guid=2000,
        bag=0,
        slot=5,
        count=1,
        template=_Template(entry=200, display_id=3000, inventory_type=13),
    )
    old_equipped = _Item(
        item_guid=3000,
        bag=1000,
        slot=0,
        count=1,
        template=_Template(entry=300, display_id=4000, inventory_type=13),
    )
    state.put(bag)
    state.put(new_equipped)
    state.put(old_equipped)
    session.known_inventory_guids = {
        inventory_sync._make_item_world_guid(1000),
        inventory_sync._make_item_world_guid(2000),
        inventory_sync._make_item_world_guid(3000),
    }
    result = SimpleNamespace(
        changed_positions=((1000, 0), (0, 5)),
        changed_items=(new_equipped, old_equipped),
        released_items=(),
        removed_item_guids=(),
    )

    responses = inventory_sync.build_inventory_delta_responses(session, result)
    updates = []
    for opcode, payload in responses:
        if opcode != "SMSG_UPDATE_OBJECT":
            continue
        decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}
        updates.extend(decoded.get("updates", []))

    equip_field = inventory_sync._inventory_slot_field_index(0, 5)
    visible_field = inventory_sync._PLAYER_FIELD_VISIBLE_ITEMS + (5 * 2)
    player_set_bits = [visible_field, visible_field + 1, equip_field, equip_field + 1]
    relevant = [
        update for update in updates
        if (
            (update.get("guid") == 7 and update["mask"]["set_bits"] == [equip_field, equip_field + 1])
            or (update.get("guid") == inventory_sync._make_item_world_guid(3000) and update["mask"]["set_bits"] == [8, 9, 10, 11])
            or (update.get("guid") == inventory_sync._make_item_world_guid(1000) and update["mask"]["set_bits"] == [69, 70])
            or (update.get("guid") == inventory_sync._make_item_world_guid(2000) and update["mask"]["set_bits"] == [8, 9, 10, 11])
            or (update.get("guid") == 7 and update["mask"]["set_bits"] == player_set_bits)
        )
    ]
    assert [(update.get("guid"), update["mask"]["set_bits"]) for update in relevant[:5]] == [
        (7, [equip_field, equip_field + 1]),
        (inventory_sync._make_item_world_guid(3000), [8, 9, 10, 11]),
        (inventory_sync._make_item_world_guid(1000), [69, 70]),
        (inventory_sync._make_item_world_guid(2000), [8, 9, 10, 11]),
        (7, player_set_bits),
    ]


def test_inventory_delta_destroy_known_item_clears_slot_and_removes_guid_from_cache():
    session = _FakeSession()
    state = _InventoryState()
    session.inventory_state = state
    session.known_inventory_guids = {inventory_sync._make_item_world_guid(2000)}

    result = SimpleNamespace(
        changed_positions=((0, 23),),
        changed_items=(),
        released_items=(),
        removed_item_guids=(2000,),
    )

    responses = inventory_sync.build_inventory_delta_responses(session, result)
    assert len([opcode for opcode, _payload in responses if opcode == "SMSG_UPDATE_OBJECT"]) == 2
    updates = []
    decoded_packets = []
    for opcode, payload in responses:
        if opcode != "SMSG_UPDATE_OBJECT":
            continue
        decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}
        decoded_packets.append(decoded)
        updates.extend(decoded.get("updates", []))

    root_field = inventory_sync._inventory_slot_field_index(0, 23)
    assert any(update["guid"] == 7 and update["mask"]["set_bits"] == [root_field, root_field + 1] for update in updates)
    assert any(update["update_type"] == 3 and update.get("out_of_range_count") == 1 for update in updates)
    assert decoded_packets[0]["updates"][0]["update_type"] == 0
    assert decoded_packets[1]["updates"][0]["update_type"] == 3
    assert inventory_sync._make_item_world_guid(2000) not in session.known_inventory_guids
    assert not any(update.get("guid") == inventory_sync._make_item_world_guid(2000) and update["update_type"] == 0 for update in updates)


def test_inventory_delta_destroy_equipped_item_clears_visible_slot_immediately():
    session = _FakeSession()
    state = _InventoryState()
    session.inventory_state = state
    session.known_inventory_guids = {inventory_sync._make_item_world_guid(2000)}
    state.put(
        _Item(
            item_guid=2000,
            bag=0,
            slot=1,
            count=1,
            template=_Template(entry=1234, display_id=5678, inventory_type=1),
        )
    )

    result = SimpleNamespace(
        changed_positions=((0, 1),),
        changed_items=(),
        released_items=(),
        removed_item_guids=(2000,),
    )

    responses = inventory_sync.build_inventory_delta_responses(session, result)

    updates = []
    for opcode, payload in responses:
        if opcode != "SMSG_UPDATE_OBJECT":
            continue
        decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}
        updates.extend(decoded.get("updates", []))

    equip_field = inventory_sync._inventory_slot_field_index(0, 1)
    visible_field = inventory_sync._PLAYER_FIELD_VISIBLE_ITEMS + (1 * 2)
    assert any(update["guid"] == 7 and update["mask"]["set_bits"] == [equip_field, equip_field + 1] for update in updates)
    assert any(update["guid"] == 7 and update["mask"]["set_bits"] == [visible_field, visible_field + 1] for update in updates)
    assert any(update["update_type"] == 3 and update.get("out_of_range_count") == 1 for update in updates)


def test_trigger_inventory_activation_detaches_and_reattaches_equipped_bag_once():
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

    responses = inventory_sync.trigger_inventory_activation(session)
    updates = [
        dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)["updates"][0]
        for opcode, payload in responses
        if opcode == "SMSG_UPDATE_OBJECT"
    ]

    bag_slot_field = inventory_sync._inventory_slot_field_index(0, 19)
    bag_guid = inventory_sync._make_item_world_guid(1000)
    assert session.inventory_activated is True
    assert len(updates) == 2
    assert updates[0]["guid"] == 7
    assert updates[0]["mask"]["set_bits"] == [bag_slot_field, bag_slot_field + 1]
    assert updates[0]["fields"]["u32"] == [0, 0]
    assert updates[1]["guid"] == 7
    assert updates[1]["mask"]["set_bits"] == [bag_slot_field, bag_slot_field + 1]
    assert updates[1]["fields"]["u32"] == [int(bag_guid & 0xFFFFFFFF), int((bag_guid >> 32) & 0xFFFFFFFF)]


def test_trigger_inventory_activation_detaches_and_reattaches_all_equipped_bags():
    session = _FakeSession()
    state = _InventoryState()
    session.inventory_state = state
    for offset, item_guid in enumerate((1000, 1001, 1002)):
        state.put(
            _Item(
                item_guid=item_guid,
                bag=0,
                slot=19 + offset,
                count=1,
                template=_Template(entry=100 + offset, display_id=2000 + offset, inventory_type=18, container_slots=6),
            )
        )

    responses = inventory_sync.trigger_inventory_activation(session)
    updates = [
        dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)["updates"][0]
        for opcode, payload in responses
        if opcode == "SMSG_UPDATE_OBJECT"
    ]

    assert session.inventory_activated is True
    assert len(updates) == 6
    for offset, item_guid in enumerate((1000, 1001, 1002)):
        field_index = inventory_sync._inventory_slot_field_index(0, 19 + offset)
        bag_guid = inventory_sync._make_item_world_guid(item_guid)
        clear_update = updates[offset * 2]
        set_update = updates[(offset * 2) + 1]
        assert clear_update["guid"] == 7
        assert clear_update["mask"]["set_bits"] == [field_index, field_index + 1]
        assert clear_update["fields"]["u32"] == [0, 0]
        assert set_update["guid"] == 7
        assert set_update["mask"]["set_bits"] == [field_index, field_index + 1]
        assert set_update["fields"]["u32"] == [int(bag_guid & 0xFFFFFFFF), int((bag_guid >> 32) & 0xFFFFFFFF)]


def test_trigger_inventory_activation_skips_when_already_active():
    session = _FakeSession()
    session.inventory_activated = True

    responses = inventory_sync.trigger_inventory_activation(session)

    assert responses == []


def test_open_known_bag_does_not_replay_create_packets():
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
        count=1,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    state.put(bag)
    state.put(contained)
    session.known_inventory_guids = {
        inventory_sync._make_item_world_guid(1000),
        inventory_sync._make_item_world_guid(2000),
    }

    responses = inventory_sync.build_container_open_responses(session, bag)

    assert responses == []


def test_open_unknown_bag_creates_bag_and_contained_items_and_updates_cache():
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
        count=1,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    state.put(bag)
    state.put(contained)

    responses = inventory_sync.build_container_open_responses(session, bag)
    updates = [
        dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)["updates"][0]
        for opcode, payload in responses
        if opcode == "SMSG_UPDATE_OBJECT"
    ]

    assert len([u for u in updates if u["update_type"] == 1]) == 2
    assert inventory_sync._make_item_world_guid(1000) in session.known_inventory_guids
    assert inventory_sync._make_item_world_guid(2000) in session.known_inventory_guids


def test_inventory_delta_additem_creates_new_item_and_marks_guid_known():
    session = _FakeSession()
    state = _InventoryState()
    session.inventory_state = state
    item = _Item(
        item_guid=2000,
        bag=0,
        slot=23,
        count=2,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    state.put(item)

    result = SimpleNamespace(
        changed_positions=((0, 23),),
        changed_items=(item,),
        created_item_guids=(2000,),
        released_items=(),
        removed_item_guids=(),
    )

    responses = inventory_sync.build_inventory_delta_responses(session, result)
    updates = [
        dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)["updates"][0]
        for opcode, payload in responses
        if opcode == "SMSG_UPDATE_OBJECT"
    ]

    assert any(update["guid"] == inventory_sync._make_item_world_guid(2000) and update["update_type"] == 1 for update in updates)
    assert inventory_sync._make_item_world_guid(2000) in session.known_inventory_guids


def test_full_resync_clears_stale_known_guids_and_rebuilds_visible_inventory():
    session = _FakeSession()
    state = _InventoryState()
    session.inventory_state = state
    session.inventory_activated = True
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
        count=1,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    backpack_item = _Item(
        item_guid=3000,
        bag=0,
        slot=23,
        count=1,
        template=_Template(entry=300, display_id=4000, inventory_type=0),
    )
    state.put(bag)
    state.put(contained)
    state.put(backpack_item)
    stale_guid = inventory_sync._make_item_world_guid(9999)
    session.known_inventory_guids = {stale_guid}

    responses = inventory_sync.build_login_inventory_sync_responses(session)

    assert responses
    assert stale_guid not in session.known_inventory_guids
    assert session.inventory_activated is False
    assert session.known_inventory_guids == {
        inventory_sync._make_item_world_guid(1000),
        inventory_sync._make_item_world_guid(2000),
        inventory_sync._make_item_world_guid(3000),
    }


def test_inventory_delta_cross_container_move_triggers_activation():
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
    moved = _Item(
        item_guid=2000,
        bag=1000,
        slot=0,
        count=1,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    state.put(bag)
    state.put(moved)
    session.known_inventory_guids = {
        inventory_sync._make_item_world_guid(1000),
        inventory_sync._make_item_world_guid(2000),
    }
    released = _Item(
        item_guid=2000,
        bag=0,
        slot=23,
        count=1,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    result = SimpleNamespace(
        changed_positions=((0, 23), (1000, 0)),
        changed_items=(moved,),
        released_items=(released,),
        removed_item_guids=(),
    )

    responses = inventory_sync.build_inventory_delta_responses(session, result)
    updates = [
        dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)["updates"][0]
        for opcode, payload in responses
        if opcode == "SMSG_UPDATE_OBJECT"
    ]

    bag_slot_field = inventory_sync._inventory_slot_field_index(0, 19)
    player_updates = [
        update for update in updates if update.get("guid") == 7 and update["mask"]["set_bits"] == [bag_slot_field, bag_slot_field + 1]
    ]
    assert session.inventory_activated is True
    assert len(player_updates) == 2
    assert player_updates[0]["fields"]["u32"] == [0, 0]
    bag_guid = inventory_sync._make_item_world_guid(1000)
    assert player_updates[1]["fields"]["u32"] == [int(bag_guid & 0xFFFFFFFF), int((bag_guid >> 32) & 0xFFFFFFFF)]


def test_login_inventory_sync_does_not_duplicate_equipped_bag_create():
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
        count=1,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    backpack_item = _Item(
        item_guid=3000,
        bag=0,
        slot=23,
        count=1,
        template=_Template(entry=300, display_id=4000, inventory_type=0),
    )
    state.put(bag)
    state.put(contained)
    state.put(backpack_item)

    responses = inventory_sync.build_login_inventory_sync_responses(session)

    bag_creates = [
        dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)["updates"][0]
        for opcode, payload in responses
        if opcode == "SMSG_UPDATE_OBJECT"
        and (dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}).get("updates", [{}])[0].get("guid")
        == inventory_sync._make_item_world_guid(1000)
        and (dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}).get("updates", [{}])[0].get("update_type") == 1
    ]

    assert len(bag_creates) == 1
    assert inventory_sync._make_item_world_guid(1000) in session.known_inventory_guids
    assert inventory_sync._make_item_world_guid(2000) in session.known_inventory_guids
    assert inventory_sync._make_item_world_guid(3000) in session.known_inventory_guids


def test_login_inventory_sync_uses_live_equip_player_fields_for_equipped_item():
    session = _FakeSession()
    state = _InventoryState()
    session.inventory_state = state

    equipped = _Item(
        item_guid=1000,
        bag=0,
        slot=15,
        count=1,
        template=_Template(entry=19019, display_id=2000, inventory_type=13),
    )
    state.put(equipped)

    responses = inventory_sync.build_login_inventory_sync_responses(session)

    equip_field = inventory_sync._inventory_slot_field_index(0, 15)
    visible_field = inventory_sync._PLAYER_FIELD_VISIBLE_ITEMS + (15 * 2)
    player_bits = [visible_field, visible_field + 1, equip_field, equip_field + 1]

    player_updates = [
        dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)["updates"][0]
        for opcode, payload in responses
        if opcode == "SMSG_UPDATE_OBJECT"
        and (dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}).get("updates", [{}])[0].get("guid") == 7
    ]

    assert any(update["mask"]["set_bits"] == player_bits for update in player_updates)


def test_equipped_bag_sync_includes_fourth_bag_and_contents():
    session = _FakeSession()
    state = _InventoryState()
    session.inventory_state = state

    bag = _Item(
        item_guid=1000,
        bag=0,
        slot=22,
        count=1,
        template=_Template(entry=100, display_id=2000, inventory_type=18, container_slots=10),
    )
    contained = _Item(
        item_guid=2000,
        bag=1000,
        slot=9,
        count=1,
        template=_Template(entry=200, display_id=3000, inventory_type=0),
    )
    state.put(bag)
    state.put(contained)

    responses = inventory_sync.build_equipped_bag_sync_responses(session)

    assert inventory_sync._make_item_world_guid(1000) in session.known_inventory_guids
    assert inventory_sync._make_item_world_guid(2000) in session.known_inventory_guids
    assert len(responses) == 2


def test_root_inventory_slot_sync_skips_occupied_equipped_bag_slots():
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

    responses = inventory_sync.build_root_inventory_slot_sync_responses(session)

    player_updates = [
        dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)["updates"][0]
        for opcode, payload in responses
        if opcode == "SMSG_UPDATE_OBJECT"
        and (dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}).get("updates", [{}])[0].get("guid") == 7
    ]

    bag_slot_field = inventory_sync._PLAYER_FIELD_INV_SLOTS + (19 * 2)
    assert any(bag_slot_field in update["mask"]["set_bits"] for update in player_updates)


def test_equipped_bag_sync_includes_release_then_create_for_bag():
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

    responses = inventory_sync.build_equipped_bag_sync_responses(session)

    bag_updates = [
        dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)["updates"][0]
        for opcode, payload in responses
        if opcode == "SMSG_UPDATE_OBJECT"
        and (dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True) or {}).get("updates", [{}])[0].get("guid")
        == inventory_sync._make_item_world_guid(1000)
    ]

    assert len(bag_updates) == 1
    assert bag_updates[0]["update_type"] == 1
