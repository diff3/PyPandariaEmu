import importlib
import struct
import sys
import types
from types import SimpleNamespace

from server.modules.interpretation.utils import dsl_decode


def _import_inventory_handlers():
    stub_modules = {
        "server.modules.database.DatabaseConnection": {
            "DatabaseConnection": type("DatabaseConnection", (), {}),
        },
        "server.modules.game.inventory": {
            "auto_equip_item": lambda *args, **kwargs: None,
            "auto_store_item": lambda *args, **kwargs: None,
            "destroy_character_item": lambda *args, **kwargs: None,
            "move_item_to_root_slot_by_guid": lambda *args, **kwargs: None,
            "swap_character_item": lambda *args, **kwargs: None,
        },
        "server.modules.handlers.world.chat.codec": {
            "encode_skyfire_messagechat_system_payload": lambda message: message.encode(),
        },
        "server.modules.handlers.world.state.runtime": {
            "resync_player_appearance": lambda session: None,
            "build_self_player_appearance_responses": lambda session: [],
        },
    }

    for module_name, attrs in stub_modules.items():
        module = types.ModuleType(module_name)
        for attr_name, value in attrs.items():
            setattr(module, attr_name, value)
        sys.modules[module_name] = module

    sys.modules.pop("server.modules.handlers.world.opcodes.inventory", None)
    module = importlib.import_module("server.modules.handlers.world.opcodes.inventory")
    sys.modules.pop("server.modules.game.inventory", None)
    return module


inventory_handlers = _import_inventory_handlers()


def _ok_result(message="ok"):
    return SimpleNamespace(ok=True, message=message)


def test_autoequip_item_dsl_decodes_runtime_layout():
    decoded = dsl_decode("CMSG_AUTOEQUIP_ITEM", bytes.fromhex("0114400114"), silent=True)

    assert decoded["src_slot"] == 1
    assert decoded["src_bag"] == 20


def test_autoequip_item_uses_decoded_fields(monkeypatch):
    calls = []
    monkeypatch.setattr(
        inventory_handlers,
        "auto_equip_item",
        lambda session, src_bag, src_slot: (
            calls.append((src_bag, src_slot)) or _ok_result("item equipped")
        ),
    )
    monkeypatch.setattr(inventory_handlers, "build_inventory_delta_responses", lambda session, result: [])

    ctx = SimpleNamespace(
        name="CMSG_AUTOEQUIP_ITEM",
        payload=bytes.fromhex("0000"),
        decoded={"src_slot": 1, "src_bag": 20},
    )

    status, responses = inventory_handlers.handle_autoequip_item(object(), ctx)

    assert status == 0
    assert responses is None
    assert calls == [(20, 1)]


def test_autoequip_item_resyncs_peer_appearance_when_equipment_changes(monkeypatch):
    calls = []
    resync_calls = []
    result = SimpleNamespace(
        ok=True,
        message="item equipped",
        changed_positions=((0, 2), (0, 24)),
    )
    monkeypatch.setattr(
        inventory_handlers,
        "auto_equip_item",
        lambda session, src_bag, src_slot: (
            calls.append((src_bag, src_slot)) or result
        ),
    )
    monkeypatch.setattr(inventory_handlers, "build_inventory_delta_responses", lambda session, current_result: [])
    monkeypatch.setattr(
        inventory_handlers,
        "resync_player_appearance",
        lambda session: resync_calls.append(session),
    )

    session = object()
    ctx = SimpleNamespace(
        name="CMSG_AUTOEQUIP_ITEM",
        payload=bytes.fromhex("0000"),
        decoded={"src_slot": 24, "src_bag": 255},
    )

    status, responses = inventory_handlers.handle_autoequip_item(session, ctx)

    assert status == 0
    assert responses is None
    assert calls == [(255, 24)]
    assert resync_calls == [session]


def test_autoequip_item_slot_dsl_decodes_slot_and_packed_guid():
    decoded = dsl_decode("CMSG_AUTOEQUIP_ITEM_SLOT", bytes([15, 1, 0x34]), silent=True)

    assert decoded["slot"] == 15
    assert decoded["guid"] == 0x34


def test_autoequip_item_slot_uses_decoded_fields(monkeypatch):
    calls = []
    monkeypatch.setattr(
        inventory_handlers,
        "move_item_to_root_slot_by_guid",
        lambda session, item_guid, slot: (
            calls.append((item_guid, slot)) or _ok_result("item equipped")
        ),
    )
    monkeypatch.setattr(inventory_handlers, "build_inventory_delta_responses", lambda session, result: [])

    ctx = SimpleNamespace(
        name="CMSG_AUTOEQUIP_ITEM_SLOT",
        payload=bytes([0]),
        decoded={"slot": 15, "guid": 0x12345678},
    )

    status, responses = inventory_handlers.handle_autoequip_item_slot(object(), ctx)

    assert status == 0
    assert responses is None
    assert calls == [(0x12345678, 15)]


def test_swap_inv_item_dsl_decodes_slots():
    decoded = dsl_decode("CMSG_SWAP_INV_ITEM", bytes([19, 23]), silent=True)

    assert decoded["src_slot"] == 19
    assert decoded["dst_slot"] == 23


def test_swap_inv_item_uses_decoded_fields(monkeypatch):
    calls = []
    monkeypatch.setattr(
        inventory_handlers,
        "swap_character_item",
        lambda session, src_bag, src_slot, dst_bag, dst_slot: (
            calls.append((src_bag, src_slot, dst_bag, dst_slot)) or _ok_result("item moved")
        ),
    )
    monkeypatch.setattr(inventory_handlers, "build_inventory_delta_responses", lambda session, result: [])

    ctx = SimpleNamespace(
        name="CMSG_SWAP_INV_ITEM",
        payload=b"\x00\x00",
        decoded={"src_slot": 19, "dst_slot": 23},
    )

    status, responses = inventory_handlers.handle_swap_inv_item(object(), ctx)

    assert status == 0
    assert responses is None
    assert calls == [(0, 19, 0, 23)]


def test_swap_item_prefers_decoded_fields_over_raw(monkeypatch):
    calls = []
    monkeypatch.setattr(
        inventory_handlers,
        "swap_character_item",
        lambda session, src_bag, src_slot, dst_bag, dst_slot: (
            calls.append((src_bag, src_slot, dst_bag, dst_slot)) or _ok_result("item moved")
        ),
    )
    monkeypatch.setattr(inventory_handlers, "build_inventory_delta_responses", lambda session, result: [])

    ctx = SimpleNamespace(
        name="CMSG_SWAP_ITEM",
        payload=b"\x00\x00\x00\x00",
        decoded={"src_bag": 0, "src_slot": 19, "dst_bag": 0, "dst_slot": 23},
    )

    status, responses = inventory_handlers.handle_swap_item(object(), ctx)

    assert status == 0
    assert responses is None
    assert calls == [(0, 19, 0, 23)]


def test_swap_item_decodes_mop_bitpacked_payload_when_decoded_missing(monkeypatch):
    calls = []
    monkeypatch.setattr(
        inventory_handlers,
        "swap_character_item",
        lambda session, src_bag, src_slot, dst_bag, dst_slot: (
            calls.append((src_bag, src_slot, dst_bag, dst_slot)) or _ok_result("item moved")
        ),
    )
    monkeypatch.setattr(inventory_handlers, "build_inventory_delta_responses", lambda session, result: [])

    ctx = SimpleNamespace(
        name="CMSG_SWAP_ITEM",
        payload=bytes.fromhex("0113FF1880FF181301"),
        decoded={},
    )

    status, responses = inventory_handlers.handle_swap_item(object(), ctx)

    assert status == 0
    assert responses is None
    assert calls == [(19, 1, 255, 24)]


def test_autostore_bag_item_prefers_decoded_fields_over_raw(monkeypatch):
    calls = []
    monkeypatch.setattr(
        inventory_handlers,
        "auto_store_item",
        lambda session, src_bag, src_slot, dst_bag: (
            calls.append((src_bag, src_slot, dst_bag)) or _ok_result("item moved")
        ),
    )
    monkeypatch.setattr(inventory_handlers, "build_inventory_delta_responses", lambda session, result: [])

    ctx = SimpleNamespace(
        name="CMSG_AUTOSTORE_BAG_ITEM",
        payload=b"\x00\x00\x00",
        decoded={"src_bag": 0, "src_slot": 19, "dst_bag": 0},
    )

    status, responses = inventory_handlers.handle_autostore_bag_item(object(), ctx)

    assert status == 0
    assert responses is None
    assert calls == [(0, 19, 0)]


def test_failed_swap_returns_only_inventory_change_failure(monkeypatch):
    monkeypatch.setattr(
        inventory_handlers,
        "swap_character_item",
        lambda session, src_bag, src_slot, dst_bag, dst_slot: SimpleNamespace(
            ok=False,
            message="cannot move non-empty equipped bag there yet",
        ),
    )
    monkeypatch.setattr(
        inventory_handlers,
        "_inventory_item_world_guid",
        lambda state, bag, slot: 0x0000800000400000 if (bag, slot) == (0, 20) else 0,
    )

    ctx = SimpleNamespace(
        name="CMSG_SWAP_ITEM",
        payload=b"\x00\x00\x00\x00",
        decoded={"src_bag": 0, "src_slot": 20, "dst_bag": 255, "dst_slot": 255},
    )

    session = SimpleNamespace(inventory_state=object())
    status, responses = inventory_handlers.handle_swap_item(session, ctx)

    assert status == 0
    assert responses == [("SMSG_INVENTORY_CHANGE_FAILURE", bytes.fromhex("000A0081411F"))]


def test_open_item_prefers_decoded_fields(monkeypatch):
    bag_item = SimpleNamespace(item_guid=1000, is_bag=True)
    session = SimpleNamespace(inventory_state=SimpleNamespace(get=lambda bag, slot: bag_item if (bag, slot) == (0, 19) else None))
    monkeypatch.setattr(
        inventory_handlers,
        "build_container_open_responses",
        lambda current_session, item: [("SMSG_UPDATE_OBJECT", b"open-bag")],
    )

    ctx = SimpleNamespace(
        name="CMSG_OPEN_ITEM",
        payload=b"\x00\x00",
        decoded={"bag": 255, "slot": 19},
    )

    status, responses = inventory_handlers.handle_open_item(session, ctx)

    assert status == 0
    assert responses == [("SMSG_UPDATE_OBJECT", b"open-bag")]


def test_destroy_item_decodes_mop_layout_count_slot_bag(monkeypatch):
    calls = []
    monkeypatch.setattr(
        inventory_handlers,
        "destroy_character_item",
        lambda session, bag, slot, count: (
            calls.append((bag, slot, count)) or _ok_result("item destroyed")
        ),
    )
    monkeypatch.setattr(inventory_handlers, "build_inventory_delta_responses", lambda session, result: [])

    ctx = SimpleNamespace(
        name="CMSG_DESTROY_ITEM",
        payload=struct.pack("<IBB", 0, 24, 255),
        decoded={},
    )

    status, responses = inventory_handlers.handle_destroy_item(object(), ctx)

    assert status == 0
    assert responses is None
    assert calls == [(255, 24, 0)]


def test_inventory_change_failure_matches_skyfire548_nonempty_bag_sniff():
    payload = inventory_handlers.build_inventory_change_failure_payload(
        error_code=31,
        item_guid=0x0000800000400000,
        item_guid2=0,
    )

    assert payload == bytes.fromhex("000A0081411F")
