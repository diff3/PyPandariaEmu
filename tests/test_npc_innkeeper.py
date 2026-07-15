#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from types import SimpleNamespace

from server.modules.handlers.world.opcodes import npc_interaction


def test_innkeeper_gossip_opens_minimal_menu(monkeypatch):
    monkeypatch.setattr(npc_interaction, "Logger", SimpleNamespace(info=lambda *args, **kwargs: None))
    session = SimpleNamespace(
        npc_flags_by_guid={123: npc_interaction.UNIT_NPC_FLAG_INNKEEPER},
        npc_positions_by_guid={123: (0, 10.0, 10.0, 0.0, 0.0)},
        map_id=0,
        x=10.0,
        y=10.0,
        z=0.0,
    )

    responses = npc_interaction.handle_gossip_hello_for_npc(session, 123, b"")

    assert responses is not None
    assert responses[0][0] == "SMSG_GOSSIP_MESSAGE"
    assert len(responses[0][1]) > 0
    assert session.gossip_npc_guid == 123


def test_barkeep_name_can_open_bind_gossip(monkeypatch):
    monkeypatch.setattr(npc_interaction, "Logger", SimpleNamespace(info=lambda *args, **kwargs: None))
    session = SimpleNamespace(
        npc_flags_by_guid={5611: 0x280},
        npc_positions_by_guid={5611: (1, 10.0, 10.0, 0.0, 0.0)},
        npc_names_by_guid={5611: "Barkeep Morag"},
        map_id=1,
        x=10.0,
        y=10.0,
        z=0.0,
    )

    responses = npc_interaction.handle_gossip_hello_for_npc(session, 5611, b"")

    assert responses is not None
    assert responses[0][0] == "SMSG_GOSSIP_MESSAGE"
    assert session.gossip_npc_guid == 5611


def test_barkeep_list_inventory_opens_binder_confirm(monkeypatch):
    monkeypatch.setattr(npc_interaction, "Logger", SimpleNamespace(info=lambda *args, **kwargs: None))
    session = SimpleNamespace(
        npc_flags_by_guid={5611: 0x280},
        npc_positions_by_guid={5611: (1, 10.0, 10.0, 0.0, 0.0)},
        npc_names_by_guid={5611: "Barkeep Morag"},
        map_id=1,
        x=10.0,
        y=10.0,
        z=0.0,
    )

    status, responses = npc_interaction.handle_list_inventory_for_barkeep(session, b"")

    assert status == 0
    assert responses == [("SMSG_BINDER_CONFIRM", npc_interaction.build_binder_confirm_payload(5611))]
    assert session.gossip_npc_guid == 5611


def test_binder_activate_saves_player_position_and_sends_feedback(monkeypatch):
    saved = {}

    class FakeDatabase:
        @staticmethod
        def save_character_homebind(_char_guid, _realm_id, **kwargs):
            saved.update(kwargs)
            return True

    monkeypatch.setattr(npc_interaction, "DatabaseConnection", FakeDatabase)
    monkeypatch.setattr(npc_interaction, "Logger", SimpleNamespace(info=lambda *args, **kwargs: None))
    session = SimpleNamespace(
        npc_flags_by_guid={123: npc_interaction.UNIT_NPC_FLAG_INNKEEPER},
        npc_positions_by_guid={123: (1, 20.0, 30.0, 40.0, 0.0)},
        gossip_npc_guid=123,
        map_id=1,
        zone=12,
        current_area=34,
        x=20.0,
        y=30.0,
        z=40.0,
        orientation=1.25,
        char_guid=55,
        realm_id=1,
    )

    status, responses = npc_interaction.handle_binder_activate(session, b"")

    assert status == 0
    assert saved == {
        "map_id": 1,
        "zone_id": 34,
        "x": 20.0,
        "y": 30.0,
        "z": 40.0,
        "orientation": 1.25,
    }
    assert [opcode for opcode, _payload in responses] == [
        "SMSG_BIND_POINT_UPDATE",
        "SMSG_PLAYERBOUND",
        "SMSG_GOSSIP_COMPLETE",
        "SMSG_MESSAGECHAT",
    ]
    assert session.bind_map_id == 1
    assert session.bind_area_id == 34
    assert session.bind_x == 20.0
    assert session.bind_o == 1.25


def test_hearthstone_uses_saved_bind_position(monkeypatch):
    calls = []

    class FakeDatabase:
        @staticmethod
        def save_character_position(*args, **kwargs):
            calls.append((args, kwargs))
            return True

    monkeypatch.setattr(npc_interaction, "DatabaseConnection", FakeDatabase)
    monkeypatch.setattr(npc_interaction, "Logger", SimpleNamespace(info=lambda *args, **kwargs: None))
    session = SimpleNamespace(
        char_guid=55,
        realm_id=1,
        map_id=0,
        zone=12,
        current_area=12,
        x=1.0,
        y=2.0,
        z=3.0,
        orientation=0.0,
        bind_map_id=1,
        bind_area_id=34,
        bind_x=20.0,
        bind_y=30.0,
        bind_z=40.0,
        bind_o=1.25,
    )

    responses = npc_interaction.handle_hearthstone_cast(session)

    assert [opcode for opcode, _payload in responses] == [
        "SMSG_SPELL_FAILURE",
        "SMSG_SPELL_FAILED_OTHER",
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    assert session.map_id == 1
    assert session.zone == 34
    assert session.x == 20.0
    assert session.orientation == 1.25
    assert calls[0][1]["map_id"] == 1
    assert calls[0][1]["orientation"] == 1.25


def test_use_item_hearthstone_teleports(monkeypatch):
    monkeypatch.setattr(npc_interaction, "Logger", SimpleNamespace(info=lambda *args, **kwargs: None))
    monkeypatch.setattr(
        npc_interaction,
        "handle_hearthstone_cast",
        lambda _session: [("SMSG_TRANSFER_PENDING", b""), ("SMSG_NEW_WORLD", b"")],
    )
    hearthstone = SimpleNamespace(entry=npc_interaction.HEARTHSTONE_ITEM_ID)
    inventory_state = SimpleNamespace(
        items_by_pos={(0, 23): hearthstone},
        get=lambda bag, slot: hearthstone if (bag, slot) == (0, 23) else None,
    )
    session = SimpleNamespace(
        inventory_state=inventory_state,
        inventory_by_guid={},
        char_guid=55,
        realm_id=1,
        map_id=0,
        zone=12,
        current_area=12,
        x=1.0,
        y=2.0,
        z=3.0,
        orientation=0.0,
        bind_map_id=1,
        bind_area_id=34,
        bind_x=20.0,
        bind_y=30.0,
        bind_z=40.0,
        bind_o=1.25,
    )

    status, responses = npc_interaction.handle_use_item(session, bytes.fromhex("17ff000000000000000000000000"))

    assert status == 0
    assert [opcode for opcode, _payload in responses] == ["SMSG_TRANSFER_PENDING", "SMSG_NEW_WORLD"]
