import json
import math
import struct
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from DSL.modules.EncoderHandler import EncoderHandler
from server.modules.handlers.world.bootstrap import gameobjects
from server.modules.game.guid import GameObjectGuid, GuidHelper, MoTransportGuid
from server.modules.handlers.world.runtime.gameobject import GameObject
from server.modules.handlers.world.runtime.gameobject_store import (
    get_gameobject_runtime_store,
)
from server.modules.interpretation.utils import dsl_decode
from shared.Logger import Logger


def _entry():
    return {
        "guid": 4,
        "entry": 175354,
        "x": 1569.97,
        "y": -4397.41,
        "z": 16.05,
        "orientation": 0.0,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.0,
        "rotation3": 1.0,
        "display_id": 3015,
        "flags": 40,
        "size": 1.0,
        "type": 15,
        "state": 1,
        "animprogress": 255,
        "faction": 0,
        "transport_path_progress": 0,
    }


def _dsl_fields():
    entry = _entry()
    world_guid = MoTransportGuid.from_spawn_guid(entry["guid"])
    mask_bytes, field_bytes = gameobjects._build_fixed_u32_field_block(
        gameobjects._build_gameobject_field_values(entry, world_guid=world_guid),
        mask_blocks=1,
    )
    update_flags = gameobjects._gameobject_update_flags(entry)
    flags = gameobjects.gameobject_defs.build_gameobject_create_flags(update_flags)
    return {
        "map_id": 1,
        "update_count": 1,
        "update_type": 1,
        "guid": {"guid": world_guid},
        "object_type": 5,
        "create_flag_0": flags[0],
        "create_flag_1": flags[1],
        "create_flag_2": flags[2],
        "create_flag_3": flags[3],
        "create_flag_4": flags[4],
        "create_flag_5": flags[5],
        "stationary_y": float(entry["y"]),
        "stationary_z": float(entry["z"]),
        "stationary_orientation": float(entry["orientation"]),
        "stationary_x": float(entry["x"]),
        "has_transport_block": bool(update_flags & gameobjects._UPDATEFLAG_TRANSPORT),
        "movement_block_uint32": 0,
        "gameobject_rotation_packed": gameobjects._gameobject_rotation_packed(entry),
        "mask_blocks": len(mask_bytes) // 4,
        "mask": mask_bytes,
        "fields": field_bytes,
        "dynamic_mask_blocks": 0,
    }


def test_gameobject_create_dsl_matches_public_payload_builder():
    fields = _dsl_fields()
    dsl_payload = EncoderHandler.encode_packet("GAMEOBJECT_CREATE", fields)
    assert dsl_payload == gameobjects._build_gameobject_update_payload(
        map_id=1,
        entry=_entry(),
        realm_id=1,
    )


def test_gameobject_update_payload_uses_dsl_compatible_layout():
    payload = gameobjects._build_gameobject_update_payload(map_id=1, entry=_entry(), realm_id=1)
    fields = _dsl_fields()
    assert payload == EncoderHandler.encode_packet("GAMEOBJECT_CREATE", fields)


def test_create_packet_runtime_object_path_matches_mapping_fallback(monkeypatch):
    entry = {
        **_entry(),
        "map_id": 1,
        "map": 1,
        "type": 5,
    }
    runtime_guid = GameObjectGuid.from_spawn_guid(entry["guid"], 1)
    runtime_object = GameObject.from_mapping(
        entry,
        runtime_guid=runtime_guid,
    )
    store = get_gameobject_runtime_store()
    store.clear()
    try:
        fallback_payload = gameobjects._build_gameobject_update_payload(
            map_id=1,
            entry=entry,
            realm_id=1,
        )

        def reject_temporary_construction(cls, mapping, *, runtime_guid=0):
            raise AssertionError("matching runtime object must be consumed directly")

        monkeypatch.setattr(
            GameObject,
            "from_mapping",
            classmethod(reject_temporary_construction),
        )
        runtime_payload = gameobjects._build_gameobject_update_payload(
            map_id=1,
            entry=entry,
            realm_id=1,
            gameobject=runtime_object,
        )
    finally:
        store.clear()

    assert runtime_payload == fallback_payload


def test_create_packet_uses_runtime_object_live_transform():
    persistent_entry = {
        **_entry(),
        "map_id": 1,
        "map": 1,
        "type": 5,
    }
    live_entry = {
        **persistent_entry,
        "x": 101.25,
        "y": -202.5,
        "z": 33.75,
        "orientation": 1.25,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.5850972729404622,
        "rotation3": 0.8109631195052179,
        "size": 1.75,
    }
    runtime_guid = GameObjectGuid.from_spawn_guid(
        persistent_entry["guid"],
        1,
    )
    runtime_object = GameObject.from_mapping(
        live_entry,
        runtime_guid=runtime_guid,
    )
    store = get_gameobject_runtime_store()
    store.clear()
    try:
        persistent_payload = gameobjects._build_gameobject_update_payload(
            map_id=1,
            entry=persistent_entry,
            realm_id=1,
        )
        runtime_payload = gameobjects._build_gameobject_update_payload(
            map_id=1,
            entry=persistent_entry,
            realm_id=1,
            gameobject=runtime_object,
        )
        live_mapping_payload = gameobjects._build_gameobject_update_payload(
            map_id=1,
            entry=live_entry,
            realm_id=1,
        )
    finally:
        store.clear()

    assert runtime_payload == live_mapping_payload
    assert runtime_payload != persistent_payload


def test_create_packet_observes_mutated_runtime_object_state():
    persistent_entry = {
        **_entry(),
        "map_id": 1,
        "map": 1,
        "type": 5,
        "artkit": 0,
    }
    expected_entry = {
        **persistent_entry,
        "x": 101.25,
        "y": -202.5,
        "z": 33.75,
        "orientation": 1.25,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.5850972729404622,
        "rotation3": 0.8109631195052179,
        "size": 1.75,
        "display_id": 4321,
        "state": 2,
        "flags": 17,
        "faction": 35,
        "artkit": 9,
        "animprogress": 127,
        "type": 3,
    }
    runtime_guid = GameObjectGuid.from_spawn_guid(
        persistent_entry["guid"],
        1,
    )
    runtime_object = GameObject.from_mapping(
        persistent_entry,
        runtime_guid=runtime_guid,
    )
    runtime_object.set_position(101.25, -202.5, 33.75)
    runtime_object.set_orientation(1.25)
    runtime_object.set_rotation(
        (0.0, 0.0, 0.5850972729404622, 0.8109631195052179)
    )
    runtime_object.set_scale(1.75)
    runtime_object.set_display_id(4321)
    runtime_object.set_state(2)
    runtime_object.set_flags(17)
    runtime_object.set_faction(35)
    runtime_object.set_art_kit(9)
    runtime_object.set_animation_progress(127)
    runtime_object.set_gameobject_type(3)

    runtime_payload = gameobjects._build_gameobject_update_payload(
        map_id=1,
        entry=persistent_entry,
        realm_id=1,
        gameobject=runtime_object,
    )
    expected_payload = gameobjects._build_gameobject_update_payload(
        map_id=1,
        entry=expected_entry,
        realm_id=1,
    )

    assert runtime_payload == expected_payload
    assert persistent_entry["x"] != runtime_object.x
    assert persistent_entry["display_id"] != runtime_object.display_id


def test_create_packet_resolves_mutated_object_from_runtime_store():
    persistent_entry = {
        **_entry(),
        "map_id": 1,
        "map": 1,
        "type": 5,
    }
    runtime_guid = GameObjectGuid.from_spawn_guid(
        persistent_entry["guid"],
        1,
    )
    runtime_object = GameObject.from_mapping(
        persistent_entry,
        runtime_guid=runtime_guid,
    )
    runtime_object.set_position(101.25, -202.5, 33.75)
    runtime_object.set_state(2)
    runtime_object.set_display_id(4321)
    expected_entry = {
        **persistent_entry,
        "x": 101.25,
        "y": -202.5,
        "z": 33.75,
        "state": 2,
        "display_id": 4321,
    }
    store = get_gameobject_runtime_store()
    store.clear()
    expected_payload = gameobjects._build_gameobject_update_payload(
        map_id=1,
        entry=expected_entry,
        realm_id=1,
    )
    store.add(runtime_object)
    try:
        runtime_payload = gameobjects._build_gameobject_update_payload(
            map_id=1,
            entry=persistent_entry,
            realm_id=1,
        )
    finally:
        store.clear()

    assert runtime_payload == expected_payload
    assert persistent_entry["x"] != runtime_object.x
    assert persistent_entry["state"] != runtime_object.state


def test_create_packet_reuses_preloaded_runtime_store_object(monkeypatch):
    entry = {
        **_entry(),
        "map_id": 1,
        "map": 1,
        "type": 5,
    }
    runtime_guid = GameObjectGuid.from_spawn_guid(entry["guid"], 1)
    runtime_object = GameObject.from_mapping(
        entry,
        runtime_guid=runtime_guid,
    )
    store = get_gameobject_runtime_store()
    store.clear()
    store.add(runtime_object)

    def reject_temporary_construction(cls, mapping, *, runtime_guid=0):
        raise AssertionError("preloaded packet path must not create a duplicate")

    monkeypatch.setattr(
        GameObject,
        "from_mapping",
        classmethod(reject_temporary_construction),
    )
    try:
        payload = gameobjects._build_gameobject_update_payload(
            map_id=1,
            entry=entry,
            realm_id=1,
        )
    finally:
        store.clear()

    assert payload


def test_create_packet_does_not_read_runtime_snapshot_fields_from_mapping():
    entry = {
        **_entry(),
        "map_id": 1,
        "map": 1,
        "type": 5,
        "display_id": 4321,
        "state": 2,
        "flags": 17,
        "faction": 35,
        "artkit": 9,
        "animprogress": 127,
    }
    runtime_guid = GameObjectGuid.from_spawn_guid(entry["guid"], 1)
    runtime_object = GameObject.from_mapping(
        entry,
        runtime_guid=runtime_guid,
    )
    expected = gameobjects._build_gameobject_update_payload(
        map_id=1,
        entry=entry,
        realm_id=1,
        gameobject=runtime_object,
    )
    migrated_fields = {
        "type",
        "display_id",
        "state",
        "flags",
        "faction",
        "artkit",
        "animprogress",
    }

    class RuntimeFieldRejectingMapping(dict):
        def get(self, key, default=None):
            if key in migrated_fields:
                raise AssertionError(f"packet mapping read runtime field {key}")
            return super().get(key, default)

    actual = gameobjects._build_gameobject_update_payload(
        map_id=1,
        entry=RuntimeFieldRejectingMapping(entry),
        realm_id=1,
        gameobject=runtime_object,
    )

    assert actual == expected


def test_values_packet_runtime_object_path_matches_mapping_fallback():
    entry = {
        **_entry(),
        "map_id": 1,
        "map": 1,
        "type": 5,
    }
    runtime_guid = GameObjectGuid.from_spawn_guid(entry["guid"], 1)
    runtime_object = GameObject.from_mapping(
        entry,
        runtime_guid=runtime_guid,
    )
    store = get_gameobject_runtime_store()
    store.clear()
    try:
        fallback_payload = gameobjects._build_gameobject_values_update_payload(
            map_id=1,
            entry=entry,
            realm_id=1,
        )
        runtime_payload = gameobjects._build_gameobject_values_update_payload(
            map_id=1,
            entry=entry,
            realm_id=1,
            gameobject=runtime_object,
        )
    finally:
        store.clear()

    assert runtime_payload == fallback_payload


def test_create_response_runtime_object_path_matches_mapping_fallback():
    entry = {
        **_entry(),
        "map_id": 1,
        "map": 1,
        "type": 5,
    }
    runtime_guid = GameObjectGuid.from_spawn_guid(entry["guid"], 1)
    runtime_object = GameObject.from_mapping(
        entry,
        runtime_guid=runtime_guid,
    )
    session = SimpleNamespace(map_id=1, realm_id=1)
    store = get_gameobject_runtime_store()
    store.clear()
    try:
        fallback_response = gameobjects.build_gameobject_create_response(
            session,
            entry,
        )
        runtime_response = gameobjects.build_gameobject_create_response(
            session,
            entry,
            gameobject=runtime_object,
        )
    finally:
        store.clear()

    assert runtime_response == fallback_response


def test_destroy_response_runtime_object_path_matches_guid_path(monkeypatch):
    entry = {
        **_entry(),
        "map_id": 1,
        "map": 1,
        "type": 5,
    }
    runtime_guid = GameObjectGuid.from_spawn_guid(entry["guid"], 1)
    runtime_object = GameObject.from_mapping(
        entry,
        runtime_guid=runtime_guid,
    )
    session = SimpleNamespace(map_id=1)
    movement_module = ModuleType(
        "server.modules.handlers.world.opcodes.movement"
    )
    def build_out_of_range_payload(*, map_id, guid):
        payload = bytearray()
        payload += struct.pack("<HI", int(map_id) & 0xFFFF, 1)
        payload += struct.pack("<B", 3)
        payload += struct.pack("<I", 1)
        payload += GuidHelper.pack(int(guid) & 0xFFFFFFFFFFFFFFFF)
        return bytes(payload)

    movement_module._build_out_of_range_update_object_payload = (
        build_out_of_range_payload
    )
    monkeypatch.setitem(
        sys.modules,
        "server.modules.handlers.world.opcodes.movement",
        movement_module,
    )

    guid_response = gameobjects.build_gameobject_destroy_response(
        session,
        runtime_guid,
    )
    runtime_response = gameobjects.build_gameobject_destroy_response(
        session,
        runtime_guid,
        gameobject=runtime_object,
    )

    assert runtime_response == guid_response


def test_create_packet_without_preload_constructs_temporary_fallback(monkeypatch):
    entry = {
        **_entry(),
        "map_id": 1,
        "map": 1,
        "type": 5,
    }
    store = get_gameobject_runtime_store()
    store.clear()
    original_from_mapping = GameObject.from_mapping
    constructions = []

    def track_construction(cls, mapping, *, runtime_guid=0):
        constructions.append((dict(mapping), int(runtime_guid)))
        return original_from_mapping(mapping, runtime_guid=runtime_guid)

    monkeypatch.setattr(
        GameObject,
        "from_mapping",
        classmethod(track_construction),
    )
    try:
        gameobjects._build_gameobject_update_payload(
            map_id=1,
            entry=entry,
            realm_id=1,
        )
    finally:
        store.clear()

    assert len(constructions) == 1


def test_mo_transport_create_movement_block_uses_path_progress():
    entry = {
        **_entry(),
        "type": 15,
        "transport_path_progress": 99681,
    }

    assert gameobjects._gameobject_movement_block_uint32(entry) == 99681


def test_non_transport_create_movement_block_unchanged():
    entry = {
        **_entry(),
        "type": 5,
        "transport_path_progress": 99681,
    }

    assert gameobjects._gameobject_movement_block_uint32(entry) == 0


def test_normal_gameobject_create_omits_transport_layout():
    entry = {
        **_entry(),
        "type": 5,
    }
    update_flags = gameobjects._gameobject_update_flags(entry)
    captured = {}
    original_encode = EncoderHandler.encode_packet

    def _capture(opcode_name, fields):
        captured.update(fields)
        return original_encode(opcode_name, fields)

    with patch.object(EncoderHandler, "encode_packet", side_effect=_capture):
        payload = gameobjects._build_gameobject_update_payload(
            map_id=1,
            entry=entry,
            realm_id=1,
        )

    transport_fields = dict(captured)
    transport_fields["has_transport_block"] = True
    transport_payload = original_encode("GAMEOBJECT_CREATE", transport_fields)

    assert update_flags == (
        gameobjects._UPDATEFLAG_STATIONARY_POSITION
        | gameobjects._UPDATEFLAG_ROTATION
    )
    assert bytes(captured[f"create_flag_{index}"] for index in range(6)) == bytes.fromhex(
        "000000010040"
    )
    assert captured["has_transport_block"] is False
    assert len(payload) == len(transport_payload) - 4


def test_type_15_create_preserves_transport_layout():
    entry = _entry()
    update_flags = gameobjects._gameobject_update_flags(entry)

    assert update_flags == (
        gameobjects._UPDATEFLAG_TRANSPORT
        | gameobjects._UPDATEFLAG_STATIONARY_POSITION
        | gameobjects._UPDATEFLAG_ROTATION
    )
    assert gameobjects.gameobject_defs.build_gameobject_create_flags(update_flags) == bytes.fromhex(
        "000000030040"
    )


def test_type_15_update_fields_match_mop_transport_state_and_anim_progress():
    entry = {
        **_entry(),
        # Runtime-created type 15 transports currently arrive with these
        # server-side defaults; packet packing must expose the 5.4.8 values.
        "state": 0,
        "animprogress": 0,
    }
    world_guid = MoTransportGuid.from_spawn_guid(entry["guid"])

    fields = gameobjects._build_gameobject_field_values(entry, world_guid=world_guid)

    assert fields[gameobjects._GAMEOBJECT_FIELD_PERCENT_HEALTH] == 0x00000F01
    assert fields[gameobjects._GAMEOBJECT_FIELD_STATE_SPELL_VISUAL_ID] == 0xFF000000
    assert fields[gameobjects._GAMEOBJECT_FIELD_PERCENT_HEALTH] >> 24 == 0
    assert fields[gameobjects._GAMEOBJECT_FIELD_PERCENT_HEALTH] & 0xFFFF == 0x0F01


def test_type_15_update_fields_match_available_548_captures():
    root = Path(__file__).resolve().parents[2]
    capture_paths = (
        root / "data/proxy/pandaria548/captures/debug/SMSG_UPDATE_OBJECT.json",
        root / "data/proxy/skyfire548/captures/debug/SMSG_UPDATE_OBJECT.json",
    )

    for capture_path in capture_paths:
        capture = json.loads(capture_path.read_text(encoding="utf-8"))
        decoded = dsl_decode(
            "SMSG_UPDATE_OBJECT",
            bytes.fromhex(capture["hex_compact"]),
            silent=True,
        )
        update = decoded["updates"][0]
        captured_fields = dict(zip(update["mask"]["set_bits"], update["fields"]["u32"]))

        assert captured_fields[gameobjects._GAMEOBJECT_FIELD_PERCENT_HEALTH] == 0x00000F01
        assert captured_fields[gameobjects._GAMEOBJECT_FIELD_STATE_SPELL_VISUAL_ID] == 0xFF000000


def test_transport_gameobject_uses_start_open_state_without_anim_progress_in_state_field():
    entry = {
        **_entry(),
        "entry": 4170,
        "display_id": 360,
        "type": 11,
        "state": 24,
        "animprogress": 0,
        "data0": 0,
        "data1": 0,
    }
    world_guid = GameObjectGuid.from_spawn_guid(entry["guid"], 1)

    fields = gameobjects._build_gameobject_field_values(entry, world_guid=world_guid)

    percent_health = fields[gameobjects._GAMEOBJECT_FIELD_PERCENT_HEALTH]
    state_spell_visual_id = fields[gameobjects._GAMEOBJECT_FIELD_STATE_SPELL_VISUAL_ID]
    assert gameobjects._effective_gameobject_state(entry) == 1
    assert percent_health & 0xFF == 1
    assert (percent_health >> 8) & 0xFF == 11
    assert (percent_health >> 24) & 0xFF == 0
    assert (state_spell_visual_id >> 24) & 0xFF == 0
    assert fields[gameobjects._GAMEOBJECT_FIELD_LEVEL] == 0
    assert fields[gameobjects._GAMEOBJECT_FIELD_FLAGS] & gameobjects._GO_FLAG_TRANSPORT


def test_transport_gameobject_does_not_pack_path_progress_in_dynamic_flags():
    entry = {
        **_entry(),
        "entry": 4170,
        "display_id": 360,
        "type": 11,
        "transport_period": 32000,
        "transport_path_progress": 16000,
    }
    world_guid = GameObjectGuid.from_spawn_guid(entry["guid"], 1)

    fields = gameobjects._build_gameobject_field_values(entry, world_guid=world_guid)

    assert fields[gameobjects._OBJECT_FIELD_DYNAMIC_FLAGS] == 0


def test_transport_dynamic_flags_ignore_seed_for_type_11(monkeypatch):
    entry = {
        **_entry(),
        "entry": 4170,
        "display_id": 360,
        "type": 11,
        "transport_period": 32000,
    }
    monkeypatch.setattr(gameobjects.time, "time", lambda: 12.345)
    world_guid = GameObjectGuid.from_spawn_guid(entry["guid"], 1)

    fields = gameobjects._build_gameobject_field_values(entry, world_guid=world_guid)
    assert fields[gameobjects._OBJECT_FIELD_DYNAMIC_FLAGS] == 0


def test_type_11_create_movement_block_still_uses_path_progress():
    entry = {
        **_entry(),
        "entry": 4170,
        "display_id": 360,
        "type": 11,
        "transport_path_progress": 16000,
    }

    assert gameobjects._gameobject_movement_block_uint32(entry) == 16000


def test_type_11_create_flags_match_skyfire_transport_stationary_rotation_layout():
    update_flags = (
        gameobjects._UPDATEFLAG_TRANSPORT
        | gameobjects._UPDATEFLAG_STATIONARY_POSITION
        | gameobjects._UPDATEFLAG_ROTATION
    )

    assert gameobjects.gameobject_defs.build_gameobject_create_flags(update_flags) == bytes.fromhex(
        "000000030040"
    )


def test_deeprun_visible_subway_entries_are_detected():
    entry = {
        **_entry(),
        "guid": 18802,
        "entry": 176080,
        "map_id": 369,
        "type": 11,
        "display_id": 3831,
    }

    assert gameobjects._is_deeprun_visible_subway_entry(entry) is True


def test_deeprun_create_audit_logs_expected_fields(monkeypatch):
    entry = {
        **_entry(),
        "guid": 18802,
        "entry": 176080,
        "map_id": 369,
        "type": 11,
        "display_id": 3831,
        "data0": 0,
        "data1": 0,
    }
    world_guid = GameObjectGuid.from_spawn_guid(entry["guid"], 1)
    field_values = gameobjects._build_gameobject_field_values(entry, world_guid=world_guid)
    logged: list[str] = []

    def _capture(message, *args, **kwargs):
        logged.append(str(message) % args if args else str(message))

    monkeypatch.setattr(Logger, "info", _capture)

    gameobjects._log_deeprun_create_audit(
        entry,
        world_guid=world_guid,
        packet_map_id=369,
        update_flags=(
            gameobjects._UPDATEFLAG_TRANSPORT
            | gameobjects._UPDATEFLAG_STATIONARY_POSITION
            | gameobjects._UPDATEFLAG_ROTATION
        ),
        create_flags=bytes.fromhex("000000030040"),
        movement_block_uint32=1234,
        field_values=field_values,
    )

    assert logged
    assert "[DEEPRUN_CREATE_AUDIT]" in logged[0]
    assert "entry=176080" in logged[0]
    assert "create_flags=000000030040" in logged[0]
    assert "transport_block=yes" in logged[0]


def test_deeprun_visible_subway_keeps_gameobject_guid():
    entry = {
        **_entry(),
        "guid": 18802,
        "entry": 176080,
        "map_id": 369,
        "type": 11,
        "display_id": 3831,
    }

    assert gameobjects._resolve_world_guid(entry, 1) == GameObjectGuid.from_spawn_guid(18802, 1)


def test_deeprun_visible_subway_type_11_level_uses_data0_only():
    entry = {
        **_entry(),
        "guid": 18806,
        "entry": 176084,
        "map_id": 369,
        "type": 11,
        "display_id": 3831,
        "data0": 0,
        "data6": 58633,
        "data8": 71667,
        "data10": 130300,
    }
    world_guid = GameObjectGuid.from_spawn_guid(entry["guid"], 1)

    fields = gameobjects._build_gameobject_field_values(entry, world_guid=world_guid)

    assert gameobjects._client_transport_period(entry) == 0
    assert fields[gameobjects._GAMEOBJECT_FIELD_LEVEL] == 0
    assert fields[gameobjects._OBJECT_FIELD_DYNAMIC_FLAGS] == 0


def test_deeprun_visible_subway_entries_never_pack_transport_progress():
    for guid, entry_id in (
        (18802, 176080),
        (18803, 176081),
        (18804, 176082),
        (18805, 176083),
        (18806, 176084),
        (18807, 176085),
    ):
        entry = {
            **_entry(),
            "guid": guid,
            "entry": entry_id,
            "map_id": 369,
            "type": 11,
            "display_id": 3831,
            "data0": 0,
            "data6": 58633 if entry_id == 176084 else 0,
            "data8": 71667 if entry_id == 176084 else 0,
            "data10": 130300 if entry_id == 176084 else 0,
            "transport_path_progress": 54321,
        }
        world_guid = GameObjectGuid.from_spawn_guid(guid, 1)
        fields = gameobjects._build_gameobject_field_values(entry, world_guid=world_guid)

        assert fields[gameobjects._OBJECT_FIELD_DYNAMIC_FLAGS] == 0


def test_mo_transport_still_packs_path_progress_in_dynamic_flags():
    entry = {
        **_entry(),
        "type": 15,
        "transport_period": 32000,
        "transport_path_progress": 16000,
    }
    world_guid = MoTransportGuid.from_spawn_guid(entry["guid"])

    fields = gameobjects._build_gameobject_field_values(entry, world_guid=world_guid)

    packed = fields[gameobjects._OBJECT_FIELD_DYNAMIC_FLAGS]
    assert packed & 0xFFFF == 0
    assert ((packed >> 16) & 0xFFFF) in (32767, 32768)


def test_deeprun_preserves_spawn_quaternion_fields_from_db():
    entry = {
        **_entry(),
        "guid": 18802,
        "entry": 176080,
        "map_id": 369,
        "type": 11,
        "display_id": 3831,
        "orientation": 1.5708,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 1.0,
        "rotation3": 0.0,
    }
    world_guid = GameObjectGuid.from_spawn_guid(entry["guid"], 1)

    fields = gameobjects._build_gameobject_field_values(entry, world_guid=world_guid)

    assert gameobjects._rotation_components(entry) == (0.0, 0.0, 1.0, 0.0)
    assert gameobjects._GAMEOBJECT_FIELD_ROTATION_START + 2 in fields
    assert gameobjects._GAMEOBJECT_FIELD_ROTATION_START + 3 not in fields
    assert fields[gameobjects._GAMEOBJECT_FIELD_ROTATION_START + 2] == 0x3F800000


def test_mailbox_create_preserves_skyfire_parent_rotation_and_world_yaw():
    entry = {
        **_entry(),
        "guid": 73385,
        "entry": 206726,
        "type": 19,
        "display_id": 2128,
        "orientation": 3.91827,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.0,
        "rotation3": 1.0,
        "size": 1.0,
        "flags": 0,
        "faction": 1735,
    }
    world_guid = GameObjectGuid.from_spawn_guid(entry["guid"], 1)
    fields = gameobjects._build_gameobject_field_values(entry, world_guid=world_guid)

    assert gameobjects._stationary_orientation(entry) == gameobjects._normalize_orientation(3.91827)
    assert gameobjects._rotation_components(entry) == (0.0, 0.0, 0.0, 1.0)
    assert fields[gameobjects._GAMEOBJECT_FIELD_ROTATION_START + 3] == 0x3F800000
    assert gameobjects._GAMEOBJECT_FIELD_ROTATION_START + 2 not in fields
    assert fields[gameobjects._GAMEOBJECT_FIELD_DISPLAY_ID] == 2128
    assert fields[gameobjects._OBJECT_FIELD_SCALE] == 0x3F800000
    assert fields[gameobjects._GAMEOBJECT_FIELD_PERCENT_HEALTH] == (1 | (19 << 8))
    assert gameobjects._gameobject_rotation_packed(entry) != 0


def test_rotation_components_uses_entry_type_for_transport_transform_object():
    entry = {
        **_entry(),
        "type": 15,
        "orientation": 1.25,
        "_runtime_transport_orientation_authoritative": True,
    }
    transport = SimpleNamespace(
        orientation=1.25,
        rotation=(0.0, 0.0, 0.0, 1.0),
    )

    components = gameobjects._rotation_components(entry, transport)

    assert components == gameobjects._normalize_quaternion(
        0.0,
        0.0,
        math.sin(1.25 * 0.5),
        math.cos(1.25 * 0.5),
    )


def test_deeprun_packed_rotation_still_uses_orientation_seed():
    entry = {
        **_entry(),
        "guid": 18802,
        "entry": 176080,
        "map_id": 369,
        "type": 11,
        "display_id": 3831,
        "orientation": 1.5708,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 1.0,
        "rotation3": 0.0,
    }

    assert gameobjects._gameobject_rotation_packed(entry) == 0x0B5050


def test_mo_transport_uses_mo_transport_guid():
    entry = {**_entry(), "guid": 6, "type": 15}

    assert gameobjects._resolve_world_guid(entry, 1) == 0x1FC0000000000006


def test_mo_transport_keeps_explicit_world_guid():
    entry = {
        **_entry(),
        "guid": 6,
        "type": 15,
        "world_guid": GameObjectGuid.from_spawn_guid(6, 1),
    }

    assert gameobjects._resolve_world_guid(entry, 1) == GameObjectGuid.from_spawn_guid(6, 1)


def test_mo_transport_level_uses_transport_period_when_present():
    entry = {**_entry(), "guid": 6, "type": 15, "data0": 0, "transport_period": 339575}
    world_guid = MoTransportGuid.from_spawn_guid(entry["guid"])

    fields = gameobjects._build_gameobject_field_values(entry, world_guid=world_guid)

    assert fields[gameobjects._GAMEOBJECT_FIELD_LEVEL] == 339575
