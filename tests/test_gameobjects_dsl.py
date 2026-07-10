import json
from pathlib import Path
from unittest.mock import patch

from DSL.modules.EncoderHandler import EncoderHandler
from server.modules.handlers.world.bootstrap import gameobjects
from server.modules.game.guid import GameObjectGuid, MoTransportGuid
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
