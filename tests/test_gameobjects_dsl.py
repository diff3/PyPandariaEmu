from DSL.modules.EncoderHandler import EncoderHandler
from server.modules.handlers.world.bootstrap import gameobjects
from server.modules.game.guid import GameObjectGuid, MoTransportGuid


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
    }


def _dsl_fields():
    entry = _entry()
    world_guid = MoTransportGuid.from_spawn_guid(entry["guid"])
    mask_bytes, field_bytes = gameobjects._build_fixed_u32_field_block(
        gameobjects._build_gameobject_field_values(entry, world_guid=world_guid),
        mask_blocks=1,
    )
    flags = gameobjects._GAMEOBJECT_CREATE_FLAGS
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


def test_transport_gameobject_uses_start_open_state_and_full_health():
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
    assert (percent_health >> 24) & 0xFF == 0xFF
    assert (state_spell_visual_id >> 24) & 0xFF == 0
    assert fields[gameobjects._GAMEOBJECT_FIELD_LEVEL] == 0
    assert fields[gameobjects._GAMEOBJECT_FIELD_FLAGS] & gameobjects._GO_FLAG_TRANSPORT


def test_transport_gameobject_packs_path_progress_in_dynamic_flags():
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

    packed = fields[gameobjects._OBJECT_FIELD_DYNAMIC_FLAGS]
    assert packed & 0xFFFF == 0
    assert ((packed >> 16) & 0xFFFF) in (32767, 32768)


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
