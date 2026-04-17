from DSL.modules.EncoderHandler import EncoderHandler
from server.modules.handlers.world.bootstrap import gameobjects
from server.modules.game.guid import GameObjectGuid


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
    world_guid = GameObjectGuid.from_spawn_guid(entry["guid"], 1)
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
        "gameobject_rotation_packed": 0,
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
