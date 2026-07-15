from __future__ import annotations

from server.modules.handlers.world.protocol.orientation import normalize_orientation

"""Player UPDATE_OBJECT notes for the native server-built implementation.

Known state:
- This module currently owns two things:
  1. Server-built player CREATE_OBJECT and value-update payloads.
  2. Debug helpers that inspect captured player UPDATE_OBJECT payloads.
- The player create movement block is still an exact byte block and is the
  remaining non-native part of the current 0002 builder.

What is already understood:
- Packed GUID extraction for the first UPDATE_OBJECT entry works well enough for
  player guid verification.
- A minimal value-update packet can be built server-side with:
  map_id, update_count, update_type, packed guid, update mask, field values,
  and a trailing zero byte.
- Captured player creates contain a living movement block that can be detected
  heuristically from a 13-float sequence. The currently recognized values are:
  fly_speed, turn_speed, swim_speed, pitch_speed, x, orientation, walk_speed,
  y, fly_back_speed, run_back_speed, run_speed, swim_back_speed, z.

Known field specification:
- Current server-built player value-update packet layout, in wire order:
  1. map_id: uint16, 2 bytes
  2. update_count: uint32, 4 bytes
  3. update_type: uint8, 1 byte
  4. guid: packed guid
     - guid mask: uint8, 1 byte
     - guid data: variable length, 0 to 8 bytes
     - size depends on how many bits are set in the guid mask
  5. mask_words: uint8, 1 byte
  6. update mask: 4 bytes per mask word
     - total size = mask_words * 4
  7. field_bytes: variable length
     - each field value is uint32, 4 bytes
     - one uint32 is written for each enabled bit in the update mask
     - fields are serialized in ascending field-index order
  8. end marker: uint8 zero, 1 byte
- Known gaps in the current server-built value-update layout:
  - There are no known padding gaps between the sections listed above.
  - The only variable-size regions are packed guid, update mask, and field_bytes.
- Captured player UPDATE_OBJECT guid parsing, in wire order:
  1. map_id: uint16, 2 bytes
  2. update_count: uint32, 4 bytes
  3. update_type: uint8, 1 byte
  4. optional out_of_range_count: uint32, 4 bytes
     - only present when update_type == 3
  5. guid mask: uint8, 1 byte
  6. guid data: variable length, 0 to 8 bytes
     - size is the popcount of the guid mask
  - Verified player CREATE_OBJECT capture:
  - Source:
    - data/proxy/skyfire548/captures/focus/debug/SMSG_UPDATE_OBJECT_1776451639_0458.json
  - Verified top-level layout:
    1. map_id: uint16, bytes 0x0000-0x0001, value 1
    2. update_count: uint32, bytes 0x0002-0x0005, value 1
    3. update_type: uint8, byte 0x0006, value 2
       - consistent with CreateObject2
    4. guid mask: uint8, byte 0x0007, value 0x01
    5. guid data: bytes 0x0008-0x0008, value 0x0E
       - reconstructed guid: 0x000000000000000E
    6. object_type: uint8, byte 0x0009, value 4
       - treated as Player in this packet path
  - Verified object body layout:
    1. movement region: bytes 0x000A-0x004B
    2. mask_blocks: uint8, byte 0x004C, value 63
    3. update mask: bytes 0x004D-0x0148, size 252 bytes
    4. field values: bytes 0x0149-0x0308, size 448 bytes
    5. trailing byte: byte 0x0309, value 0
       - treated as dynamic_mask_blocks = 0
  - Known gaps in this verified create packet:
    - the movement block is not fully decoded yet
    - some bytes inside the movement region are still unidentified
- Captured living movement block:
  - This block is currently identified heuristically inside the captured player
    payload, not from a full formal packet definition.
  - Observed order and size:
    1. fly_speed: float, 4 bytes
    2. turn_speed: float, 4 bytes
    3. swim_speed: float, 4 bytes
    4. pitch_speed: float, 4 bytes
    5. x: float, 4 bytes
    6. orientation: float, 4 bytes
    7. walk_speed: float, 4 bytes
    8. y: float, 4 bytes
    9. fly_back_speed: float, 4 bytes
    10. run_back_speed: float, 4 bytes
    11. run_speed: float, 4 bytes
    12. swim_back_speed: float, 4 bytes
    13. z: float, 4 bytes
  - Total observed size: 52 bytes
  - Known gap status:
    - no internal gaps are assumed inside this 13-float block
    - any bytes before or after this block inside the captured player
      object are still unknown
- Verified field indices from the SkyFire player create capture:
  - object fields:
    - 0: OBJECT_FIELD_GUID low
    - 4: OBJECT_FIELD_TYPE
    - 7: OBJECT_FIELD_SCALE_X
  - unit fields:
    - 30: UNIT_FIELD_BYTES_0
    - 33: UNIT_FIELD_HEALTH
    - 34: UNIT_FIELD_POWER[0]
    - 39: UNIT_FIELD_MAXHEALTH
    - 55: UNIT_FIELD_LEVEL
    - 57: UNIT_FIELD_FACTIONTEMPLATE
    - 61: UNIT_FIELD_FLAGS
    - 62: UNIT_FIELD_FLAGS_2
    - 67: UNIT_FIELD_BOUNDINGRADIUS
    - 68: UNIT_FIELD_COMBATREACH
    - 69: UNIT_FIELD_DISPLAYID
    - 70: UNIT_FIELD_NATIVEDISPLAYID
    - 71: UNIT_FIELD_MOUNTDISPLAYID
    - 72: UNIT_FIELD_MINDAMAGE
    - 73: UNIT_FIELD_MAXDAMAGE
  - player fields:
    - 166: PLAYER_BYTES
    - 167: PLAYER_BYTES_2
    - 168: PLAYER_BYTES_3
    - 961: PLAYER_FIELD_VIRTUAL_PLAYER_REALM
    - 1943: PLAYER_FIELD_MAX_LEVEL
    - 1952-1957: PLAYER_FIELD_GLYPH_SLOTS_1..6
- Verified field values from the same capture:
  - 0  -> 14
  - 4  -> 25
  - 7  -> 1.0
  - 33 -> 102
  - 39 -> 102
  - 55 -> 1
  - 57 -> 4
  - 61 -> 8
  - 62 -> 2048
  - 67 -> 0.389
  - 68 -> 1.5
  - 69 -> 56
  - 70 -> 56
  - 71 -> 0
  - 166 -> 393479
  - 167 -> 16777220
  - 168 -> 1
  - 1943 -> 90
- Confidence notes for the verified capture:
  - high confidence:
    - top-level create packet layout
    - mask block location and size
    - field value block location and size
    - the object/unit/player field mappings listed above
  - medium confidence:
    - exact meaning of all movement bytes before mask_blocks
    - some sparse player-private field ranges not yet documented here
  - low confidence:
    - any undocumented bytes inside the movement region
    - any inferred field names not listed explicitly above

Known remaining gap:
- The player create movement block is still carried as exact bytes. Replacing it
  requires decoding the unidentified movement-region bytes without changing the
  current packet identity.
"""

import math
import struct

from shared.Logger import Logger
from server.modules.game.guid import GuidHelper
from server.modules.handlers.world.protocol.update_object import player as player_update_defs
from server.modules.handlers.world.protocol.update_object.serializers import (
    build_fixed_u32_field_block,
    u32_from_float,
)
from server.modules.handlers.world.runtime.player import Player
from server.session.runtime import session as runtime_session

for _definition_name in player_update_defs.__all__:
    globals()[f"_{_definition_name}"] = getattr(player_update_defs, _definition_name)

_BIAS_SENSITIVE_PLAYER_FIELDS = (57, 166, 167, 168, 1943)


def _u32_from_float(value: float) -> int:
    return u32_from_float(value)


def _resolve_player_guid(ctx, player: Player | None = None) -> int:
    if player is not None:
        return int(player.runtime_guid)
    return int(
        getattr(ctx, "world_guid", 0)
        or getattr(ctx, "player_guid", 0)
        or getattr(ctx, "char_guid", 0)
        or 0
    )


def _resolve_player_low_guid(ctx, player: Player | None = None) -> int:
    if player is not None:
        return int(player.character_guid) & 0xFF
    return int(
        getattr(ctx, "exact_0002_low_guid", 0)
        or getattr(ctx, "char_guid", 0)
        or getattr(ctx, "player_guid", 0)
        or getattr(ctx, "world_guid", 0)
        or 0
    ) & 0xFF


def _resolve_player_display_id(ctx) -> int:
    explicit_value = int(getattr(ctx, "display_id", 0) or 0)
    if explicit_value > 0:
        return explicit_value

    race = int(getattr(ctx, "race", 0) or 0)
    gender = int(getattr(ctx, "gender", 0) or 0)
    gender_map = _PLAYER_DISPLAY_IDS.get(race)

    if not gender_map:
        return 15475
    return int(gender_map.get(gender, 15475))


def _resolve_player_faction_template(ctx) -> int:
    explicit_value = int(getattr(ctx, "faction_template", 0) or 0)
    if explicit_value > 0:
        return explicit_value

    race = int(getattr(ctx, "race", 0) or 0)
    return int(_PLAYER_FACTION_TEMPLATE_IDS.get(race, 1610))


def _u32_from_two_u16(low: int, high: int) -> int:
    return _pack_u16x2(low, high)


def _pack_u8x4(a: int, b: int, c: int, d: int) -> int:
    return (
        (int(a) & 0xFF)
        | ((int(b) & 0xFF) << 8)
        | ((int(c) & 0xFF) << 16)
        | ((int(d) & 0xFF) << 24)
    )


def _pack_u16x2(a: int, b: int) -> int:
    return (int(a) & 0xFFFF) | ((int(b) & 0xFFFF) << 16)


def _unpack_u8x4(value: int) -> tuple[int, int, int, int]:
    raw = int(value or 0)
    return (
        raw & 0xFF,
        (raw >> 8) & 0xFF,
        (raw >> 16) & 0xFF,
        (raw >> 24) & 0xFF,
    )


def _resolve_player_team(ctx) -> str | None:
    """Resolve Alliance/Horde from explicit faction data before falling back to race."""
    explicit_faction = getattr(ctx, "faction", None)
    if isinstance(explicit_faction, str):
        normalized = explicit_faction.strip().lower()
        if normalized in {"alliance", "ally"}:
            return "alliance"
        if normalized in {"horde"}:
            return "horde"

    faction_template = int(getattr(ctx, "faction_template", 0) or 0)
    if faction_template in _ALLIANCE_FACTION_TEMPLATES:
        return "alliance"
    if faction_template in _HORDE_FACTION_TEMPLATES:
        return "horde"

    race = int(getattr(ctx, "race", 0) or 0)
    if race in _ALLIANCE_RACES:
        return "alliance"
    if race in _HORDE_RACES:
        return "horde"
    return None


def _patch_language_mask_bytes(payload: bytes, ctx) -> bytes:
    """Keep server-built player-create payload bytes stable.

    The legacy path used a raw payload byte-replace for language masks, but
    doing that here can mutate unrelated sections such as the update mask. The
    server-built path already patches language/riding values through
    _patch_language_skill_fields(), so the payload itself must remain untouched.
    """
    return bytes(payload)


def _apply_legacy_language_riding_skill_block(
    field_values: dict[int, int],
    *,
    primary_language: int,
    racial_language: int,
) -> None:
    """Build the legacy-compatible language/riding skill block exactly."""
    field_values[1153] = _u32_from_two_u16(primary_language, _SKILL_RIDING)
    field_values[1154] = _u32_from_two_u16(racial_language, 0)
    field_values[1155] = 0
    field_values[1156] = 0
    field_values[1157] = 0
    field_values[1158] = 0
    field_values[1159] = 0

    field_values[1281] = _u32_from_two_u16(_SKILL_LANGUAGE_RANK, _SKILL_RIDING_RANK)
    field_values[1282] = _u32_from_two_u16(_SKILL_LANGUAGE_RANK, 0)
    field_values[1283] = 0
    field_values[1284] = 0
    field_values[1285] = 0
    field_values[1286] = 0
    field_values[1287] = 0

    field_values[1409] = _u32_from_two_u16(_SKILL_LANGUAGE_RANK, _SKILL_RIDING_RANK)
    field_values[1410] = _u32_from_two_u16(_SKILL_LANGUAGE_RANK, 0)
    field_values[1411] = 0
    field_values[1412] = 0
    field_values[1413] = 0
    field_values[1414] = 0
    field_values[1415] = 0


def _patch_language_skill_fields(field_values: dict[int, int], ctx) -> None:
    """Patch the old working language/riding skill block."""
    team = _resolve_player_team(ctx)
    if team == "alliance":
        primary_language = _LANGUAGE_SKILL_COMMON
    elif team == "horde":
        primary_language = _LANGUAGE_SKILL_ORCISH
    else:
        return

    race = int(getattr(ctx, "race", 0) or 0)
    racial_language = int(_RACIAL_LANGUAGE_SKILL_BY_RACE.get(race, primary_language) or primary_language)
    _apply_legacy_language_riding_skill_block(
        field_values,
        primary_language=primary_language,
        racial_language=racial_language,
    )


def locate_update_field_region(payload: bytes) -> dict[str, int]:
    """Locate the field mask and field bytes inside a CREATE_OBJECT payload."""
    if len(payload) < 10:
        raise ValueError("payload is too short to contain player CREATE_OBJECT data")

    exact_region = _locate_server_built_create_field_region(payload)
    if exact_region is not None:
        return exact_region

    body_offset = 10
    candidates: list[dict[str, int]] = []

    for mask_offset in range(body_offset, len(payload)):
        mask_blocks = payload[mask_offset]
        if mask_blocks <= 0:
            continue

        mask_size = int(mask_blocks) * 4
        remaining = len(payload) - (mask_offset + 1)
        if remaining < mask_size + 1:
            continue

        field_bytes_size = remaining - mask_size - 1
        if field_bytes_size < 0 or field_bytes_size % 4 != 0:
            continue

        mask_start = mask_offset + 1
        mask_end = mask_start + mask_size
        field_start = mask_end
        field_end = field_start + field_bytes_size
        mask_bytes = payload[mask_start:mask_end]
        enabled_bits = sum(byte.bit_count() for byte in mask_bytes)
        field_count = field_bytes_size // 4

        if enabled_bits != field_count:
            continue

        candidates.append(
            {
                "mask_offset": mask_offset,
                "mask_blocks": int(mask_blocks),
                "mask_start": mask_start,
                "mask_end": mask_end,
                "field_start": field_start,
                "field_end": field_end,
                "field_count": field_count,
            }
        )

    if not candidates:
        raise ValueError("could not locate CREATE_OBJECT field region")

    candidates.sort(key=lambda item: (-item["field_count"], item["mask_offset"]))
    return candidates[0]


def _locate_server_built_create_field_region(
    payload: bytes,
    *,
    movement_block_size: int = _PLAYER_CREATE_MOVEMENT_BLOCK_SIZE,
) -> dict[str, int] | None:
    """Locate the field region from the known server-built CREATE_OBJECT layout."""
    if len(payload) < 9:
        return None

    try:
        update_type = payload[6]
        if update_type != _PLAYER_CREATE_UPDATE_TYPE:
            return None

        offset = 7
        guid_mask = payload[offset]
        offset += 1 + guid_mask.bit_count()
        if offset >= len(payload):
            return None

        offset += 1
        mask_offset = offset + int(movement_block_size)
        if mask_offset >= len(payload):
            return None

        mask_blocks = int(payload[mask_offset])
        if mask_blocks <= 0:
            return None

        mask_start = mask_offset + 1
        mask_end = mask_start + (mask_blocks * 4)
        if mask_end >= len(payload):
            return None

        field_bytes_size = len(payload) - mask_end - 1
        if field_bytes_size < 0 or field_bytes_size % 4 != 0:
            return None

        mask_bytes = payload[mask_start:mask_end]
        enabled_bits = sum(byte.bit_count() for byte in mask_bytes)
        field_count = field_bytes_size // 4
        if enabled_bits != field_count:
            return None

        return {
            "mask_offset": mask_offset,
            "mask_blocks": mask_blocks,
            "mask_start": mask_start,
            "mask_end": mask_end,
            "field_start": mask_end,
            "field_end": mask_end + field_bytes_size,
            "field_count": field_count,
        }
    except (IndexError, struct.error, ValueError):
        return None


def locate_field_region(payload: bytes) -> tuple[int, int]:
    """Return the start and end offsets for the CREATE_OBJECT field bytes."""
    region = locate_update_field_region(payload)
    return region["field_start"], region["field_end"]


def locate_mask_region(payload: bytes) -> tuple[int, int, int]:
    """Return the start, end, and block count for the CREATE_OBJECT field mask."""
    region = locate_update_field_region(payload)
    return region["mask_start"], region["mask_end"], region["mask_blocks"]


def extract_field_indices(mask_bytes: bytes, mask_blocks: int) -> list[int]:
    """Expand mask bytes into a flat list of enabled field indices."""
    indices: list[int] = []
    for word_index in range(mask_blocks):
        word = struct.unpack_from("<I", mask_bytes, word_index * 4)[0]
        for bit_index in range(32):
            if word & (1 << bit_index):
                indices.append(word_index * 32 + bit_index)
    return indices


def patch_create_fields(
    ref_field_bytes: bytes,
    field_indices: list[int],
    srv_values: dict[int, int],
) -> bytes:
    """Patch CREATE_OBJECT field bytes using server-built values where available."""
    output = bytearray(ref_field_bytes)
    offset = 0

    for field_index in field_indices:
        if field_index in srv_values:
            struct.pack_into("<I", output, offset, srv_values[field_index])
        offset += 4

    return bytes(output)


def build_update_mask(field_values: dict[int, int]) -> tuple[bytes, int]:
    """Build CREATE_OBJECT update-mask bytes directly from field indices."""
    if not field_values:
        raise ValueError("field_values must not be empty")

    max_index = max(int(field_index) for field_index in field_values)
    mask_words = (max_index // 32) + 1
    mask_bytes, _field_bytes = build_fixed_u32_field_block(field_values, mask_blocks=mask_words)
    return mask_bytes, mask_words


def _serialize_field_values(field_values: dict[int, int]) -> bytes:
    """Serialize CREATE_OBJECT fields in ascending field-index order."""
    mask_words = (max(int(field_index) for field_index in field_values) // 32) + 1
    _mask_bytes, field_bytes = build_fixed_u32_field_block(field_values, mask_blocks=mask_words)
    return field_bytes


def _read_u32_field_value(field_indices: list[int], field_bytes: bytes, field_index: int) -> int:
    """Read one uint32 field value from packed CREATE_OBJECT field bytes."""
    offset = 0
    for current_index in field_indices:
        if current_index == field_index:
            return struct.unpack_from("<I", field_bytes, offset)[0]
        offset += 4
    raise ValueError(f"missing field {field_index}")


def _verify_player_level_field_in_payload(
    payload: bytes,
    expected_level: int,
    *,
    movement_block_size: int = _PLAYER_CREATE_MOVEMENT_BLOCK_SIZE,
) -> None:
    """Ensure CREATE_OBJECT includes the level field and that it matches ctx.level."""
    region = _locate_server_built_create_field_region(
        payload,
        movement_block_size=movement_block_size,
    )
    if region is None:
        raise ValueError("could not locate server-built player create field region")
    mask_start = region["mask_start"]
    mask_end = region["mask_end"]
    mask_blocks = region["mask_blocks"]
    field_start = region["field_start"]
    field_end = region["field_end"]
    field_indices = extract_field_indices(payload[mask_start:mask_end], mask_blocks)

    if _UNIT_FIELD_LEVEL not in field_indices:
        raise ValueError(f"player create mask missing field {_UNIT_FIELD_LEVEL}")

    actual_level = _read_u32_field_value(
        field_indices,
        payload[field_start:field_end],
        _UNIT_FIELD_LEVEL,
    )
    Logger.info(f"[LEVEL FIELD] idx=55 value={actual_level}")
    if int(actual_level) != int(expected_level):
        raise ValueError(
            f"player create level mismatch: expected {int(expected_level)} got {int(actual_level)}"
        )


def _diff_bytes(a: bytes, b: bytes) -> list[tuple[int, int, int]]:
    """Return byte differences for equally sized byte sequences."""
    return [(index, a[index], b[index]) for index in range(min(len(a), len(b))) if a[index] != b[index]]


def _pack_msb_bits(values: list[tuple[int, int]]) -> bytes:
    output = bytearray()
    current = 0
    bit_count = 0
    for value, width in values:
        for bit_index in range(int(width) - 1, -1, -1):
            current = (current << 1) | ((int(value) >> bit_index) & 1)
            bit_count += 1
            if bit_count == 8:
                output.append(current)
                current = 0
                bit_count = 0
    if bit_count:
        output.append(current << (8 - bit_count))
    return bytes(output)


_MOVEMENTFLAG_FALLING = 0x00000800
_MOVEMENTFLAG_SWIMMING = 0x00100000
_MOVEMENTFLAG_FLYING = 0x01000000
_MOVEMENTFLAG_SPLINE_ELEVATION = 0x02000000
_MOVEMENTFLAG2_ALWAYS_ALLOW_PITCHING = 0x00000010


def _guid_byte_seq(raw_guid: bytes, index: int) -> bytes:
    value = raw_guid[index]
    if not value:
        return b""
    return bytes((value ^ 0x01,))


def _movement_u32(ctx, *names: str, default: int = 0) -> int:
    for name in names:
        value = getattr(ctx, name, None)
        if value is not None:
            return int(value or 0) & 0xFFFFFFFF
    return int(default) & 0xFFFFFFFF


def _movement_float(ctx, *names: str, default: float = 0.0) -> float:
    for name in names:
        value = getattr(ctx, name, None)
        if value is not None:
            return float(value or 0.0)
    return float(default)


def _movement_int(ctx, *names: str, default: int = 0) -> int:
    for name in names:
        value = getattr(ctx, name, None)
        if value is not None:
            return int(value or 0)
    return int(default)


def _experimental_player_create_living_movement_enabled() -> bool:
    try:
        from server.modules.handlers.world.feature_config import (
            experimental_player_create_living_movement_enabled,
        )

        return bool(experimental_player_create_living_movement_enabled())
    except Exception:
        return False


def _resolve_player_create_movement_guid(
    ctx,
    player: Player | None = None,
) -> int:
    return _resolve_player_guid(ctx, player)


def _player_create_transport_data(ctx) -> dict[str, int | float] | None:
    guid = int(getattr(ctx, "transport_guid", 0) or 0)
    if not bool(getattr(ctx, "has_transport_data", False)) or guid <= 0:
        return None
    return {
        "guid": guid,
        "x": float(getattr(ctx, "transport_x", 0.0) or 0.0),
        "y": float(getattr(ctx, "transport_y", 0.0) or 0.0),
        "z": float(getattr(ctx, "transport_z", 0.0) or 0.0),
        "orientation": float(getattr(ctx, "transport_orientation", 0.0) or 0.0),
        "time": int(getattr(ctx, "transport_time", 0) or 0) & 0xFFFFFFFF,
        "time2": int(getattr(ctx, "transport_time2", 0) or 0) & 0xFFFFFFFF,
        "time3": int(getattr(ctx, "transport_time3", 0) or 0) & 0xFFFFFFFF,
        "seat": int(getattr(ctx, "transport_seat", -1)),
    }


def _player_create_movement_state(
    ctx,
    player: Player | None = None,
) -> dict[str, int | float | bool | None]:
    movement_flags = _movement_u32(ctx, "movement_flags", "move_flags")
    movement_flags2 = _movement_u32(ctx, "movement_flags2", "move_flags2")
    movement_counter = _movement_u32(ctx, "movement_counter")
    timestamp = _movement_u32(ctx, "movement_timestamp", "timestamp", "time")
    orientation = (
        float(player.orientation)
        if player is not None
        else _movement_float(ctx, "orientation")
    )
    pitch = _movement_float(ctx, "pitch")
    fall_time = _movement_u32(ctx, "fall_time")
    fall_zspeed = _movement_float(ctx, "fall_zspeed", "jump_zspeed")
    fall_cos = _movement_float(ctx, "fall_cos_angle", "jump_cos_angle")
    fall_sin = _movement_float(ctx, "fall_sin_angle", "jump_sin_angle")
    fall_xyspeed = _movement_float(ctx, "fall_xy_speed", "jump_xy_speed")
    spline_elevation = _movement_float(ctx, "spline_elevation")
    has_fall_direction = bool(
        getattr(ctx, "has_fall_direction", False)
        or getattr(ctx, "fall_direction", False)
        or (movement_flags & _MOVEMENTFLAG_FALLING)
    )
    has_fall_data = bool(has_fall_direction or fall_time)
    has_pitch = bool(
        getattr(ctx, "has_pitch", False)
        or (movement_flags & (_MOVEMENTFLAG_SWIMMING | _MOVEMENTFLAG_FLYING))
        or (movement_flags2 & _MOVEMENTFLAG2_ALWAYS_ALLOW_PITCHING)
    )
    has_spline_elevation = bool(movement_flags & _MOVEMENTFLAG_SPLINE_ELEVATION)
    return {
        "movement_flags": movement_flags,
        "movement_flags2": movement_flags2,
        "movement_counter": movement_counter,
        "timestamp": timestamp,
        "orientation": orientation,
        "pitch": pitch,
        "fall_time": fall_time,
        "fall_zspeed": fall_zspeed,
        "fall_cos": fall_cos,
        "fall_sin": fall_sin,
        "fall_xyspeed": fall_xyspeed,
        "spline_elevation": spline_elevation,
        "has_fall_direction": has_fall_direction,
        "has_fall_data": has_fall_data,
        "has_pitch": has_pitch,
        "has_spline_elevation": has_spline_elevation,
        "has_timestamp": bool(timestamp),
        "has_orientation": not math.isclose(orientation, 0.0, abs_tol=1e-6),
        "has_movement_flags": bool(movement_flags),
        "has_movement_flags2": bool(movement_flags2),
    }


def _build_player_create_movement_bits(
    ctx=None,
    player: Player | None = None,
) -> bytes:
    """Build the SkyFire 5.4.8 CREATE_OBJECT living movement bit region."""
    transport = _player_create_transport_data(ctx) if ctx is not None else None
    state = (
        _player_create_movement_state(ctx, player)
        if ctx is not None
        else _player_create_movement_state(object(), player)
    )
    player_guid = (
        _resolve_player_create_movement_guid(ctx, player)
        if ctx is not None
        else 0
    )
    player_guid_bytes = int(player_guid).to_bytes(8, "little", signed=False)
    transport_guid_bytes = (
        int(transport["guid"]).to_bytes(8, "little", signed=False)
        if transport is not None
        else bytes(8)
    )
    transport_masks = [1 if value else 0 for value in transport_guid_bytes]
    has_time2 = bool(transport and int(transport["time2"]) != 0)
    has_time3 = bool(transport and int(transport["time3"]) != 0)

    bits = [
        (_PLAYER_CREATE_BIT676, 1),
        (_PLAYER_CREATE_HAS_ANIM_KITS, 1),
        (_PLAYER_CREATE_IS_LIVING, 1),
        (_PLAYER_CREATE_BIT810, 1),
        (0, 1),  # fake bit
        (_PLAYER_CREATE_TRANSPORT_FRAMES, 22),
        (_PLAYER_CREATE_HAS_VEHICLE_DATA, 1),
        (_PLAYER_CREATE_BIT1044, 1),
        (0, 1),  # fake bit
        (_PLAYER_CREATE_BIT476, 1),
        (_PLAYER_CREATE_HAS_GAMEOBJECT_ROTATION, 1),
        (0, 1),  # fake bit
        (_PLAYER_CREATE_BIT680, 1),
        (_PLAYER_CREATE_HAS_ATTACKING_TARGET, 1),
        (_PLAYER_CREATE_HAS_SCENE_OBJECT_DATA, 1),
        (_PLAYER_CREATE_BIT1064, 1),
        (0, 1),  # fake bit
        (_PLAYER_CREATE_BIT668, 1),
        (_PLAYER_CREATE_HAS_TRANSPORT_POSITION, 1),
        (_PLAYER_CREATE_BIT681, 1),
        (_PLAYER_CREATE_HAS_STATIONARY_POSITION, 1),
        (1 if player_guid_bytes[2] else 0, 1),
        (_PLAYER_CREATE_BIT140, 1),
        (0 if bool(state["has_pitch"]) else 1, 1),
        (1 if transport is not None else _PLAYER_CREATE_HAS_TRANSPORT_DATA, 1),
        (0, 1),  # fake bit
    ]
    if transport is not None:
        bits.extend(
            [
                (transport_masks[4], 1),
                (transport_masks[2], 1),
                (1 if has_time3 else 0, 1),
                (transport_masks[0], 1),
                (transport_masks[1], 1),
                (transport_masks[3], 1),
                (transport_masks[6], 1),
                (transport_masks[7], 1),
                (1 if has_time2 else 0, 1),
                (transport_masks[5], 1),
            ]
        )
    bits.extend([
        (0 if bool(state["has_timestamp"]) else 1, 1),
        (1 if player_guid_bytes[6] else 0, 1),
        (1 if player_guid_bytes[4] else 0, 1),
        (1 if player_guid_bytes[3] else 0, 1),
        (0 if bool(state["has_orientation"]) else 1, 1),
        (0 if int(state["movement_counter"]) else 1, 1),
        (1 if player_guid_bytes[5] else 0, 1),
        (_PLAYER_CREATE_BITS98, 22),
        (0 if bool(state["has_movement_flags"]) else 1, 1),
        (_PLAYER_CREATE_BITS168, 19),
        (1 if bool(state["has_fall_data"]) else 0, 1),
    ])
    if bool(state["has_movement_flags"]):
        bits.append((int(state["movement_flags"]) & 0x3FFFFFFF, 30))
    bits.extend([
        (0 if bool(state["has_spline_elevation"]) else 1, 1),
        (_PLAYER_CREATE_HAS_SPLINE_DATA, 1),
        (_PLAYER_CREATE_BIT141, 1),
        (1 if player_guid_bytes[0] else 0, 1),
        (1 if player_guid_bytes[7] else 0, 1),
        (1 if player_guid_bytes[1] else 0, 1),
    ])
    bits.append((0 if bool(state["has_movement_flags2"]) else 1, 1))
    if bool(state["has_fall_data"]):
        bits.append((1 if bool(state["has_fall_direction"]) else 0, 1))
    if bool(state["has_movement_flags2"]):
        bits.append((int(state["movement_flags2"]) & 0x1FFF, 13))
    return _pack_msb_bits(bits)


def _build_legacy_player_create_movement_header() -> bytes:
    """Build the stable pre-experiment CreateObject movement header/speed region."""
    header_bits = _pack_msb_bits([
        (_PLAYER_CREATE_BIT676, 1),
        (_PLAYER_CREATE_HAS_ANIM_KITS, 1),
        (_PLAYER_CREATE_IS_LIVING, 1),
        (_PLAYER_CREATE_BIT810, 1),
        (0, 1),  # fake bit
        (_PLAYER_CREATE_TRANSPORT_FRAMES, 22),
        (_PLAYER_CREATE_HAS_VEHICLE_DATA, 1),
        (_PLAYER_CREATE_BIT1044, 1),
        (0, 1),  # fake bit
        (_PLAYER_CREATE_BIT476, 1),
        (_PLAYER_CREATE_HAS_GAMEOBJECT_ROTATION, 1),
        (0, 1),  # fake bit
        (_PLAYER_CREATE_BIT680, 1),
        (_PLAYER_CREATE_HAS_ATTACKING_TARGET, 1),
        (_PLAYER_CREATE_HAS_SCENE_OBJECT_DATA, 1),
        (_PLAYER_CREATE_BIT1064, 1),
        (0, 1),  # fake bit
        (_PLAYER_CREATE_BIT668, 1),
        (_PLAYER_CREATE_HAS_TRANSPORT_POSITION, 1),
        (_PLAYER_CREATE_BIT681, 1),
        (_PLAYER_CREATE_HAS_STATIONARY_POSITION, 1),
        (_PLAYER_CREATE_GUID_BIT_2, 1),
        (_PLAYER_CREATE_BIT140, 1),
        (0 if _PLAYER_CREATE_HAS_PITCH else 1, 1),
        (_PLAYER_CREATE_HAS_TRANSPORT_DATA, 1),
        (0, 1),  # fake bit
        (0 if _PLAYER_CREATE_HAS_TIMESTAMP else 1, 1),
        (_PLAYER_CREATE_GUID_BIT_6, 1),
        (_PLAYER_CREATE_GUID_BIT_4, 1),
        (_PLAYER_CREATE_GUID_BIT_3, 1),
        (0 if _PLAYER_CREATE_HAS_ORIENTATION else 1, 1),
        (0 if _PLAYER_CREATE_BIT160 else 1, 1),
        (_PLAYER_CREATE_GUID_BIT_5, 1),
        (_PLAYER_CREATE_BITS98, 22),
        (0 if _PLAYER_CREATE_HAS_MOVEMENT_FLAGS else 1, 1),
        (_PLAYER_CREATE_BITS168, 19),
        (_PLAYER_CREATE_HAS_FALL_DATA, 1),
        (0 if _PLAYER_CREATE_HAS_SPLINE_ELEVATION else 1, 1),
        (_PLAYER_CREATE_HAS_SPLINE_DATA, 1),
        (_PLAYER_CREATE_BIT141, 1),
        (_PLAYER_CREATE_GUID_BIT_0, 1),
        (_PLAYER_CREATE_GUID_BIT_7, 1),
        (_PLAYER_CREATE_GUID_BIT_1, 1),
        (0 if _PLAYER_CREATE_HAS_MOVEMENT_FLAGS_EXTRA else 1, 1),
    ])
    if len(header_bits) != _PLAYER_CREATE_MOVEMENT_HEADER_BITS_SIZE:
        raise ValueError("player create movement header size mismatch")

    output = bytearray(header_bits)
    output.extend(struct.pack("<f", _PLAYER_CREATE_FLY_SPEED))
    output.extend(struct.pack("<f", _PLAYER_CREATE_TURN_SPEED))
    output.extend(struct.pack("<f", _PLAYER_CREATE_SWIM_SPEED))
    output.extend(struct.pack("<f", _PLAYER_CREATE_PITCH_SPEED))
    return bytes(output)


def _build_skyfire_player_create_movement_header(
    ctx=None,
    player: Player | None = None,
) -> bytes:
    """Build the SkyFire 5.4.8 CREATE_OBJECT living movement pre-position region."""
    transport = _player_create_transport_data(ctx) if ctx is not None else None
    transport_guid_bytes = (
        int(transport["guid"]).to_bytes(8, "little", signed=False)
        if transport is not None
        else bytes(8)
    )
    has_time2 = bool(transport and int(transport["time2"]) != 0)
    has_time3 = bool(transport and int(transport["time3"]) != 0)
    output = bytearray(_build_player_create_movement_bits(ctx, player))
    if transport is not None:
        def append_guid_byte(index: int) -> None:
            output.extend(_guid_byte_seq(transport_guid_bytes, index))

        append_guid_byte(7)
        output.extend(struct.pack("<f", float(transport["x"])))
        if has_time3:
            output.extend(struct.pack("<I", int(transport["time3"])))
        output.extend(struct.pack("<f", normalize_orientation(transport["orientation"])))
        output.extend(struct.pack("<f", float(transport["y"])))
        append_guid_byte(4)
        append_guid_byte(1)
        append_guid_byte(3)
        output.extend(struct.pack("<f", float(transport["z"])))
        append_guid_byte(5)
        if has_time2:
            output.extend(struct.pack("<I", int(transport["time2"])))
        append_guid_byte(0)
        output.extend(struct.pack("<b", int(transport["seat"])))
        append_guid_byte(6)
        append_guid_byte(2)
        output.extend(struct.pack("<I", int(transport["time"])))
    return bytes(output)


def build_player_create_movement_header(
    ctx=None,
    player: Player | None = None,
) -> bytes:
    """Build the active player CREATE_OBJECT movement header.

    The SkyFire living-movement port is experimental because the normal
    no-transport login path must retain the known-good 826-byte payload.
    """
    if _experimental_player_create_living_movement_enabled():
        return _build_skyfire_player_create_movement_header(ctx, player)
    return _build_legacy_player_create_movement_header()


def build_skyfire_player_create_living_movement_block(
    ctx,
    player: Player | None = None,
) -> bytes:
    """Build the player CREATE_OBJECT living movement block in SkyFire 5.4.8 order."""
    state = _player_create_movement_state(ctx, player)
    player_guid = _resolve_player_create_movement_guid(ctx, player)
    player_guid_bytes = int(player_guid).to_bytes(8, "little", signed=False)
    output = bytearray(_build_skyfire_player_create_movement_header(ctx, player))

    output.extend(_guid_byte_seq(player_guid_bytes, 4))
    # Player CREATE has no spline payload for the local player in the current path.
    output.extend(struct.pack("<f", _movement_float(ctx, "fly_speed", default=_PLAYER_CREATE_FLY_SPEED)))
    movement_counter = int(state["movement_counter"])
    if movement_counter:
        output.extend(struct.pack("<I", movement_counter & 0xFFFFFFFF))
    output.extend(_guid_byte_seq(player_guid_bytes, 2))

    if bool(state["has_fall_data"]):
        if bool(state["has_fall_direction"]):
            output.extend(struct.pack("<f", float(state["fall_xyspeed"])))
            output.extend(struct.pack("<f", float(state["fall_cos"])))
            output.extend(struct.pack("<f", float(state["fall_sin"])))
        output.extend(struct.pack("<I", int(state["fall_time"]) & 0xFFFFFFFF))
        output.extend(struct.pack("<f", float(state["fall_zspeed"])))

    output.extend(_guid_byte_seq(player_guid_bytes, 1))
    output.extend(struct.pack("<f", _movement_float(ctx, "turn_speed", default=_PLAYER_CREATE_TURN_SPEED)))
    if bool(state["has_timestamp"]):
        output.extend(struct.pack("<I", int(state["timestamp"]) & 0xFFFFFFFF))
    output.extend(struct.pack("<f", _movement_float(ctx, "run_back_speed", default=_PLAYER_CREATE_RUN_BACK_SPEED)))
    if bool(state["has_spline_elevation"]):
        output.extend(struct.pack("<f", float(state["spline_elevation"])))

    output.extend(_guid_byte_seq(player_guid_bytes, 7))
    output.extend(struct.pack("<f", _movement_float(ctx, "pitch_speed", default=_PLAYER_CREATE_PITCH_SPEED)))
    output.extend(struct.pack(
        "<f",
        float(player.x) if player is not None else float(getattr(ctx, "x", 0.0) or 0.0),
    ))
    if bool(state["has_pitch"]):
        output.extend(struct.pack("<f", float(state["pitch"])))
    if bool(state["has_orientation"]):
        output.extend(struct.pack("<f", normalize_orientation(state["orientation"])))

    output.extend(struct.pack("<f", _movement_float(ctx, "walk_speed", default=_PLAYER_CREATE_WALK_SPEED)))
    output.extend(struct.pack(
        "<f",
        float(player.y) if player is not None else float(getattr(ctx, "y", 0.0) or 0.0),
    ))
    output.extend(struct.pack("<f", _movement_float(ctx, "fly_back_speed", default=_PLAYER_CREATE_FLY_BACK_SPEED)))
    output.extend(_guid_byte_seq(player_guid_bytes, 3))
    output.extend(_guid_byte_seq(player_guid_bytes, 5))
    output.extend(_guid_byte_seq(player_guid_bytes, 6))
    output.extend(_guid_byte_seq(player_guid_bytes, 0))
    output.extend(struct.pack("<f", _movement_float(ctx, "swim_back_speed", default=_PLAYER_CREATE_SWIM_BACK_SPEED)))
    output.extend(struct.pack("<f", _movement_float(ctx, "run_speed", default=_PLAYER_CREATE_RUN_SPEED)))
    output.extend(struct.pack("<f", _movement_float(ctx, "swim_speed", default=_PLAYER_CREATE_SWIM_SPEED)))
    output.extend(struct.pack(
        "<f",
        float(player.z) if player is not None else float(getattr(ctx, "z", 0.0) or 0.0),
    ))
    if _player_create_transport_data(ctx) is None and len(output) != _PLAYER_CREATE_MOVEMENT_BLOCK_SIZE:
        raise ValueError("player create movement block size mismatch")
    return bytes(output)


def build_movement_block(ctx, player: Player | None = None) -> bytes:
    """Build the player CREATE_OBJECT movement block.

    Default: stable pre-experiment no-transport layout used by ordinary login.
    Experiment: SkyFire 5.4.8 living movement serializer.
    """
    if _player_create_transport_data(ctx) is not None:
        return build_skyfire_player_create_living_movement_block(ctx, player)
    if _experimental_player_create_living_movement_enabled():
        return build_skyfire_player_create_living_movement_block(ctx, player)

    output = bytearray(_build_legacy_player_create_movement_header())
    output.extend(struct.pack(
        "<f",
        float(player.x) if player is not None else float(getattr(ctx, "x", 0.0) or 0.0),
    ))
    output.extend(struct.pack(
        "<f",
        normalize_orientation(player.orientation)
        if player is not None
        else normalize_orientation(getattr(ctx, "orientation", 0.0) or 0.0),
    ))
    output.extend(struct.pack("<f", _PLAYER_CREATE_WALK_SPEED))
    output.extend(struct.pack(
        "<f",
        float(player.y) if player is not None else float(getattr(ctx, "y", 0.0) or 0.0),
    ))
    output.extend(struct.pack("<f", _PLAYER_CREATE_FLY_BACK_SPEED))
    output.append(_PLAYER_CREATE_MOVEMENT_GUID_BYTE)
    output.extend(struct.pack("<f", _PLAYER_CREATE_RUN_BACK_SPEED))
    output.extend(struct.pack("<f", _PLAYER_CREATE_RUN_SPEED))
    output.extend(struct.pack("<f", _PLAYER_CREATE_SWIM_BACK_SPEED))
    output.extend(struct.pack(
        "<f",
        float(player.z) if player is not None else float(getattr(ctx, "z", 0.0) or 0.0),
    ))
    if len(output) != _PLAYER_CREATE_MOVEMENT_BLOCK_SIZE:
        raise ValueError("player create movement block size mismatch")
    return bytes(output)


def build_player_field_values(
    ctx,
    player: Player | None = None,
) -> dict[int, int]:
    """Build the current server-side player field mapping for value updates."""
    guid = _resolve_player_guid(ctx, player)
    race = int(getattr(ctx, "race", 0) or 0)
    class_id = int(getattr(ctx, "player_class", 0) or getattr(ctx, "class_id", 0) or 0)
    gender = int(getattr(ctx, "gender", 0) or 0)
    health = int(getattr(ctx, "health", 103) or 103)
    max_health = int(getattr(ctx, "max_health", health) or health)
    power_primary = int(getattr(ctx, "power_primary", 100) or 100)
    max_power = int(getattr(ctx, "max_power", 40) or 40)
    level = int(getattr(ctx, "level", 1) or 1)
    faction = _resolve_player_faction_template(ctx)
    display_id = _resolve_player_display_id(ctx)
    default_player_bytes = int(getattr(ctx, "player_bytes", 198401) or 198401)
    default_player_bytes_2 = int(getattr(ctx, "player_bytes2", 16777224) or 16777224)
    default_player_bytes_3 = int(
        getattr(ctx, "player_bytes3", _PLAYER_BYTES_3_DEFAULT) or _PLAYER_BYTES_3_DEFAULT
    )
    default_skin, default_face, default_hair_style, default_hair_color = _unpack_u8x4(default_player_bytes)
    default_facial_hair, _, _, _ = _unpack_u8x4(default_player_bytes_2)
    skin = int(getattr(ctx, "skin", default_skin) or default_skin)
    face = int(getattr(ctx, "face", default_face) or default_face)
    hair_style = int(getattr(ctx, "hair_style", default_hair_style) or default_hair_style)
    hair_color = int(getattr(ctx, "hair_color", default_hair_color) or default_hair_color)
    facial_hair = int(getattr(ctx, "facial_hair", default_facial_hair) or default_facial_hair)
    player_bytes = _pack_u8x4(skin, face, hair_style, hair_color)
    player_bytes_2 = _pack_u8x4(facial_hair, 0, 0, gender)
    player_bytes_3 = _pack_u8x4(gender, 0, 0, 0)
    max_level = int(getattr(ctx, "max_level", _PLAYER_MAX_LEVEL_DEFAULT) or _PLAYER_MAX_LEVEL_DEFAULT)
    money = int(getattr(ctx, "money", 0) or 0) & 0xFFFFFFFFFFFFFFFF
    chosen_title = int(getattr(ctx, "chosen_title", 0) or 0)
    mount_display_id = int(getattr(ctx, "mount_display_id", _PLAYER_MOUNT_DISPLAY_ID) or _PLAYER_MOUNT_DISPLAY_ID)
    unit_flags = _PLAYER_FLAGS
    if mount_display_id > 0:
        unit_flags |= _PLAYER_FLAGS_MOUNTED

    field_values = dict(_PLAYER_CREATE_REFERENCE_DERIVED_FIELDS)
    field_values.update(_PLAYER_CREATE_NAMED_DEFAULT_FIELDS)
    field_values.update(_PLAYER_CREATE_POWER_REGEN_DEFAULT_FIELDS)
    field_values.update(_PLAYER_CREATE_UNIT_MISC_DEFAULT_FIELDS)
    field_values.update(_PLAYER_CREATE_BASE_STAT_FIELDS)
    field_values.update(_PLAYER_CREATE_BASE_POWER_HEALTH_FIELDS)
    field_values.update(_PLAYER_CREATE_EXPLORATION_DEFAULT_FIELDS)
    field_values.update(_PLAYER_CREATE_RESTED_DEFAULT_FIELDS)
    field_values.update(_PLAYER_CREATE_LANGUAGE_RIDING_DEFAULT_FIELDS)
    field_values.update(_PLAYER_CREATE_COMBAT_DEFAULT_FIELDS)
    field_values.update(_PLAYER_CREATE_RATING_DEFAULT_FIELDS)
    field_values.update(_PLAYER_CREATE_MODIFIER_DEFAULT_FIELDS)
    field_values.update(_PLAYER_CREATE_GLYPH_SLOT_DEFAULT_FIELDS)
    field_values.update(
        {
            _OBJECT_FIELD_GUID_LOW: int(guid) & 0xFFFFFFFF,
            _OBJECT_FIELD_TYPE: _PLAYER_OBJECT_TYPE,
            _OBJECT_FIELD_SCALE_X: _u32_from_float(
                float(player.scale) if player is not None else _PLAYER_SCALE_X
            ),
            30: _pack_u8x4(race, class_id, 0, gender),
            _UNIT_FIELD_HEALTH: health,
            _UNIT_FIELD_POWER_PRIMARY: power_primary,
            _UNIT_FIELD_MAX_HEALTH: max_health,
            40: max_power,
            _UNIT_FIELD_LEVEL: level,
            _UNIT_FIELD_FACTION_TEMPLATE: int(getattr(ctx, "faction_template", faction) or faction),
            _UNIT_FIELD_FLAGS: unit_flags,
            _UNIT_FIELD_FLAGS_2: _PLAYER_FLAGS_2,
            _UNIT_FIELD_BOUNDING_RADIUS: _u32_from_float(_PLAYER_BOUNDING_RADIUS),
            _UNIT_FIELD_COMBAT_REACH: _u32_from_float(_PLAYER_COMBAT_REACH),
            _UNIT_FIELD_DISPLAY_ID: display_id,
            _UNIT_FIELD_NATIVE_DISPLAY_ID: display_id,
            _UNIT_FIELD_MOUNT_DISPLAY_ID: mount_display_id,
            _PLAYER_BYTES: player_bytes,
            _PLAYER_BYTES_2: player_bytes_2,
            _PLAYER_BYTES_3: player_bytes_3,
            _PLAYER_FIELD_PLAYER_TITLE: chosen_title,
            _PLAYER_FIELD_COINAGE: money & 0xFFFFFFFF,
            _PLAYER_FIELD_COINAGE + 1: (money >> 32) & 0xFFFFFFFF,
            _PLAYER_FIELD_MAX_LEVEL: max_level,
        }
    )
    try:
        from server.modules.handlers.world.title_service import normalize_known_titles

        for offset, value in enumerate(normalize_known_titles(getattr(ctx, "known_titles_raw", ""))):
            field_values[_PLAYER_FIELD_KNOWN_TITLES + offset] = int(value)
    except Exception as exc:
        Logger.warning("[Title] failed to add known title fields to player create: %s", exc)

    _patch_language_skill_fields(field_values, ctx)
    for field_index in _BIAS_SENSITIVE_PLAYER_FIELDS:
        assert field_index in field_values
    Logger.info(
        f"[FIELD30] race={race} class={class_id} "
        f"gender={gender} zero_byte=0 "
        f"packed={field_values[30]}"
    )
    Logger.info(f"[FIELD57] faction_template={field_values[57]}")
    Logger.info(
        f"[PLAYER_BYTES] 166={field_values[166]} 167={field_values[167]} 168={field_values[168]}"
    )
    Logger.info(f"[LEVEL FIELD] idx=55 value={field_values[_UNIT_FIELD_LEVEL]}")
    return field_values


def build_create_object_payload(
    ctx,
    player: Player | None = None,
) -> bytes:
    """Build the top-level CREATE_OBJECT payload header without a template."""
    payload = bytearray()
    payload += struct.pack(
        "<H",
        int(player.map_id if player is not None else getattr(ctx, "map_id", 0) or 0)
        & 0xFFFF,
    )
    payload += struct.pack("<I", _PLAYER_CREATE_UPDATE_COUNT)
    payload += struct.pack("<B", _PLAYER_CREATE_UPDATE_TYPE)
    payload += GuidHelper.pack(_resolve_player_low_guid(ctx, player))
    payload += struct.pack("<B", _PLAYER_CREATE_OBJECT_TYPE)
    return bytes(payload)


def build_full_player_create(
    ctx,
    player: Player | None = None,
) -> bytes | None:
    """Build a full player CREATE_OBJECT using a built header plus known body blocks."""
    try:
        movement_block = build_movement_block(ctx, player)
        if (
            _player_create_transport_data(ctx) is None
            and len(movement_block)
            != (_PLAYER_CREATE_MOVEMENT_BLOCK_END - _PLAYER_CREATE_MOVEMENT_BLOCK_START)
        ):
            return None

        srv_values = build_player_field_values(ctx, player)
        if 30 not in srv_values:
            raise ValueError("player create fields missing field 30")
        if _UNIT_FIELD_LEVEL not in srv_values:
            raise ValueError(f"player create fields missing field {_UNIT_FIELD_LEVEL}")
        for field_index in _BIAS_SENSITIVE_PLAYER_FIELDS:
            if field_index not in srv_values:
                raise ValueError(f"player create fields missing field {field_index}")

        mask_bytes, mask_words = build_update_mask(srv_values)
        field_bytes = _serialize_field_values(srv_values)
        Logger.info(f"[MASK BUILD] words={mask_words} fields={len(srv_values)}")

        payload = bytearray(build_create_object_payload(ctx, player))
        payload += movement_block
        payload += struct.pack("<B", int(mask_words) & 0xFF)
        payload += mask_bytes
        payload += field_bytes
        payload += struct.pack("<B", 0)
        built_payload = _patch_language_mask_bytes(bytes(payload), ctx)
        if bool(getattr(ctx, "exact_0002_remote_player", False)):
            remote_payload = bytearray(built_payload)
            if len(remote_payload) > _PLAYER_CREATE_REMOTE_SELF_FLAG_OFFSET:
                remote_payload[_PLAYER_CREATE_REMOTE_SELF_FLAG_OFFSET] &= (
                    ~_PLAYER_CREATE_REMOTE_SELF_FLAG
                ) & 0xFF
            built_payload = bytes(remote_payload)
        assert isinstance(built_payload, (bytes, bytearray))
        assert len(built_payload) > 0
        _verify_player_level_field_in_payload(
            built_payload,
            int(getattr(ctx, "level", 1) or 1),
            movement_block_size=len(movement_block),
        )
        Logger.info(
            f"[CREATE BUILD] guid={getattr(ctx, 'guid', None)} "
            f"type=4 "
            f"mask_words={mask_words} "
            f"fields={len(srv_values)} "
            f"field_bytes={len(field_bytes)} "
            f"size={len(built_payload)}"
        )

        Logger.info(
            f"[CREATE FIELDS] guid={getattr(ctx, 'guid', None)} "
            f"indices={sorted(srv_values.keys())}"
        )
        return built_payload
    except Exception as exc:
        Logger.warning(f"[PLAYER CREATE] direct build failed: {exc}")
        return None


def build_server_built_player_create(
    ctx,
    player: Player | None = None,
) -> bytes | None:
    """Build player CREATE_OBJECT from the single server-built runtime path."""
    Logger.info("[CREATE_OBJECT] server-built only path active")
    return build_full_player_create(ctx, player)


def build_server_built_minimal_player_value_update(
    ctx,
    player: Player | None = None,
) -> bytes | None:
    """Build a minimal server-built player UPDATE_OBJECT value-update packet."""
    guid = _resolve_player_guid(ctx, player)
    if guid <= 0:
        Logger.warning("[PLAYER UPDATE_OBJECT] server-built experimental path skipped: missing guid")
        return None

    map_id = int(
        player.map_id if player is not None else getattr(ctx, "map_id", 0) or 0
    )

    # server-built experimental path
    field_values = build_player_field_values(ctx, player)

    Logger.info(
        "[PLAYER UPDATE_OBJECT] server-built experimental path active map_id=%s guid=0x%X",
        map_id,
        guid,
    )
    return build_multi_u32_update_object_payload(
        map_id=map_id,
        guid=guid,
        field_updates=sorted(field_values.items()),
    )


def unpack_guid(mask: int, data: bytes) -> int:
    guid_bytes = [0] * 8
    offset = 0

    for bit in range(8):
        if mask & (1 << bit):
            if offset >= len(data):
                raise ValueError("packed guid data shorter than mask indicates")
            guid_bytes[bit] = data[offset]
            offset += 1

    return int.from_bytes(bytes(guid_bytes), "little", signed=False)


def extract_first_update_object_guid_info(payload: bytes) -> tuple[int, int, bytes] | None:
    if len(payload) < 8:
        return None

    update_count = struct.unpack_from("<I", payload, 2)[0]
    if update_count <= 0:
        return None

    offset = 6
    update_type = payload[offset]
    offset += 1

    if update_type == 3:
        if offset + 4 > len(payload):
            return None
        out_of_range_count = struct.unpack_from("<I", payload, offset)[0]
        offset += 4
        if out_of_range_count <= 0:
            return None

    if offset >= len(payload):
        return None

    mask = payload[offset]
    offset += 1
    packed_len = int(mask).bit_count()
    if offset + packed_len > len(payload):
        return None

    packed_guid_bytes = payload[offset : offset + packed_len]
    return unpack_guid(mask, packed_guid_bytes), int(mask), packed_guid_bytes


def _current_session():
    return runtime_session


def debug_log_replayed_update_object_guid(payload: bytes, update_index: int | None = None) -> None:
    session = _current_session()
    session_player_guid = int(
        getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or 0
    )
    if session_player_guid <= 0:
        return

    try:
        guid_info = extract_first_update_object_guid_info(payload)
    except Exception as exc:
        Logger.warning(f"[GUID DEBUG] failed to decode packed guid: {exc}")
        return

    if guid_info is None:
        Logger.warning("[GUID DEBUG] no packed guid found in SMSG_UPDATE_OBJECT")
        return

    packet_guid, guid_mask, packed_guid_bytes = guid_info
    packed_guid_bytes_display = "[" + " ".join(f"{byte:02X}" for byte in packed_guid_bytes) + "]"
    Logger.info(
        "[GUID DEBUG]\n"
        f"update_index = {update_index if update_index is not None else -1}\n"
        f"mask = 0x{guid_mask:02X}\n"
        f"raw_sniffed_guid_bytes = {packed_guid_bytes_display}\n"
        f"reconstructed = 0x{packet_guid:016X}\n"
        f"session_player_guid = 0x{session_player_guid:016X}"
    )
    if packet_guid != session_player_guid:
        Logger.debug("[GUID MISMATCH] UPDATE_OBJECT GUID does not match session player GUID.")


def debug_verify_update_object_guid(payload: bytes) -> None:
    session = _current_session()
    expected = int(
        getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or 0
    )
    if expected <= 0:
        return

    try:
        guid_info = extract_first_update_object_guid_info(payload)
    except Exception as exc:
        Logger.warning(f"[GUID CHECK] failed to decode packed guid: {exc}")
        return

    if guid_info is None:
        Logger.warning("[GUID CHECK] no packed guid found in SMSG_UPDATE_OBJECT")
        return
    received, _guid_mask, _packed_guid_bytes = guid_info

    Logger.info(
        "[GUID CHECK]\n"
        f"expected: 0x{expected:X}\n"
        f"received: 0x{received:X}"
    )
    if received != expected:
        Logger.debug("WARNING: Player UPDATE_OBJECT GUID mismatch")


def find_player_living_movement_block(payload: bytes) -> dict[str, float] | None:
    block_size = 13 * 4
    if len(payload) < block_size:
        return None

    for offset in range(0, len(payload) - block_size + 1):
        try:
            (
                fly_speed,
                turn_speed,
                swim_speed,
                pitch_speed,
                x,
                orientation,
                walk_speed,
                y,
                fly_back_speed,
                run_back_speed,
                run_speed,
                swim_back_speed,
                z,
            ) = struct.unpack_from("<13f", payload, offset)
        except struct.error:
            continue

        values = (
            fly_speed,
            turn_speed,
            swim_speed,
            pitch_speed,
            x,
            orientation,
            walk_speed,
            y,
            fly_back_speed,
            run_back_speed,
            run_speed,
            swim_back_speed,
            z,
        )
        if not all(math.isfinite(value) for value in values):
            continue
        if not (6.5 <= run_speed <= 7.5):
            continue
        if not (3.0 <= turn_speed <= 3.3):
            continue
        if not (3.0 <= pitch_speed <= 3.3):
            continue
        if not (2.0 <= walk_speed <= 3.0):
            continue
        if not (4.0 <= run_back_speed <= 5.0):
            continue
        if not (4.0 <= fly_back_speed <= 5.0):
            continue
        if not (-math.pi * 4 <= orientation <= math.pi * 4):
            continue
        if abs(x) > 100000 or abs(y) > 100000 or abs(z) > 100000:
            continue

        return {
            "offset": float(offset),
            "fly_speed": float(fly_speed),
            "turn_speed": float(turn_speed),
            "swim_speed": float(swim_speed),
            "pitch_speed": float(pitch_speed),
            "x": float(x),
            "orientation": float(orientation),
            "walk_speed": float(walk_speed),
            "y": float(y),
            "fly_back_speed": float(fly_back_speed),
            "run_back_speed": float(run_back_speed),
            "run_speed": float(run_speed),
            "swim_back_speed": float(swim_back_speed),
            "z": float(z),
        }

    return None


def debug_log_player_movement_flags(payload: bytes, *, update_index: int | None = None) -> None:
    if update_index != 1:
        return

    movement = find_player_living_movement_block(payload)
    if movement is None:
        Logger.debug("[PLAYER MOVEMENT FLAGS] no living player movement block found in UPDATE_OBJECT")
        return

    Logger.info(
        f"[PLAYER MOVEMENT FLAGS] run={movement['run_speed']:.6f} "
        f"turn={movement['turn_speed']:.6f} pitch={movement['pitch_speed']:.6f}"
    )
    Logger.info(
        f"[PLAYER MOVEMENT CREATE] is_living=1 orientation={movement['orientation']:.6f} "
        f"walk={movement['walk_speed']:.6f} swim={movement['swim_speed']:.6f} "
        f"offset={int(movement['offset'])}"
    )


def build_single_u32_update_object_payload(*, map_id: int, guid: int, field_index: int, value: int) -> bytes:
    return build_multi_u32_update_object_payload(
        map_id=map_id,
        guid=guid,
        field_updates=[(int(field_index), int(value))],
    )


def build_multi_u32_update_object_payload(*, map_id: int, guid: int, field_updates: list[tuple[int, int]]) -> bytes:
    normalized_updates = [(int(field_index), int(value)) for field_index, value in (field_updates or [])]
    if not normalized_updates:
        return bytes(struct.pack("<HI", int(map_id) & 0xFFFF, 0))

    highest_field_index = max(field_index for field_index, _value in normalized_updates)
    mask_words = (highest_field_index // 32) + 1
    mask = bytearray(mask_words * 4)
    values_by_field = {field_index: value for field_index, value in normalized_updates}
    field_bytes = bytearray()

    for field_index in sorted(values_by_field):
        mask_word = int(field_index) // 32
        mask_bit = int(field_index) % 32
        current_word = struct.unpack_from("<I", mask, mask_word * 4)[0]
        struct.pack_into("<I", mask, mask_word * 4, current_word | (1 << mask_bit))

    for field_index in range(mask_words * 32):
        mask_word = field_index // 32
        mask_bit = field_index % 32
        word_value = struct.unpack_from("<I", mask, mask_word * 4)[0]
        if not (word_value & (1 << mask_bit)):
            continue
        field_bytes += struct.pack("<I", int(values_by_field.get(field_index, 0)) & 0xFFFFFFFF)

    payload = bytearray()
    payload += struct.pack("<HI", int(map_id) & 0xFFFF, 1)
    payload += struct.pack("<B", 0)
    payload += GuidHelper.pack(int(guid) & 0xFFFFFFFFFFFFFFFF)
    payload += struct.pack("<B", mask_words)
    payload += bytes(mask)
    payload += bytes(field_bytes)
    payload += struct.pack("<B", 0)
    return bytes(payload)


def make_update_object_response(payload: bytes, *, update_index: int | None = None) -> tuple[str, bytes]:
    debug_log_replayed_update_object_guid(payload, update_index=update_index)
    debug_verify_update_object_guid(payload)
    debug_log_player_movement_flags(payload, update_index=update_index)
    return "SMSG_UPDATE_OBJECT", payload
