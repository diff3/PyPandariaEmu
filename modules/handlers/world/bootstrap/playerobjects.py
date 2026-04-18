from __future__ import annotations

"""Player UPDATE_OBJECT notes for the future server-built implementation.

Known state:
- This module does not build the full player CREATE_OBJECT or full player 0002.
- The current login/bootstrap player object still depends on replay/exact builders
  elsewhere in the world login flow.
- This module currently owns two things:
  1. Small server-built value-update payloads for player fields.
  2. Debug helpers that inspect replayed player UPDATE_OBJECT payloads.

What is already understood:
- Packed GUID extraction for the first UPDATE_OBJECT entry works well enough for
  player guid verification.
- A minimal value-update packet can be built server-side with:
  map_id, update_count, update_type, packed guid, update mask, field values,
  and a trailing zero byte.
- The player replay path contains a living movement block that can be detected
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
- Replayed player UPDATE_OBJECT guid parsing, in wire order:
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
    - data/skyfire548/captures/focus/debug/SMSG_UPDATE_OBJECT_1776451639_0458.json
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
- Replayed living movement block:
  - This block is currently identified heuristically inside the replayed player
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
    - any bytes before or after this block inside the full replayed player
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

Known gaps in field specification:
- The full player CREATE_OBJECT body layout is still unknown.
- The exact field index map for the replayed player 0002 value block is not yet
  documented here.
- The mandatory create flags, movement flags, and object-type-specific layout
  bits for a fully server-built player object are still unresolved.

What is not yet established:
- A full server-built player CREATE_OBJECT layout.
- A complete field map for the player 0002 payload.
- Which player fields are mandatory for a valid first world snapshot versus
  optional follow-up value updates.
- A clean DSL definition for a full player object packet.

Working assumption for the next phase:
- Keep using this module as the place to document confirmed player packet
  structure until the replayed player object can be replaced with a fully
  server-built payload.
"""

import math
import struct

from shared.Logger import Logger
from server.modules.game.guid import GuidHelper
from server.session.runtime import session as runtime_session

USE_SERVER_BUILT_MINIMAL_PLAYER = False
USE_SERVER_BUILT_PLAYER_CREATE = True
USE_SERVER_BUILT_PLAYER_CREATE_DIRECT = True

_PLAYER_CREATE_GUID_MASK_OFFSET = 7
_PLAYER_CREATE_GUID_VALUE_OFFSET = 8
_PLAYER_CREATE_MOVEMENT_BLOCK_START = 10
_PLAYER_CREATE_MOVEMENT_BLOCK_END = 76
_PLAYER_CREATE_MOVEMENT_X_OFFSET = 29
_PLAYER_CREATE_MOVEMENT_O_OFFSET = 33
_PLAYER_CREATE_MOVEMENT_Y_OFFSET = 41
_PLAYER_CREATE_MOVEMENT_Z_OFFSET = 62
_PLAYER_CREATE_OBJECT_TYPE = 4
_PLAYER_CREATE_UPDATE_COUNT = 1
_PLAYER_CREATE_UPDATE_TYPE = 2
_PLAYER_CREATE_CONST_MOVEMENT_BLOCK = bytes.fromhex(
    "200000004009080000080000490000e040e00f494000009040c3f54840"
    "de507d465c57d93f00002040aef47d46000090400f000020400000e040"
    "711c9740fb536c41"
)

_OBJECT_FIELD_GUID_LOW = 0
_OBJECT_FIELD_TYPE = 4
_OBJECT_FIELD_SCALE_X = 7
_UNIT_FIELD_HEALTH = 33
_UNIT_FIELD_POWER_PRIMARY = 34
_UNIT_FIELD_MAX_HEALTH = 39
_UNIT_FIELD_LEVEL = 55
_UNIT_FIELD_FACTION_TEMPLATE = 57
_UNIT_FIELD_FLAGS = 61
_UNIT_FIELD_FLAGS_2 = 62
_UNIT_FIELD_BOUNDING_RADIUS = 67
_UNIT_FIELD_COMBAT_REACH = 68
_UNIT_FIELD_DISPLAY_ID = 69
_UNIT_FIELD_NATIVE_DISPLAY_ID = 70
_UNIT_FIELD_MOUNT_DISPLAY_ID = 71
_PLAYER_BYTES = 166
_PLAYER_BYTES_2 = 167
_PLAYER_BYTES_3 = 168
_PLAYER_FIELD_MAX_LEVEL = 1943
_LANG_SKILL_ID_FIELD = 1154
_LANG_SKILL_VALUE_FIELD = 1282
_LANG_SKILL_MAX_FIELD = 1410
_SKILL_RIDING = 762
_SKILL_LANGUAGE_RANK = 300
_SKILL_RIDING_RANK = 375
_LANGUAGE_MASK_COMMON = (1 << 7).to_bytes(4, "little")
_LANGUAGE_MASK_ORCISH = (1 << 1).to_bytes(4, "little")

_VERIFIED_PLAYER_REFERENCE_FIELDS = {
    6: 0,
    26: 0,
    27: 0,
    28: 0,
    30: 16780036,
    36: 100,
    40: 40,
    41: 1000,
    42: 100,
    43: 100,
    45: 1066639324,
    50: 1042536202,
    64: 2000,
    65: 2000,
    66: 2000,
    72: 1074341010,
    73: 1078535314,
    81: 1065353216,
    82: 1065353216,
    83: 1065353216,
    84: 1065353216,
    90: 18,
    91: 25,
    92: 19,
    93: 22,
    94: 22,
    126: 40,
    127: 83,
    129: 8,
    137: 1065353216,
    138: 1073741824,
    154: 1065353216,
    961: 1,
    1152: 400,
    1153: 6225974,
    1154: 7405666,
    1155: 10485896,
    1156: 11337890,
    1157: 27132133,
    1158: 30998943,
    1159: 798,
    1281: 65537,
    1282: 19661100,
    1283: 65537,
    1284: 65537,
    1285: 65537,
    1286: 65537,
    1287: 5,
    1409: 327685,
    1410: 19661100,
    1411: 327685,
    1412: 327685,
    1413: 65541,
    1414: 327681,
    1415: 5,
    1610: 1095173714,
    1612: 1093282693,
    1613: 1093282693,
    1614: 1093282693,
    1616: 1084224438,
    1617: 1084224438,
    1618: 1084224438,
    1619: 1084224438,
    1620: 1084224438,
    1621: 1084224438,
    1622: 30,
    1624: 1090519040,
    1648: 8,
    1827: 65,
    1829: 12,
    1830: 12,
    1831: 12,
    1832: 12,
    1833: 12,
    1834: 12,
    1842: 1065353216,
    1843: 1065353216,
    1844: 1065353216,
    1845: 1065353216,
    1846: 1065353216,
    1847: 1065353216,
    1848: 1065353216,
    1849: 12,
    1850: 1065353216,
    1851: 1065353216,
    1853: 1065353216,
    1856: 1065353216,
    1952: 21,
    1953: 22,
    1954: 23,
    1955: 24,
    1956: 25,
    1957: 26,
}

_PLAYER_OBJECT_TYPE = 25
_PLAYER_SCALE_X = 1.0
_PLAYER_FLAGS = 8
_PLAYER_FLAGS_2 = 2048
_PLAYER_BOUNDING_RADIUS = 0.389
_PLAYER_COMBAT_REACH = 1.5
_PLAYER_MOUNT_DISPLAY_ID = 0
_PLAYER_BYTES_3_DEFAULT = 1
_PLAYER_MAX_LEVEL_DEFAULT = 90

_PLAYER_DISPLAY_IDS = {
    1: {0: 49, 1: 50},
    2: {0: 51, 1: 52},
    3: {0: 53, 1: 54},
    4: {0: 55, 1: 56},
    5: {0: 57, 1: 58},
    6: {0: 59, 1: 60},
    7: {0: 1563, 1: 1564},
    8: {0: 1478, 1: 1479},
    9: {0: 6894, 1: 6895},
    10: {0: 15476, 1: 15475},
    11: {0: 16125, 1: 16126},
}

_PLAYER_FACTION_TEMPLATE_IDS = {
    1: 1,
    2: 2,
    3: 3,
    4: 4,
    5: 5,
    6: 6,
    7: 115,
    8: 116,
    9: 2204,
    10: 1610,
    11: 1629,
}

_ALLIANCE_RACES = {1, 3, 4, 7, 11, 22, 25}
_HORDE_RACES = {2, 5, 6, 8, 9, 10, 26}
_ALLIANCE_FACTION_TEMPLATES = frozenset(
    int(_PLAYER_FACTION_TEMPLATE_IDS[race]) for race in _ALLIANCE_RACES if race in _PLAYER_FACTION_TEMPLATE_IDS
)
_HORDE_FACTION_TEMPLATES = frozenset(
    int(_PLAYER_FACTION_TEMPLATE_IDS[race]) for race in _HORDE_RACES if race in _PLAYER_FACTION_TEMPLATE_IDS
)
_LANGUAGE_SKILL_COMMON = 98
_LANGUAGE_SKILL_ORCISH = 109
_RACIAL_LANGUAGE_SKILL_BY_RACE = {
    1: 113,
    2: 109,
    3: 111,
    4: 113,
    5: 110,
    6: 114,
    7: 115,
    8: 116,
    10: 139,
    11: 113,
}
_BIAS_SENSITIVE_PLAYER_FIELDS = (57, 166, 167, 168, 1943)


def _u32_from_float(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", float(value)))[0]


def _resolve_player_guid(ctx) -> int:
    return int(
        getattr(ctx, "world_guid", 0)
        or getattr(ctx, "player_guid", 0)
        or getattr(ctx, "char_guid", 0)
        or 0
    )


def _resolve_player_low_guid(ctx) -> int:
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
    """Mirror the old replay language-mask patch inside the new player create path."""
    team = _resolve_player_team(ctx)
    if team == "alliance":
        target_bytes = _LANGUAGE_MASK_COMMON
    elif team == "horde":
        target_bytes = _LANGUAGE_MASK_ORCISH
    else:
        return bytes(payload)

    return bytes(payload).replace(_LANGUAGE_MASK_ORCISH, target_bytes)


def _apply_legacy_language_riding_skill_block(
    field_values: dict[int, int],
    *,
    primary_language: int,
    racial_language: int,
) -> None:
    """Mirror the old working barncastle language/riding skill block exactly."""
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
    mask_words_list = [0] * mask_words

    for field_index in field_values:
        word_index = int(field_index) // 32
        bit_index = int(field_index) % 32
        mask_words_list[word_index] |= 1 << bit_index

    mask_bytes = b"".join(struct.pack("<I", int(word_value) & 0xFFFFFFFF) for word_value in mask_words_list)
    return mask_bytes, mask_words


def _serialize_field_values(field_values: dict[int, int]) -> bytes:
    """Serialize CREATE_OBJECT fields in ascending field-index order."""
    payload = bytearray()
    for field_index in sorted(field_values):
        payload += struct.pack("<I", int(field_values[field_index]) & 0xFFFFFFFF)
    return bytes(payload)


def _read_u32_field_value(field_indices: list[int], field_bytes: bytes, field_index: int) -> int:
    """Read one uint32 field value from packed CREATE_OBJECT field bytes."""
    offset = 0
    for current_index in field_indices:
        if current_index == field_index:
            return struct.unpack_from("<I", field_bytes, offset)[0]
        offset += 4
    raise ValueError(f"missing field {field_index}")


def _verify_player_level_field_in_payload(payload: bytes, expected_level: int) -> None:
    """Ensure CREATE_OBJECT includes the level field and that it matches ctx.level."""
    mask_start, mask_end, mask_blocks = locate_mask_region(payload)
    field_start, field_end = locate_field_region(payload)
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


def _write_float_le(buffer: bytearray, offset: int, value: float) -> None:
    struct.pack_into("<f", buffer, int(offset), float(value))


def build_movement_block(ctx) -> bytes:
    """Build the player CREATE_OBJECT movement block from code-only constants."""
    output = bytearray(_PLAYER_CREATE_CONST_MOVEMENT_BLOCK)
    _write_float_le(output, _PLAYER_CREATE_MOVEMENT_X_OFFSET, float(getattr(ctx, "x", 0.0) or 0.0))
    _write_float_le(output, _PLAYER_CREATE_MOVEMENT_Y_OFFSET, float(getattr(ctx, "y", 0.0) or 0.0))
    _write_float_le(output, _PLAYER_CREATE_MOVEMENT_Z_OFFSET, float(getattr(ctx, "z", 0.0) or 0.0))
    _write_float_le(output, _PLAYER_CREATE_MOVEMENT_O_OFFSET, float(getattr(ctx, "orientation", 0.0) or 0.0))
    return bytes(output)


def build_player_field_values(ctx) -> dict[int, int]:
    """Build the current server-side player field mapping for value updates."""
    guid = _resolve_player_guid(ctx)
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

    field_values = dict(_VERIFIED_PLAYER_REFERENCE_FIELDS)
    field_values.update(
        {
            _OBJECT_FIELD_GUID_LOW: int(guid) & 0xFFFFFFFF,
            _OBJECT_FIELD_TYPE: _PLAYER_OBJECT_TYPE,
            _OBJECT_FIELD_SCALE_X: _u32_from_float(_PLAYER_SCALE_X),
            30: _pack_u8x4(race, class_id, 0, gender),
            _UNIT_FIELD_HEALTH: health,
            _UNIT_FIELD_POWER_PRIMARY: power_primary,
            _UNIT_FIELD_MAX_HEALTH: max_health,
            40: max_power,
            _UNIT_FIELD_LEVEL: level,
            _UNIT_FIELD_FACTION_TEMPLATE: int(getattr(ctx, "faction_template", faction) or faction),
            _UNIT_FIELD_FLAGS: _PLAYER_FLAGS,
            _UNIT_FIELD_FLAGS_2: _PLAYER_FLAGS_2,
            _UNIT_FIELD_BOUNDING_RADIUS: _u32_from_float(_PLAYER_BOUNDING_RADIUS),
            _UNIT_FIELD_COMBAT_REACH: _u32_from_float(_PLAYER_COMBAT_REACH),
            _UNIT_FIELD_DISPLAY_ID: display_id,
            _UNIT_FIELD_NATIVE_DISPLAY_ID: display_id,
            _UNIT_FIELD_MOUNT_DISPLAY_ID: _PLAYER_MOUNT_DISPLAY_ID,
            _PLAYER_BYTES: player_bytes,
            _PLAYER_BYTES_2: player_bytes_2,
            _PLAYER_BYTES_3: player_bytes_3,
            _PLAYER_FIELD_MAX_LEVEL: max_level,
        }
    )
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


def build_create_object_payload(ctx) -> bytes:
    """Build the top-level CREATE_OBJECT payload header without a template."""
    payload = bytearray()
    payload += struct.pack("<H", int(getattr(ctx, "map_id", 0) or 0) & 0xFFFF)
    payload += struct.pack("<I", _PLAYER_CREATE_UPDATE_COUNT)
    payload += struct.pack("<B", _PLAYER_CREATE_UPDATE_TYPE)
    payload += GuidHelper.pack(_resolve_player_low_guid(ctx))
    payload += struct.pack("<B", _PLAYER_CREATE_OBJECT_TYPE)
    return bytes(payload)


def build_full_player_create(ctx) -> bytes | None:
    """Build a full player CREATE_OBJECT using a built header plus known body blocks."""
    try:
        movement_block = build_movement_block(ctx)
        if len(movement_block) != (_PLAYER_CREATE_MOVEMENT_BLOCK_END - _PLAYER_CREATE_MOVEMENT_BLOCK_START):
            return None

        srv_values = build_player_field_values(ctx)
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

        payload = bytearray(build_create_object_payload(ctx))
        payload += movement_block
        payload += struct.pack("<B", int(mask_words) & 0xFF)
        payload += mask_bytes
        payload += field_bytes
        payload += struct.pack("<B", 0)
        built_payload = _patch_language_mask_bytes(bytes(payload), ctx)
        assert isinstance(built_payload, (bytes, bytearray))
        assert len(built_payload) > 0
        _verify_player_level_field_in_payload(
            built_payload,
            int(getattr(ctx, "level", 1) or 1),
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


def build_server_built_player_create(ctx) -> bytes | None:
    """Build player CREATE_OBJECT from the single server-built runtime path."""
    Logger.info("[CREATE_OBJECT] server-built only path active")
    return build_full_player_create(ctx)


def build_server_built_minimal_player_value_update(ctx) -> bytes | None:
    """Build a minimal server-built player UPDATE_OBJECT value-update packet."""
    guid = _resolve_player_guid(ctx)
    if guid <= 0:
        Logger.warning("[PLAYER UPDATE_OBJECT] server-built experimental path skipped: missing guid")
        return None

    map_id = int(getattr(ctx, "map_id", 0) or 0)

    # server-built experimental path
    field_values = build_player_field_values(ctx)

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
