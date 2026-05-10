from __future__ import annotations

import json
from pathlib import Path
import struct
from typing import Any, Optional

from shared.Logger import Logger
from server.modules.protocol.PacketContext import PacketContext
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.handlers.world.login.context import WorldLoginContext
from server.modules.handlers.world.login.packets import build_login_packet
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from server.modules.handlers.world.bootstrap.replay import (
    build_multi_u32_update_object_payload,
)
from server.modules.handlers.world.dispatcher import register
from server.modules.handlers.world.opcodes.movement import (
    build_move_set_can_fly_payload,
    build_move_set_flight_speed_payload,
    build_move_set_run_speed_payload,
    build_move_set_speed_payload,
    resync_movement,
)
from server.modules.handlers.world.mount.mount_service import (
    ALL_MOUNT_SPELLS,
    get_mount_display_id,
    granted_mount_spells,
    is_flying_mount_spell,
    is_mount_spell,
)
from DSL.modules.bitsHandler import BitWriter

from server.modules.game import player

_ALLIANCE_RACES = {1, 3, 4, 7, 11, 22, 25}
_HORDE_RACES = {2, 5, 6, 8, 9, 10, 24, 26}
_BASE_LANGUAGE_SPELL_BY_RACE = {
    1: 668,       # Human -> Common
    2: 669,       # Orc -> Orcish
    24: 669,      # Pandaren Neutral -> Orcish fallback
    25: 668,      # Pandaren Alliance -> Common
    26: 669,      # Pandaren Horde -> Orcish
}
_RACE_LANGUAGE_SPELL_BY_RACE = {
    1: 668,
    2: 669,
    3: 672,
    4: 671,
    5: 17737,
    6: 670,
    7: 7340,
    8: 7341,
    10: 813,
    11: 29932,
    22: 69269,
    24: 669,
    25: 108130,
    26: 108131,
}
_ALL_LANGUAGE_SPELL_IDS = frozenset(
    set(_BASE_LANGUAGE_SPELL_BY_RACE.values()) | set(_RACE_LANGUAGE_SPELL_BY_RACE.values())
)
_SANDBOX_COMPANION_PET_SPELL_IDS = (
    139196,  # Pierre
    143714,  # Rascal-Bot
)
_SANDBOX_BATTLE_PET_SUPPORT_SPELL_IDS = (
    119467,  # Battle Pet Training
    122026,  # Track Pets
    125439,  # Revive Battle Pets
)
_DEFAULT_WALK_SPEED = 2.5
_DEFAULT_RUN_SPEED = 7.0
_DEFAULT_RUN_BACK_SPEED = 4.5
_DEFAULT_SWIM_SPEED = 4.7
_DEFAULT_SWIM_BACK_SPEED = 2.5
_DEFAULT_FLY_SPEED = 7.0
_DEFAULT_FLY_BACK_SPEED = 4.5
_DEFAULT_TURN_SPEED = 3.1415926
_DEFAULT_PITCH_SPEED = 3.1415926
_UNIT_FLAG_MOUNT = 0x08000000
_PLAYER_FIELD_MOUNT_STATE_FLAGS = 61
_PLAYER_FIELD_DISPLAYID = 69
_PLAYER_FIELD_NATIVEDISPLAYID = 70
_PLAYER_FIELD_MOUNTDISPLAYID = 71
_UNIT_FIELD_FLAGS = 0x60
_UNIT_FIELD_MOUNTDISPLAYID = 0x6A
_MOUNT_SPEED_MULTIPLIER = 2.0
_MOVEMENTFLAG_CAN_FLY = 0x00800000
_MOVEMENTFLAG_FLYING = 0x01000000
_MOVEMENTFLAG_ASCENDING = 0x00200000
_MOVEMENTFLAG_DESCENDING = 0x00400000
_MOVEMENTFLAG_FLYING_CAPABILITY = _MOVEMENTFLAG_CAN_FLY | _MOVEMENTFLAG_FLYING
_MOVEMENTFLAG_FLYING_STATE = (
    _MOVEMENTFLAG_FLYING
    | _MOVEMENTFLAG_ASCENDING
    | _MOVEMENTFLAG_DESCENDING
)
_LANG_ORCISH = 1
_LANG_COMMON = 7
_KNOWN_LANGUAGES_ALL = 0xFFFFFFFF
_LANGUAGE_ID_BY_SPELL_ID = {
    668: _LANG_COMMON,
    669: _LANG_ORCISH,
}

# TODO:
# - Keep the current `SMSG_SEND_KNOWN_SPELLS` timing unchanged during ACTIVE_MOVER.
#   Revisit whether this should remain a resync or become a more explicit initial spell flow later.
# - Mount tab behavior still depends on lightweight display/update-object packets rather than a
#   fully modeled spell/aura pipeline. Keep that behavior unchanged for now.
_MOUNT_AURA_APPLY_TEMPLATE = bytes.fromhex("80000044400001000000000B5A00F47D0000000100000000007943040602")
_MOUNT_AURA_REMOVE_TEMPLATE = bytes.fromhex("8000004400000602")
_FLY_AURA_PRIMARY_APPLY_TEMPLATE = bytes.fromhex("80000044400001000000000B5A00F47D0000000100000000007943040602")
_FLY_AURA_SECONDARY_APPLY_TEMPLATE = bytes.fromhex("8000004440000000000000035A00BD5101000003000000050602")
_FLY_AURA_PRIMARY_REMOVE_TEMPLATE = bytes.fromhex("8000004400040602")
_FLY_AURA_SECONDARY_REMOVE_TEMPLATE = bytes.fromhex("8000004400050602")
_FLY_AURA_SPELL_ID = 33943
USE_RAW_SNIFFED_KNOWN_SPELLS = False
_RAW_KNOWN_SPELLS_SNIFF_PATH = (
    Path(__file__).resolve().parents[5]
    / "data"
    / "skyfire548"
    / "captures"
    / "debug"
    / "SMSG_SEND_KNOWN_SPELLS.json"
)


def _world_login_context_from_session(session):
    return WorldLoginContext.from_session(session)


def load_raw_known_spells_payload() -> bytes:
    """Load one exact sniffed SMSG_SEND_KNOWN_SPELLS payload without patching."""
    data = json.loads(_RAW_KNOWN_SPELLS_SNIFF_PATH.read_text(encoding="utf-8"))
    payload_hex = data.get("hex_compact") or data.get("hex_spaced")
    if not payload_hex:
        raise ValueError(f"missing payload hex in {_RAW_KNOWN_SPELLS_SNIFF_PATH.name}")
    return bytes.fromhex(str(payload_hex).replace(" ", ""))


def _notification_response(message: str) -> list[tuple[str, bytes]]:
    # Fallback if we need to restore screen notifications for spell feedback:
    # return [("SMSG_NOTIFICATION", build_motd_notification_payload(message))]
    return [("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(message))]


def ensure_language_spells_known(session) -> None:
    spells = [int(spell) for spell in (getattr(session, "known_spells", []) or [])]
    race = int(getattr(session, "race", 0) or 0)
    granted_spells = list(granted_language_spells_for_race(race))
    known_spells = list(getattr(session, "known_spells", []) or [])
    spell_set = set(int(s) for s in known_spells)

    for spell in granted_spells:
        if spell not in spell_set:
            known_spells.append(spell)
            spell_set.add(spell)

    session.known_spells = known_spells
    extra_language_spells = sorted(
        int(spell_id)
        for spell_id in (getattr(session, "extra_language_spells", set()) or set())
        if int(spell_id) in _ALL_LANGUAGE_SPELL_IDS
    )
    for spell_id in extra_language_spells:
        if spell_id not in granted_spells:
            granted_spells.append(spell_id)
    kept_spells = [spell_id for spell_id in spells if spell_id not in _ALL_LANGUAGE_SPELL_IDS]
    normalized_spells = kept_spells + [spell_id for spell_id in granted_spells if spell_id not in kept_spells]
    changed = normalized_spells != spells
    if changed:
        session.known_spells = normalized_spells
        Logger.debug(
            "[SPELL] ensured language spells count=%s",
            len(normalized_spells),
        )
    else:
        session.known_spells = normalized_spells
    language_spells = sorted(int(spell_id) for spell_id in session.known_spells if int(spell_id) in _ALL_LANGUAGE_SPELL_IDS)
    Logger.info(
        "[SPELL][LANG] race=%s known=%s",
        race,
        language_spells,
    )


def ensure_spell_known(session, spell_id: int) -> bool:
    spell_id = int(spell_id or 0)
    if spell_id <= 0:
        return False

    known_spells = list(getattr(session, "known_spells", []) or [])
    spell_set = set(int(s) for s in known_spells)

    if spell_id in spell_set:
        return False

    # --- ADD SPELL ---
    known_spells.append(spell_id)
    spell_set.add(spell_id)
    session.known_spells = known_spells

    # --- TRACK LANGUAGE SPELLS (optional bookkeeping) ---
    if spell_id in _ALL_LANGUAGE_SPELL_IDS:
        extra = set(int(v) for v in getattr(session, "extra_language_spells", set()) or set())
        extra.add(spell_id)
        session.extra_language_spells = extra

    # --- REBUILD LANGUAGE STATE FROM SPELLS ---
    mask = 0
    detected_lang = None

    for s in spell_set:
        lang = _LANGUAGE_ID_BY_SPELL_ID.get(int(s))
        if lang is not None:
            mask |= (1 << lang)
            if detected_lang is None:
                detected_lang = lang  # pick first available

    session.known_languages_mask = mask

    if detected_lang is not None:
        session.language = detected_lang
        session.current_language = detected_lang

    return True


def granted_language_spells_for_race(race: int) -> list[int]:
    race = int(race or 0)

    # --- BASE ---
    if race in _ALLIANCE_RACES:
        base_spell = 668
    elif race in _HORDE_RACES:
        base_spell = 669
    else:
        base_spell = int(_BASE_LANGUAGE_SPELL_BY_RACE.get(race, 0) or 0)

    granted = []

    if base_spell > 0:
        granted.append(base_spell)

    # --- RACIAL ---
    race_spell = int(_RACE_LANGUAGE_SPELL_BY_RACE.get(race, 0) or 0)

    if race_spell > 0 and race_spell not in granted:
        granted.append(race_spell)

    return granted

def initialize_session_language_state(session) -> None:
    race = int(getattr(session, "race", 0) or 0)

    player_name = (
        str(getattr(session, "player_name", "") or "").strip()
        or f"Player{int(getattr(session, 'char_guid', 0) or 0)}"
    )

    # --- ENSURE CORRECT LANGUAGE SPELLS ---
    granted_spells = granted_language_spells_for_race(race)

    known_spells = list(getattr(session, "known_spells", []) or [])
    spell_set = set(int(s) for s in known_spells)

    # add correct ones
    for spell in granted_spells:
        spell_set.add(int(spell))

    session.known_spells = list(spell_set)

    # --- BUILD LANGUAGE STATE FROM SPELLS ---
    mask = 0
    detected_lang = None

    for s in spell_set:
        lang = _LANGUAGE_ID_BY_SPELL_ID.get(int(s))
        if lang is not None:
            mask |= (1 << lang)
            if detected_lang is None:
                detected_lang = lang

    session.known_languages_mask = mask
    if race in _ALLIANCE_RACES:
        session.language = _LANG_COMMON
    elif race in _HORDE_RACES:
        session.language = _LANG_ORCISH
    elif detected_lang is not None:
        session.language = detected_lang
    session.current_language = int(getattr(session, "language", 0) or 0)

    # --- DEBUG ---
    Logger.info(
        "[LANG_INIT] player=%s race=%s lang=%s mask=0x%X spells=%s",
        player_name,
        race,
        session.language,
        session.known_languages_mask,
        sorted(spell_set),
    )
    Logger.info(f"[LANG ACTIVE] {int(getattr(session, 'current_language', 0) or 0)}")

def granted_companion_pet_spells() -> list[int]:
    return sorted(int(spell_id) for spell_id in _SANDBOX_COMPANION_PET_SPELL_IDS if int(spell_id) > 0)


def granted_battle_pet_support_spells() -> list[int]:
    return sorted(int(spell_id) for spell_id in _SANDBOX_BATTLE_PET_SUPPORT_SPELL_IDS if int(spell_id) > 0)


def ensure_companion_pet_spells_known(session) -> None:
    spells = [int(spell) for spell in (getattr(session, "known_spells", []) or [])]
    changed = False
    for spell_id in granted_battle_pet_support_spells() + granted_companion_pet_spells():
        if spell_id not in spells:
            spells.append(spell_id)
            changed = True
    if changed:
        session.known_spells = spells
        Logger.debug("[SPELL] ensured companion pet spells count=%s", len(getattr(session, "known_spells", []) or []))


def ensure_mount_spells_known(session) -> None:
    mount_related_spells = granted_mount_spells()
    if not mount_related_spells:
        return

    spells = [int(spell) for spell in (getattr(session, "known_spells", []) or [])]
    spell_set = set(spells)
    changed = False

    for spell_id in mount_related_spells:
        spell_id = int(spell_id)
        if spell_id not in spell_set:
            spells.append(spell_id)
            spell_set.add(spell_id)
            changed = True

    if changed:
        session.known_spells = spells
        Logger.debug("[SPELL] ensured mount-related spells count=%s", len(mount_related_spells))


def initialize_session_spells(session, char_guid: int) -> None:
    session.known_spells = DatabaseConnection.get_character_spells(int(char_guid))
    ensure_language_spells_known(session)
    ensure_companion_pet_spells_known(session)
    ensure_mount_spells_known(session)
    initialize_session_language_state(session)
    persisted_spells = set(granted_language_spells_for_race(int(getattr(session, "race", 0) or 0)))
    persisted_spells.update(granted_battle_pet_support_spells())
    persisted_spells.update(granted_companion_pet_spells())

    if int(char_guid) > 0 and persisted_spells:
        inserted = DatabaseConnection.ensure_character_spells(int(char_guid), persisted_spells)
        if inserted:
            Logger.info("[SPELL] persisted sandbox spells guid=%s spells=%s", int(char_guid), inserted)
    Logger.debug("[SPELL] sending known spells count=%s", len(getattr(session, "known_spells", []) or []))


def build_known_spells_response(session) -> tuple[str, bytes]:
    ctx = _world_login_context_from_session(session)
    payload = build_login_packet("SMSG_SEND_KNOWN_SPELLS", ctx)
    Logger.debug("[SPELL] sending known spells count=%s", len(getattr(session, "known_spells", []) or []))
    return "SMSG_SEND_KNOWN_SPELLS", payload


def build_raw_known_spells_response() -> tuple[str, bytes]:
    """Return a byte-for-byte sniffed known-spells packet for A/B timing tests."""
    payload = load_raw_known_spells_payload()
    return "SMSG_SEND_KNOWN_SPELLS", payload


def build_active_mover_spell_sync_responses(session) -> list[tuple[str, bytes]]:
    ensure_language_spells_known(session)
    ensure_companion_pet_spells_known(session)
    ensure_mount_spells_known(session)
    if USE_RAW_SNIFFED_KNOWN_SPELLS:
        response = build_raw_known_spells_response()
        Logger.info("[KNOWN_SPELLS TEST] raw sniffed path payload_len=%s", len(response[1]))
        return [response]

    response = build_known_spells_response(session)
    Logger.info("[KNOWN_SPELLS TEST] server-built path payload_len=%s", len(response[1]))
    return [response]


def _restore_default_movement_speeds(player) -> None:
    player.walk_speed = _DEFAULT_WALK_SPEED
    player.run_speed = _DEFAULT_RUN_SPEED
    player.run_back_speed = _DEFAULT_RUN_BACK_SPEED
    player.swim_speed = _DEFAULT_SWIM_SPEED
    player.swim_back_speed = _DEFAULT_SWIM_BACK_SPEED
    player.fly_speed = _DEFAULT_FLY_SPEED
    player.fly_back_speed = _DEFAULT_FLY_BACK_SPEED
    player.turn_speed = _DEFAULT_TURN_SPEED
    player.pitch_speed = _DEFAULT_PITCH_SPEED


def _apply_mount_movement_speeds(player) -> None:
    player.walk_speed = _DEFAULT_WALK_SPEED
    player.run_speed = _DEFAULT_RUN_SPEED * _MOUNT_SPEED_MULTIPLIER
    player.run_back_speed = _DEFAULT_RUN_BACK_SPEED * _MOUNT_SPEED_MULTIPLIER
    player.swim_speed = _DEFAULT_SWIM_SPEED * _MOUNT_SPEED_MULTIPLIER
    player.swim_back_speed = _DEFAULT_SWIM_BACK_SPEED * _MOUNT_SPEED_MULTIPLIER
    player.fly_speed = _DEFAULT_FLY_SPEED * _MOUNT_SPEED_MULTIPLIER
    player.fly_back_speed = _DEFAULT_FLY_BACK_SPEED * _MOUNT_SPEED_MULTIPLIER
    player.turn_speed = _DEFAULT_TURN_SPEED
    player.pitch_speed = _DEFAULT_PITCH_SPEED


def set_custom_run_speed(player, run_speed: float) -> None:
    target_run_speed = max(0.1, float(run_speed))
    scale = float(target_run_speed) / float(_DEFAULT_RUN_SPEED)

    player.walk_speed = _DEFAULT_WALK_SPEED * scale
    player.run_speed = target_run_speed
    player.run_back_speed = _DEFAULT_RUN_BACK_SPEED * scale
    player.swim_speed = _DEFAULT_SWIM_SPEED * scale
    player.swim_back_speed = _DEFAULT_SWIM_BACK_SPEED * scale
    player.fly_speed = _DEFAULT_FLY_SPEED * scale
    player.fly_back_speed = _DEFAULT_FLY_BACK_SPEED * scale
    player.turn_speed = _DEFAULT_TURN_SPEED
    player.pitch_speed = _DEFAULT_PITCH_SPEED


def _iter_decoded_ints(value: Any):
    if isinstance(value, dict):
        for item in value.values():
            yield from _iter_decoded_ints(item)
        return
    if isinstance(value, list):
        for item in value:
            yield from _iter_decoded_ints(item)
        return
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        yield int(value)


def _extract_mount_spell_id_from_decoded(decoded: dict[str, Any] | None) -> Optional[int]:
    if not decoded:
        return None

    direct_keys = (
        "spell_id",
        "spell",
        "cast_spell_id",
        "cast_spell",
        "aura_spell_id",
        "aura",
    )
    for key in direct_keys:
        value = decoded.get(key)
        if isinstance(value, int) and is_mount_spell(value):
            return int(value)

    for value in _iter_decoded_ints(decoded):
        if is_mount_spell(value):
            return int(value)
    return None


def _extract_packet_spell_id(ctx: PacketContext) -> Optional[int]:
    decoded = ctx.decoded or {}
    direct_keys = (
        "spell_id",
        "spellId",
        "spellID",
        "spell",
        "cast_spell_id",
        "castSpellId",
        "cast_spell",
        "castSpell",
    )
    for key in direct_keys:
        value = decoded.get(key)
        if isinstance(value, int) and 0 < int(value) <= 500000:
            return int(value)

    payload = bytes(ctx.payload or b"")
    if len(payload) < 4:
        return None

    candidate_offsets = (0, 1, 2, 3, 4, 8, 12, 16, 20, 24, 28, 32)
    for offset in candidate_offsets:
        if offset + 4 > len(payload):
            continue
        value = struct.unpack_from("<I", payload, offset)[0]
        if 0 < int(value) <= 500000:
            return int(value)
    return None


def _extract_mount_spell_id_from_payload(payload: bytes) -> Optional[int]:
    if not payload or len(payload) < 4 or not ALL_MOUNT_SPELLS:
        return None

    unique_matches: list[int] = []
    seen: set[int] = set()
    scan_limit = len(payload) - 3

    for offset in range(0, scan_limit, 4):
        value = struct.unpack_from("<I", payload, offset)[0]
        if value in ALL_MOUNT_SPELLS and value not in seen:
            unique_matches.append(value)
            seen.add(value)

    if not unique_matches:
        for offset in range(0, scan_limit):
            value = struct.unpack_from("<I", payload, offset)[0]
            if value in ALL_MOUNT_SPELLS and value not in seen:
                unique_matches.append(value)
                seen.add(value)

    if not unique_matches:
        return None
    return int(unique_matches[0])


def extract_mount_spell_id(session, ctx: PacketContext) -> Optional[int]:
    spell_id = _extract_mount_spell_id_from_decoded(ctx.decoded)
    if spell_id:
        return spell_id

    spell_id = _extract_mount_spell_id_from_payload(ctx.payload)
    if spell_id:
        return spell_id

    current_mount = int(getattr(session, "mount_spell", 0) or 0)
    if current_mount and is_mount_spell(current_mount):
        return current_mount
    return None


def _player_object_guid(session) -> int:
    return int(
        getattr(session, "char_guid", 0)
        or getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or 0
    )


def _current_unit_flags(session) -> int:
    return int(getattr(session, "unit_flags", 0) or 0) & 0xFFFFFFFF


def _current_mount_display_id(session) -> int:
    return int(getattr(session, "mount_display_id", 0) or 0) & 0xFFFFFFFF


def _player_mount_state_flags(session, display_id: int) -> int:
    # Sniffed self mount updates use one compact player field that carries the
    # mounted bit plus a stable base value of 0x8.
    base_flags = 0x00000008
    if int(display_id) > 0:
        return int(base_flags | _UNIT_FLAG_MOUNT)
    return int(base_flags)


def _runtime_player_unit_field_values(session) -> dict[int, int]:
    return {
        _UNIT_FIELD_FLAGS: _current_unit_flags(session),
        _UNIT_FIELD_MOUNTDISPLAYID: _current_mount_display_id(session),
    }


def build_player_unit_field_update(
    session,
    field_indices: list[int],
    *,
    source_label: str = "runtime_session_values",
) -> list[tuple[str, bytes]]:
    guid = _player_object_guid(session)
    map_id = int(getattr(session, "map_id", 0) or 0)
    runtime_values = _runtime_player_unit_field_values(session)
    normalized: list[tuple[int, int]] = []
    for field_index in sorted({int(field_index) for field_index in (field_indices or [])}):
        if field_index not in runtime_values:
            continue
        normalized.append((int(field_index), int(runtime_values[field_index]) & 0xFFFFFFFF))
    if guid <= 0 or not normalized:
        Logger.warning(
            "[MOUNT_FIX] skipping player unit update guid=%s map_id=%s fields=%s",
            int(guid),
            int(map_id),
            normalized,
        )
        return []

    Logger.info(
        "[MOUNT_SOURCE] unit_flags source=session.unit_flags value=0x%08X",
        int(_current_unit_flags(session)) & 0xFFFFFFFF,
    )
    Logger.info(
        "[MOUNT_SOURCE] mount_display_id source=session.mount_display_id value=%s",
        int(_current_mount_display_id(session)),
    )
    Logger.info(
        "[MOUNT_SOURCE] player_update_source=%s synthetic_overrides=0 guid=0x%016X",
        str(source_label),
        int(guid) & 0xFFFFFFFFFFFFFFFF,
    )

    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_multi_u32_update_object_payload(
                map_id=map_id,
                guid=guid,
                field_updates=normalized,
            ),
        )
    ]


def _build_run_speed_update_response(player) -> tuple[str, bytes]:
    return ("SMSG_MOVE_SET_RUN_SPEED", build_move_set_run_speed_payload(player))


def _build_movement_speed_update_responses(player) -> list[tuple[str, bytes]]:
    return [
        (
            "SMSG_MOVE_SET_WALK_SPEED",
            build_move_set_speed_payload(
                player,
                "SMSG_MOVE_SET_WALK_SPEED",
                float(getattr(player, "walk_speed", _DEFAULT_WALK_SPEED) or _DEFAULT_WALK_SPEED),
            ),
        ),
        (
            "SMSG_MOVE_SET_RUN_SPEED",
            build_move_set_speed_payload(
                player,
                "SMSG_MOVE_SET_RUN_SPEED",
                float(getattr(player, "run_speed", _DEFAULT_RUN_SPEED) or _DEFAULT_RUN_SPEED),
            ),
        ),
        (
            "SMSG_MOVE_SET_SWIM_SPEED",
            build_move_set_speed_payload(
                player,
                "SMSG_MOVE_SET_SWIM_SPEED",
                float(getattr(player, "swim_speed", _DEFAULT_SWIM_SPEED) or _DEFAULT_SWIM_SPEED),
            ),
        ),
        (
            "SMSG_MOVE_SET_FLIGHT_SPEED",
            build_move_set_speed_payload(
                player,
                "SMSG_MOVE_SET_FLIGHT_SPEED",
                float(getattr(player, "fly_speed", _DEFAULT_FLY_SPEED) or _DEFAULT_FLY_SPEED),
            ),
        ),
    ]


def _resolve_unit_field_value(session, field):
    if field == _UNIT_FIELD_FLAGS:
        return int(getattr(session, "unit_flags", 0))

    if field == _UNIT_FIELD_MOUNTDISPLAYID:
        return int(getattr(session, "mount_display_id", 0))

    # fallback
    return 0
def build_mount_visual_responses(session, display_id: int) -> list[tuple[str, bytes]]:
    old_flags = _current_unit_flags(session)
    old_display_id = _current_mount_display_id(session)

    unit_flags = int(old_flags)

    if int(display_id) > 0:
        unit_flags |= _UNIT_FLAG_MOUNT
    else:
        unit_flags &= ~_UNIT_FLAG_MOUNT

    # --- STORE STATE ---
    session.unit_flags = int(unit_flags)
    session.mount_display_id = int(display_id)

    Logger.info(
        "[MOUNT_FIX] guid=0x%016X display_old=%s display_new=%s flags=0x%08X",
        int(_player_object_guid(session)) & 0xFFFFFFFFFFFFFFFF,
        int(old_display_id),
        int(display_id),
        int(unit_flags) & 0xFFFFFFFF,
    )
    display_value = int(getattr(session, "display_id", 0) or 0)
    native_display_value = int(getattr(session, "native_display_id", display_value) or display_value)
    mount_state_flags = _player_mount_state_flags(session, int(display_id))
    guid = _player_object_guid(session)
    map_id = int(getattr(session, "map_id", 0) or 0)
    if guid <= 0:
        return []

    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_multi_u32_update_object_payload(
                map_id=map_id,
                guid=guid,
                field_updates=[
                    (_PLAYER_FIELD_MOUNT_STATE_FLAGS, mount_state_flags),
                    (_PLAYER_FIELD_DISPLAYID, display_value),
                    (_PLAYER_FIELD_NATIVEDISPLAYID, native_display_value),
                    (_PLAYER_FIELD_MOUNTDISPLAYID, int(display_id)),
                ],
            ),
        )
    ]


def _broadcast_mount_visual_to_visible_peers(session, display_id: int) -> None:
    from server.modules.handlers.world.state.runtime import (
        _visible_guid_set,
        dispatch_responses_to_sessions,
        iter_in_world_sessions,
    )

    source_guid = int(getattr(session, "char_guid", 0) or 0)
    update_guid = _player_object_guid(session)
    map_id = int(getattr(session, "map_id", 0) or 0)
    if source_guid <= 0 or update_guid <= 0:
        return

    peers = [
        peer
        for peer in iter_in_world_sessions(map_id=map_id)
        if peer is not session and source_guid in _visible_guid_set(peer)
    ]
    if not peers:
        return

    display_value = int(getattr(session, "display_id", 0) or 0)
    native_display_value = int(getattr(session, "native_display_id", display_value) or display_value)
    mount_state_flags = _player_mount_state_flags(session, int(display_id))
    try:
        from server.modules.handlers.world.opcodes import movement as movement_handlers
    except Exception:
        movement_handlers = None
    move_payload = None
    if movement_handlers is not None:
        builder = getattr(movement_handlers, "build_smsg_player_move_payload", None)
        if callable(builder):
            move_payload = builder(session)
    responses = [
        (
            "SMSG_UPDATE_OBJECT",
            build_multi_u32_update_object_payload(
                map_id=map_id,
                guid=update_guid,
                field_updates=[
                    (_PLAYER_FIELD_MOUNT_STATE_FLAGS, mount_state_flags),
                    (_PLAYER_FIELD_DISPLAYID, display_value),
                    (_PLAYER_FIELD_NATIVEDISPLAYID, native_display_value),
                    (_PLAYER_FIELD_MOUNTDISPLAYID, int(display_id)),
                ],
            ),
        ),
        ("SMSG_MOVE_SET_RUN_SPEED", build_move_set_run_speed_payload(session)),
        ("SMSG_MOVE_SET_FLIGHT_SPEED", build_move_set_flight_speed_payload(session)),
    ]
    if move_payload is not None:
        responses.append(("SMSG_PLAYER_MOVE", move_payload))
    dispatch_responses_to_sessions(peers, responses)
    Logger.info(
        "[MOUNT_SYNC] peer visual/speed/move update guid=%s display=%s run=%.3f peers=%s move=%s",
        int(source_guid),
        int(display_id),
        float(getattr(session, "run_speed", 0.0) or 0.0),
        len(peers),
        "yes" if move_payload is not None else "no",
    )


def apply_mount_aura(session, spell_id: int) -> list[tuple[str, bytes]]:
    spell_id = int(spell_id or 0)
    if spell_id <= 0:
        return []

    slot = int(getattr(session, "active_mount_aura_slot", 0) or 0) & 0xFF
    session.active_mount_aura_spell_id = spell_id
    session.active_mount_aura_slot = slot

    payload = bytearray(_MOUNT_AURA_APPLY_TEMPLATE)
    payload[14:18] = int(spell_id).to_bytes(4, "little", signed=False)
    payload[28] = slot & 0xFF

    Logger.info("[MOUNT_AURA] apply spell=%s slot=%s", spell_id, slot)
    return [("SMSG_AURA_UPDATE", bytes(payload))]


def remove_mount_aura(session) -> list[tuple[str, bytes]]:
    slot = int(getattr(session, "active_mount_aura_slot", 0) or 0) & 0xFF
    session.active_mount_aura_spell_id = None

    payload = bytearray(_MOUNT_AURA_REMOVE_TEMPLATE)
    payload[5] = slot & 0xFF

    Logger.info("[MOUNT_AURA] remove spell=%s slot=%s", int(getattr(session, "mount_spell", 0) or 0), slot)
    return [("SMSG_AURA_UPDATE", bytes(payload))]


def apply_fly_aura(session, spell_id: int = _FLY_AURA_SPELL_ID) -> list[tuple[str, bytes]]:
    spell_id = int(spell_id or 0)
    if spell_id <= 0:
        return []

    session.active_fly_aura_spell_id = spell_id
    Logger.info("[FLY_AURA] apply spell=%s", spell_id)
    return [
        ("SMSG_AURA_UPDATE", bytes(_FLY_AURA_PRIMARY_APPLY_TEMPLATE)),
        ("SMSG_AURA_UPDATE", bytes(_FLY_AURA_SECONDARY_APPLY_TEMPLATE)),
    ]


def remove_fly_aura(session) -> list[tuple[str, bytes]]:
    spell_id = int(getattr(session, "active_fly_aura_spell_id", 0) or 0)
    session.active_fly_aura_spell_id = None
    Logger.info("[FLY_AURA] remove spell=%s", spell_id)
    return [
        ("SMSG_AURA_UPDATE", bytes(_FLY_AURA_PRIMARY_REMOVE_TEMPLATE)),
        ("SMSG_AURA_UPDATE", bytes(_FLY_AURA_SECONDARY_REMOVE_TEMPLATE)),
    ]


def build_fly_state_responses(session) -> list[tuple[str, bytes]]:
    return build_player_unit_field_update(
        session,
        [_UNIT_FIELD_FLAGS],
        source_label="fly_toggle",
    )


def _movement_guid_value(session) -> int:
    return int(
        getattr(session, "char_guid", 0)
        or getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or 0
    )


def _append_guid_xor_bytes(
    payload: bytearray,
    raw_guid: bytes,
    order: tuple[int, ...],
) -> None:
    for index in order:
        value = raw_guid[index]
        if value:
            payload.append((value ^ 1) & 0xFF)


def build_spline_move_flying_payload(session) -> bytes:
    guid_value = _movement_guid_value(session)
    raw_guid = int(guid_value).to_bytes(8, "little", signed=False)

    bits = BitWriter()
    for index in (4, 1, 2, 0, 7, 5, 3, 6):
        bits.write_bits(1 if raw_guid[index] else 0, 1)

    payload = bytearray(bits.getvalue())
    _append_guid_xor_bytes(payload, raw_guid, (4, 7, 1, 0, 3, 5, 6, 2))
    return bytes(payload)


def build_spline_move_unset_flying_payload(session) -> bytes:
    guid_value = _movement_guid_value(session)
    raw_guid = int(guid_value).to_bytes(8, "little", signed=False)

    bits = BitWriter()
    for index in (1, 5, 7, 2, 6, 3, 0, 4):
        bits.write_bits(1 if raw_guid[index] else 0, 1)

    payload = bytearray(bits.getvalue())
    _append_guid_xor_bytes(payload, raw_guid, (2, 5, 4, 6, 1, 0, 7, 3))
    return bytes(payload)


def build_smsg_dismount_payload(session) -> bytes:
    guid_value = _movement_guid_value(session)
    raw_guid = int(guid_value).to_bytes(8, "little", signed=False)

    bits = BitWriter()
    for index in (6, 3, 0, 7, 1, 2, 5, 4):
        bits.write_bits(1 if raw_guid[index] else 0, 1)

    payload = bytearray(bits.getvalue())
    for index in (3, 6, 7, 5, 1, 4, 2, 0):
        if raw_guid[index]:
            payload.append(raw_guid[index])
    return bytes(payload)


def _set_flying_capability_state(session, enabled: bool) -> bool:
    previous = bool(getattr(session, "can_fly", False))
    session.can_fly = bool(enabled)
    session.is_flying = bool(enabled)

    state = getattr(session, "movement_state", None)
    if state is not None:
        state.x = float(getattr(session, "x", getattr(state, "x", 0.0)) or 0.0)
        state.y = float(getattr(session, "y", getattr(state, "y", 0.0)) or 0.0)
        state.z = float(getattr(session, "z", getattr(state, "z", 0.0)) or 0.0)
        state.orientation = float(getattr(session, "orientation", getattr(state, "orientation", 0.0)) or 0.0)
        flags = int(getattr(state, "flags", 0) or 0)
        if enabled:
            flags |= _MOVEMENTFLAG_FLYING_CAPABILITY
            state.has_fall_data = False
            state.fall_time = 0
            state.fall_vertical_speed = 0.0
            state.fall_horizontal_speed = 0.0
            state.fall_sin_angle = 0.0
            state.fall_cos_angle = 0.0
        else:
            flags &= ~(
                _MOVEMENTFLAG_CAN_FLY
                | _MOVEMENTFLAG_FLYING_STATE
            )
            state.is_ascending = False
            state.is_descending = False
        state.flags = int(flags)

    return previous != bool(enabled)


def build_mount_flying_capability_responses(player, spell_id: int) -> list[tuple[str, bytes]]:
    if not is_flying_mount_spell(int(spell_id)):
        return []
    player.fly_speed = float(getattr(player, "run_speed", _DEFAULT_RUN_SPEED) or _DEFAULT_RUN_SPEED) * 3.2
    if not _set_flying_capability_state(player, True):
        return []
    responses: list[tuple[str, bytes]] = []
    responses.extend(apply_fly_aura(player))
    responses.extend([
        ("SMSG_SPLINE_MOVE_SET_FLYING", build_spline_move_flying_payload(player)),
        ("SMSG_MOVE_SET_CAN_FLY", build_move_set_can_fly_payload(player, True)),
    ])
    return responses


def build_dismount_flying_capability_responses(player) -> list[tuple[str, bytes]]:
    state = getattr(player, "movement_state", None)
    state_flags = int(getattr(state, "flags", 0) or 0) if state is not None else 0
    has_flying_state = (
        bool(getattr(player, "can_fly", False))
        or bool(getattr(player, "is_flying", False))
        or bool(state_flags & (_MOVEMENTFLAG_CAN_FLY | _MOVEMENTFLAG_FLYING_STATE))
    )
    if not has_flying_state:
        return []
    _set_flying_capability_state(player, False)
    return [
        ("SMSG_MOVE_UNSET_CAN_FLY", build_move_set_can_fly_payload(player, False)),
        ("SMSG_SPLINE_MOVE_UNSET_FLYING", build_spline_move_unset_flying_payload(player)),
    ]


def build_raw_update_object(player, fields):
    payload = bytearray()

    # map_id
    payload += int(getattr(player, "map_id", 1)).to_bytes(2, "little")

    # update_count (LITTLE)
    payload += (1).to_bytes(4, "little")

    # update_type
    payload.append(0)

    # GUID packed
    guid = int(player.char_guid)
    guid_mask = 0
    guid_bytes = []

    for i in range(8):
        b = (guid >> (i * 8)) & 0xFF
        if b:
            guid_mask |= (1 << i)
            guid_bytes.append(b)

    payload.append(guid_mask)
    payload += bytes(guid_bytes)

    # mask
    max_field = max(f[0] for f in fields)
    mask_blocks = (max_field // 32) + 1

    payload.append(mask_blocks)

    mask = [0] * mask_blocks
    for field, _ in fields:
        block = field // 32
        bit = field % 32
        mask[block] |= (1 << bit)

    for m in mask:
        payload += m.to_bytes(4, "little")

    # values
    for _, value in fields:
        payload += int(value).to_bytes(4, "little")

    return ("SMSG_UPDATE_OBJECT", bytes(payload))


def send_mount_update(player, spell_id: int) -> list[tuple[str, bytes]]:
    responses: list[tuple[str, bytes]] = []
    display_id = get_mount_display_id(spell_id)
    responses.extend(apply_mount_aura(player, spell_id))
    if display_id > 0:
        responses.extend(build_mount_visual_responses(player, display_id))
        _broadcast_mount_visual_to_visible_peers(player, display_id)
    responses.extend(build_mount_flying_capability_responses(player, int(spell_id)))
    responses.append(_build_run_speed_update_response(player))
    responses.append(("SMSG_MOVE_SET_FLIGHT_SPEED", build_move_set_flight_speed_payload(player)))
    responses.extend(_notification_response(f"Mounted spell={int(spell_id)} speed={float(player.run_speed):.2f}"))
    return responses


def send_dismount_update(player) -> list[tuple[str, bytes]]:
    responses: list[tuple[str, bytes]] = list(remove_mount_aura(player))
    if int(getattr(player, "active_fly_aura_spell_id", 0) or 0):
        responses.extend(remove_fly_aura(player))
    responses.append(("SMSG_DISMOUNT", build_smsg_dismount_payload(player)))
    responses.extend(build_dismount_flying_capability_responses(player))
    responses.extend(build_mount_visual_responses(player, 0))
    _broadcast_mount_visual_to_visible_peers(player, 0)
    responses.extend(_build_movement_speed_update_responses(player))
    responses.extend(_notification_response(f"Dismounted speed={float(player.run_speed):.2f}"))
    return responses


def _mount_owner_ids(session) -> tuple[int, int]:
    char_guid = int(
        getattr(session, "char_guid", 0)
        or getattr(session, "player_guid", 0)
        or getattr(session, "world_guid", 0)
        or 0
    )
    realm_id = int(getattr(session, "realm_id", 0) or 0)
    return char_guid, realm_id


def _persist_current_mount_state(session) -> None:
    char_guid, realm_id = _mount_owner_ids(session)
    spell_id = int(getattr(session, "mount_spell", 0) or 0)
    display_id = int(getattr(session, "mount_display_id", 0) or 0)
    if char_guid <= 0 or spell_id <= 0 or display_id <= 0:
        return

    saver = getattr(DatabaseConnection, "save_character_mount_state", None)
    if not callable(saver):
        return

    saver(
        char_guid,
        realm_id,
        spell_id=spell_id,
        display_id=display_id,
    )


def clear_persisted_mount_state(session) -> None:
    """Clear DB mount state after dismount or teleport."""
    char_guid, realm_id = _mount_owner_ids(session)
    if char_guid <= 0:
        return
    clearer = getattr(DatabaseConnection, "clear_character_mount_state", None)
    if callable(clearer):
        clearer(char_guid, realm_id)


def restore_persisted_mount_state(session, char_guid: int, realm_id: int) -> bool:
    """Load mount state before login packets are built.

    The login UPDATE_OBJECT can then describe the mounted model immediately.
    Extra aura/speed/flying packets are sent later by build_login_mount_restore_responses.
    """
    loader = getattr(DatabaseConnection, "load_character_mount_state", None)
    if not callable(loader):
        return False

    state = loader(int(char_guid), int(realm_id))
    if not state:
        return False

    spell_id = int(state.get("spell") or 0)
    display_id = int(state.get("display_id") or 0) or get_mount_display_id(spell_id)
    if spell_id <= 0 or display_id <= 0 or not is_mount_spell(spell_id):
        clearer = getattr(DatabaseConnection, "clear_character_mount_state", None)
        if callable(clearer):
            clearer(int(char_guid), int(realm_id))
        return False

    session.is_mounted = True
    session.mount_spell = int(spell_id)
    session.mount_display_id = int(display_id)
    session.active_mount_aura_slot = int(getattr(session, "active_mount_aura_slot", 0) or 0)
    session.unit_flags = int(getattr(session, "unit_flags", 0) or 0) | _UNIT_FLAG_MOUNT
    _apply_mount_movement_speeds(session)
    Logger.info(
        "[Mount] restored guid=%s spell=%s display=%s",
        int(char_guid),
        int(spell_id),
        int(display_id),
    )
    return True


def build_login_mount_restore_responses(session) -> list[tuple[str, bytes]]:
    """Send the active mount pieces that are not fully covered by login fields."""
    spell_id = int(getattr(session, "mount_spell", 0) or 0)
    display_id = int(getattr(session, "mount_display_id", 0) or 0)
    if spell_id <= 0 or display_id <= 0 or not bool(getattr(session, "is_mounted", False)):
        return []

    responses: list[tuple[str, bytes]] = []
    responses.extend(build_mount_visual_responses(session, display_id))
    responses.extend(apply_mount_aura(session, spell_id))
    responses.extend(build_mount_flying_capability_responses(session, spell_id))
    responses.append(_build_run_speed_update_response(session))
    responses.append(("SMSG_MOVE_SET_FLIGHT_SPEED", build_move_set_flight_speed_payload(session)))
    responses.extend(resync_movement(session))
    return responses


def mount_direct(player, display_id: int, run_speed: float | None = None) -> list[tuple[str, bytes]]:
    Logger.info(
        "[Mount][Debug] mount_direct enter char=%s display=%s run_speed_arg=%s mounted_before=%s mount_spell_before=%s",
        int(getattr(player, "char_guid", 0) or 0),
        int(display_id),
        "None" if run_speed is None else float(run_speed),
        bool(getattr(player, "is_mounted", False)),
        int(getattr(player, "mount_spell", 0) or 0),
    )
    player.is_mounted = True
    player.mount_spell = None
    if run_speed is None:
        _apply_mount_movement_speeds(player)
    else:
        set_custom_run_speed(player, float(run_speed))

    responses: list[tuple[str, bytes]] = list(build_mount_visual_responses(player, int(display_id)))
    Logger.info(
        "[Mount][Debug] mount_direct display_packet=%s run_speed=%.2f",
        "yes" if responses else "no",
        float(getattr(player, "run_speed", 0.0) or 0.0),
    )
    responses.append(_build_run_speed_update_response(player))
    responses.extend(_notification_response(f"Mounted display={int(display_id)} speed={float(player.run_speed):.2f}"))
    Logger.info("[Mount][Debug] mount_direct total_responses=%s", len(responses))
    return responses

def handle_mount(player, spell_id: int):
    spell_id = int(spell_id)
    active_mount_spell = int(getattr(player, "mount_spell", 0) or 0)
    if active_mount_spell == spell_id and bool(getattr(player, "is_mounted", False)):
        Logger.info(
            "[Mount] toggling active mount off guid=%s spell=%s",
            int(getattr(player, "char_guid", 0) or 0),
            spell_id,
        )
        return dismount(player)

    player.is_mounted = True
    player.mount_spell = spell_id
    player.active_mount_aura_slot = int(getattr(player, "active_mount_aura_slot", 0) or 0)
    _apply_mount_movement_speeds(player)
    responses = send_mount_update(player, spell_id)
    _persist_current_mount_state(player)
    return responses


def dismount(player) -> list[tuple[str, bytes]]:
    clear_persisted_mount_state(player)
    player.is_mounted = False
    player.mount_spell = None
    player.mount_display_id = 0
    player.is_flying = False
    player.unit_flags = int(getattr(player, "unit_flags", 0) or 0) & ~_UNIT_FLAG_MOUNT
    state = getattr(player, "movement_state", None)
    if state is not None:
        state.is_ascending = False
        state.is_descending = False
        flags = int(getattr(state, "flags", 0) or 0)
        flags &= ~(
            _MOVEMENTFLAG_CAN_FLY
            | _MOVEMENTFLAG_FLYING
            | _MOVEMENTFLAG_ASCENDING
            | _MOVEMENTFLAG_DESCENDING
        )
        state.flags = int(flags)
    _restore_default_movement_speeds(player)
    return send_dismount_update(player)


@register("CMSG_CAST_SPELL")
def handle_cast_spell(session, ctx: PacketContext):
    Logger.debug(f"[SPELL] opcode={ctx.name}")
    packet_spell_id = _extract_packet_spell_id(ctx)
    if packet_spell_id and is_mount_spell(packet_spell_id):
        Logger.debug(f"[SPELL] packet mount spell_id={int(packet_spell_id)}")
        pending_cancel_spell = int(getattr(session, "pending_mount_cancel_spell", 0) or 0)
        if pending_cancel_spell:
            session.pending_mount_cancel_spell = None
            if pending_cancel_spell == int(packet_spell_id) and not bool(getattr(session, "is_mounted", False)):
                Logger.debug("[SPELL] ignored duplicate mount cast after cancel spell_id=%s", int(packet_spell_id))
                return 0, None
        active_mount = int(getattr(session, "mount_spell", 0) or 0)
        if active_mount == int(packet_spell_id) and bool(getattr(session, "is_mounted", False)):
            return 0, dismount(session)
        return 0, handle_mount(session, int(packet_spell_id))

    spell_id = extract_mount_spell_id(session, ctx)
    if not spell_id:
        return 0, None

    Logger.debug(f"[SPELL] cast spell_id={int(spell_id)}")
    pending_cancel_spell = int(getattr(session, "pending_mount_cancel_spell", 0) or 0)
    if pending_cancel_spell:
        session.pending_mount_cancel_spell = None
        if pending_cancel_spell == int(spell_id) and not bool(getattr(session, "is_mounted", False)):
            Logger.debug("[SPELL] ignored duplicate mount cast after cancel spell_id=%s", int(spell_id))
            return 0, None
    active_mount = int(getattr(session, "mount_spell", 0) or 0)
    if active_mount == int(spell_id) and bool(getattr(session, "is_mounted", False)):
        return 0, dismount(session)
    responses = handle_mount(session, int(spell_id))
    return 0, responses


@register("CMSG_CANCEL_AURA")
def handle_cancel_aura(session, ctx: PacketContext):
    Logger.debug(f"[SPELL] opcode={ctx.name}")
    spell_id = extract_mount_spell_id(session, ctx)
    active_mount = int(getattr(session, "mount_spell", 0) or 0)
    if not spell_id and not active_mount:
        return 0, None
    if spell_id and not is_mount_spell(spell_id):
        return 0, None

    responses = dismount(session)
    return 0, responses


@register("CMSG_CANCEL_MOUNT_AURA")
def handle_cancel_mount_aura(session, ctx: PacketContext):
    Logger.debug(f"[SPELL] opcode={ctx.name}")
    active_mount = int(getattr(session, "mount_spell", 0) or 0)
    if not bool(getattr(session, "is_mounted", False)) and not active_mount:
        return 0, None

    if active_mount:
        session.pending_mount_cancel_spell = active_mount
    responses = dismount(session)
    return 0, responses
