from __future__ import annotations

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
from server.modules.handlers.world.opcodes.movement import build_move_set_run_speed_payload
from server.modules.handlers.world.mount.mount_service import (
    ALL_MOUNT_SPELLS,
    get_mount_display_id,
    granted_mount_spells,
    is_mount_spell,
)


_ALLIANCE_RACES = {1, 3, 4, 7, 11, 22, 25}
_HORDE_RACES = {2, 5, 6, 8, 9, 10, 26}
_BASE_LANGUAGE_SPELL_BY_RACE = {
    1: 668,       # Human -> Common
    2: 669,       # Orc -> Orcish
    24: 108127,   # Pandaren Neutral
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
    24: 108127,
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
_UNIT_FIELD_FLAGS = 0x60
_UNIT_FIELD_MOUNTDISPLAYID = 0x6A
_UNIT_FLAG_MOUNT = 0x08000000
_MOUNT_SPEED_MULTIPLIER = 2.0
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


def _world_login_context_from_session(session):
    return WorldLoginContext.from_session(session)


def _notification_response(message: str) -> list[tuple[str, bytes]]:
    # Fallback if we need to restore screen notifications for spell feedback:
    # return [("SMSG_NOTIFICATION", build_motd_notification_payload(message))]
    return [("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(message))]


def ensure_language_spells_known(session) -> None:
    spells = [int(spell) for spell in (getattr(session, "known_spells", []) or [])]
    race = int(getattr(session, "race", 0) or 0)
    granted_spells = list(granted_language_spells_for_race(race))
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

    known_spells = [int(spell) for spell in (getattr(session, "known_spells", []) or [])]
    changed = False
    if spell_id not in known_spells:
        known_spells.append(spell_id)
        session.known_spells = known_spells
        changed = True

    if spell_id in _ALL_LANGUAGE_SPELL_IDS:
        extra_language_spells = {
            int(value)
            for value in (getattr(session, "extra_language_spells", set()) or set())
            if int(value) > 0
        }
        if spell_id not in extra_language_spells:
            extra_language_spells.add(spell_id)
            session.extra_language_spells = extra_language_spells
            changed = True
        session.language = int(_LANGUAGE_ID_BY_SPELL_ID.get(spell_id, getattr(session, "language", 0) or 0))
        session.known_languages_mask = _KNOWN_LANGUAGES_ALL
        ensure_language_spells_known(session)

    return changed


def granted_language_spells_for_race(race: int) -> list[int]:
    granted: list[int] = []
    race = int(race or 0)
    if race in _ALLIANCE_RACES:
        return [669]
    base_spell = int(_BASE_LANGUAGE_SPELL_BY_RACE.get(race, 0) or 0)
    if base_spell == 0:
        if race in _HORDE_RACES:
            base_spell = 669
    if base_spell > 0:
        granted.append(base_spell)
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
    if race in _ALLIANCE_RACES:
        team = "alliance"
        session.language = _LANG_ORCISH
    elif race in _HORDE_RACES:
        team = "horde"
        session.language = _LANG_ORCISH
    else:
        team = "neutral"
        session.language = int(getattr(session, "language", 0) or 0)

    granted_spells = granted_language_spells_for_race(race)
    if granted_spells:
        session.known_languages_mask = _KNOWN_LANGUAGES_ALL

    Logger.info(
        "[LANG_INIT] player=%s race=%s team=%s session.language=%s",
        player_name,
        race,
        team,
        int(getattr(session, "language", 0) or 0),
    )
    Logger.info(
        "[LANG_INIT] granted_language_spells=%s",
        granted_spells,
    )
    Logger.info(
        "[LANG_INIT] known_languages_field=0x%08X",
        int(getattr(session, "known_languages_mask", 0) or 0),
    )


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


def build_active_mover_spell_sync_responses(session) -> list[tuple[str, bytes]]:
    ensure_language_spells_known(session)
    ensure_companion_pet_spells_known(session)
    ensure_mount_spells_known(session)
    return [build_known_spells_response(session)]


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


def build_mount_visual_responses(session, display_id: int) -> list[tuple[str, bytes]]:
    old_flags = _current_unit_flags(session)
    old_display_id = _current_mount_display_id(session)
    unit_flags = int(old_flags)
    if int(display_id) > 0:
        unit_flags |= _UNIT_FLAG_MOUNT
        Logger.info("[MOUNT_FLAGS] mount_bit_set=%s", int(bool(unit_flags & _UNIT_FLAG_MOUNT)))
    else:
        unit_flags &= ~_UNIT_FLAG_MOUNT
        Logger.info("[MOUNT_FLAGS] mount_bit_cleared=%s", int(bool(unit_flags & _UNIT_FLAG_MOUNT)))

    session.unit_flags = int(unit_flags)
    session.mount_display_id = int(display_id)
    Logger.info(
        "[MOUNT_FLAGS] old=0x%08X new=0x%08X",
        int(old_flags) & 0xFFFFFFFF,
        int(unit_flags) & 0xFFFFFFFF,
    )
    Logger.info(
        "[MOUNT_FIX] guid=0x%016X display_old=%s display_new=%s flags=0x%08X",
        int(_player_object_guid(session)) & 0xFFFFFFFFFFFFFFFF,
        int(old_display_id),
        int(display_id),
        int(unit_flags) & 0xFFFFFFFF,
    )
    return build_player_unit_field_update(
        session,
        [_UNIT_FIELD_FLAGS, _UNIT_FIELD_MOUNTDISPLAYID],
        source_label="runtime_session_player_state",
    )


def send_mount_update(player, spell_id: int) -> list[tuple[str, bytes]]:
    responses: list[tuple[str, bytes]] = []
    display_id = get_mount_display_id(spell_id)
    if display_id > 0:
        responses.extend(build_mount_visual_responses(player, display_id))
    responses.append(_build_run_speed_update_response(player))
    responses.extend(_notification_response(f"Mounted spell={int(spell_id)} speed={float(player.run_speed):.2f}"))
    return responses


def send_dismount_update(player) -> list[tuple[str, bytes]]:
    responses: list[tuple[str, bytes]] = list(build_mount_visual_responses(player, 0))
    responses.append(_build_run_speed_update_response(player))
    responses.extend(_notification_response(f"Dismounted speed={float(player.run_speed):.2f}"))
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


def handle_mount(player, spell_id: int) -> list[tuple[str, bytes]]:
    player.is_mounted = True
    player.mount_spell = int(spell_id)
    _apply_mount_movement_speeds(player)
    Logger.debug("[SPELL] cast spell_id=%s", int(spell_id))
    return send_mount_update(player, int(spell_id))


def dismount(player) -> list[tuple[str, bytes]]:
    player.is_mounted = False
    player.mount_spell = None
    _restore_default_movement_speeds(player)
    return send_dismount_update(player)


@register("CMSG_CAST_SPELL")
def handle_cast_spell(session, ctx: PacketContext):
    Logger.debug(f"[SPELL] opcode={ctx.name}")
    packet_spell_id = _extract_packet_spell_id(ctx)
    if packet_spell_id and is_mount_spell(packet_spell_id):
        Logger.debug(f"[SPELL] packet mount spell_id={int(packet_spell_id)}")
        return 0, handle_mount(session, int(packet_spell_id))

    spell_id = extract_mount_spell_id(session, ctx)
    if not spell_id:
        return 0, None

    Logger.debug(f"[SPELL] cast spell_id={int(spell_id)}")
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
    if not bool(getattr(session, "is_mounted", False)) and not int(getattr(session, "mount_spell", 0) or 0):
        return 0, None

    responses = dismount(session)
    return 0, responses
