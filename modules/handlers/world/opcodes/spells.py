from __future__ import annotations

import struct
from typing import Any, Optional

from shared.Logger import Logger
from server.modules.protocol.PacketContext import PacketContext
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.game.guid import GuidHelper, HighGuid
from server.modules.handlers.world.login.context import WorldLoginContext
from server.modules.handlers.world.login.packets import build_login_packet
from server.modules.handlers.world.chat.codec import build_motd_notification_payload
from server.modules.handlers.world.bootstrap.replay import (
    build_single_u32_update_object_payload,
    make_update_object_response,
)
from server.modules.handlers.world.dispatcher import register
from server.modules.handlers.world.mount.mount_service import (
    ALL_MOUNT_SPELLS,
    get_mount_display_id,
    granted_mount_spells,
    is_mount_spell,
)


_ALLIANCE_RACES = {1, 3, 4, 7, 11, 22, 25}
_HORDE_RACES = {2, 5, 6, 8, 9, 10, 26}
_SANDBOX_LANGUAGE_SPELL_IDS = (668, 669, 108127)
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
    set(_SANDBOX_LANGUAGE_SPELL_IDS) | set(_BASE_LANGUAGE_SPELL_BY_RACE.values()) | set(_RACE_LANGUAGE_SPELL_BY_RACE.values())
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
_UNIT_FIELD_MOUNTDISPLAYID = 0x6A
_MOUNT_SPEED_MULTIPLIER = 2.0

# TODO:
# - Keep the current `SMSG_SEND_KNOWN_SPELLS` timing unchanged during ACTIVE_MOVER.
#   Revisit whether this should remain a resync or become a more explicit initial spell flow later.
# - Mount tab behavior still depends on lightweight display/update-object packets rather than a
#   fully modeled spell/aura pipeline. Keep that behavior unchanged for now.


def _world_login_context_from_session(session):
    return WorldLoginContext.from_session(session)


def _notification_response(message: str) -> list[tuple[str, bytes]]:
    return [("SMSG_NOTIFICATION", build_motd_notification_payload(message))]


def _make_update_object_response(payload: bytes) -> tuple[str, bytes]:
    return make_update_object_response(payload)


def _build_single_u32_update_object_payload(*, map_id: int, guid: int, field_index: int, value: int) -> bytes:
    return build_single_u32_update_object_payload(
        map_id=map_id,
        guid=guid,
        field_index=field_index,
        value=value,
    )


def ensure_language_spells_known(session) -> None:
    spells = [int(spell) for spell in (getattr(session, "known_spells", []) or [])]
    changed = False
    for spell_id in _SANDBOX_LANGUAGE_SPELL_IDS:
        spell_id = int(spell_id)
        if spell_id not in spells:
            spells.append(spell_id)
            changed = True
    race = int(getattr(session, "race", 0) or 0)
    base_spell = int(_BASE_LANGUAGE_SPELL_BY_RACE.get(race, 0) or 0)
    if base_spell == 0:
        if race in _ALLIANCE_RACES:
            base_spell = 668
        elif race in _HORDE_RACES:
            base_spell = 669
    if base_spell and base_spell not in spells:
        spells.append(base_spell)
        changed = True
    race_spell = int(_RACE_LANGUAGE_SPELL_BY_RACE.get(race, 0) or 0)
    if race_spell and race_spell not in spells:
        spells.append(race_spell)
        changed = True
    if changed:
        session.known_spells = spells
        Logger.debug(
            "[SPELL] ensured language spells count=%s",
            len(spells),
        )
    language_spells = sorted(int(spell_id) for spell_id in spells if int(spell_id) in _ALL_LANGUAGE_SPELL_IDS)
    Logger.info(
        "[SPELL][LANG] race=%s known=%s",
        race,
        language_spells,
    )


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
    ensure_mount_spells_known(session)
    Logger.debug("[SPELL] sending known spells count=%s", len(getattr(session, "known_spells", []) or []))


def build_known_spells_response(session) -> tuple[str, bytes]:
    ctx = _world_login_context_from_session(session)
    payload = build_login_packet("SMSG_SEND_KNOWN_SPELLS", ctx)
    Logger.debug("[SPELL] sending known spells count=%s", len(getattr(session, "known_spells", []) or []))
    return "SMSG_SEND_KNOWN_SPELLS", payload


def build_active_mover_spell_sync_responses(session) -> list[tuple[str, bytes]]:
    ensure_language_spells_known(session)
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


def _extract_mount_spell_id_from_payload(payload: bytes) -> Optional[int]:
    if not payload or len(payload) < 4 or not ALL_MOUNT_SPELLS:
        return None

    unique_matches: list[int] = []
    seen: set[int] = set()
    scan_limit = min(len(payload) - 3, 64)

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


def _resolve_player_world_guid(player) -> int:
    world_guid = int(getattr(player, "world_guid", 0) or 0)
    if world_guid > 0:
        return world_guid

    player_guid = int(getattr(player, "player_guid", 0) or 0)
    if player_guid > 0xFFFFFFFF:
        return player_guid

    realm_id = int(getattr(player, "realm_id", 0) or 0)
    char_guid = int(getattr(player, "char_guid", 0) or 0)
    if char_guid > 0:
        return int(
            GuidHelper.make(
                high=HighGuid.PLAYER,
                realm=realm_id,
                low=char_guid,
            )
        )

    return player_guid


def _build_mount_display_update_response(player, display_id: int) -> Optional[tuple[str, bytes]]:
    player_guid = _resolve_player_world_guid(player)
    map_id = int(getattr(player, "map_id", 0) or 0)
    if player_guid <= 0 or map_id < 0:
        Logger.warning(
            "[Mount] skipping mount display update guid=%s map_id=%s display_id=%s",
            int(player_guid),
            int(map_id),
            int(display_id),
        )
        return None
    payload = _build_single_u32_update_object_payload(
        map_id=map_id,
        guid=player_guid,
        field_index=_UNIT_FIELD_MOUNTDISPLAYID,
        value=int(display_id) & 0xFFFFFFFF,
    )
    return _make_update_object_response(payload)


def send_mount_update(player, spell_id: int) -> list[tuple[str, bytes]]:
    responses: list[tuple[str, bytes]] = []
    display_id = get_mount_display_id(spell_id)
    if display_id > 0:
        display_packet = _build_mount_display_update_response(player, display_id)
        if display_packet is not None:
            responses.append(display_packet)
    responses.extend(_notification_response(f"Mounted spell={int(spell_id)} speed={float(player.run_speed):.2f}"))
    return responses


def send_dismount_update(player) -> list[tuple[str, bytes]]:
    responses: list[tuple[str, bytes]] = []
    display_packet = _build_mount_display_update_response(player, 0)
    if display_packet is not None:
        responses.append(display_packet)
    responses.extend(_notification_response(f"Dismounted speed={float(player.run_speed):.2f}"))
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
