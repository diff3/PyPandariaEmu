#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
import struct
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from DSL.modules.bitsHandler import BitWriter
from shared.Logger import Logger
from shared.PathUtils import get_dbc_root
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.dbc import read_dbc
from server.modules.game.guid import GuidHelper, HighGuid
from server.modules.handlers.world.state.runtime import build_explored_zones_update_response


ACHIEVEMENT_CRITERIA_TYPE_REACH_LEVEL = 5
ACHIEVEMENT_CRITERIA_TYPE_EXPLORE_AREA = 43
PLAYER_EXPLORED_ZONES_SIZE = 200

ACHIEVEMENT_DBC_FMT = "niiisxiixixxiii"
ACHIEVEMENT_CRITERIA_DBC_FMT = "niiiixiiiisiiiiixxiiiii"
AREA_TABLE_DBC_FMT = "niiiixxxxxxxisiiiiiffixxxxxxxx"


@dataclass(frozen=True)
class AchievementMeta:
    achievement_id: int
    name: str
    required_faction: int
    map_id: int
    parent_achievement: int
    flags: int


@dataclass(frozen=True)
class CriteriaMeta:
    criteria_id: int
    achievement_id: int
    criteria_type: int
    asset: int
    quantity: int
    description: str


@dataclass(frozen=True)
class AreaMeta:
    area_id: int
    map_id: int
    parent_area_id: int
    explore_flag: int


_ACHIEVEMENTS: dict[int, AchievementMeta] | None = None
_CRITERIA_BY_ID: dict[int, CriteriaMeta] | None = None
_CRITERIA_BY_ACHIEVEMENT: dict[int, list[CriteriaMeta]] | None = None
_EXPLORE_CRITERIA_BY_AREA: dict[int, list[CriteriaMeta]] | None = None
_LEVEL_CRITERIA: list[CriteriaMeta] | None = None
_AREA_META_BY_ID: dict[int, AreaMeta] | None = None


def _now() -> int:
    return int(time.time())


def _player_name(session: Any) -> str:
    return str(getattr(session, "player_name", "") or getattr(session, "account_name", "") or "?")


def _world_guid(value: Any) -> int:
    world_guid = int(getattr(value, "world_guid", 0) or 0)
    if world_guid > 0:
        return world_guid
    char_guid = int(getattr(value, "char_guid", 0) or getattr(value, "player_guid", 0) or 0)
    realm_id = int(getattr(value, "realm_id", 1) or 1)
    if char_guid <= 0:
        return 0
    return int(GuidHelper.make(HighGuid.PLAYER, realm_id, char_guid))


def _guid_bytes(value: int) -> bytes:
    return int(value or 0).to_bytes(8, "little", signed=False)


def _write_guid_bits(writer: BitWriter, raw: bytes, order: tuple[int, ...]) -> None:
    for index in order:
        writer.write_bits(1 if raw[index] else 0, 1)


def _append_xor_guid_bytes(payload: bytearray, raw: bytes, order: tuple[int, ...]) -> None:
    for index in order:
        if raw[index]:
            payload.append(raw[index] ^ 1)


def _packed_wow_time(timestamp: int | None = None) -> int:
    dt = datetime.fromtimestamp(int(timestamp or _now()))
    return (
        ((dt.year - 2000) << 24)
        | ((dt.month - 1) << 20)
        | ((dt.day - 1) << 14)
        | ((dt.weekday() + 1) % 7 << 11)
        | (dt.hour << 6)
        | dt.minute
    ) & 0xFFFFFFFF


def _normalized_explored_zones(raw: str | None) -> list[int]:
    values = [
        max(0, min(0xFFFFFFFF, int(token)))
        for token in re.findall(r"-?\d+", str(raw or ""))
    ]
    if len(values) < PLAYER_EXPLORED_ZONES_SIZE:
        values.extend([0] * (PLAYER_EXPLORED_ZONES_SIZE - len(values)))
    return values[:PLAYER_EXPLORED_ZONES_SIZE]


def _serialize_explored_zones(values: list[int]) -> str:
    return " ".join(str(max(0, min(0xFFFFFFFF, int(value)))) for value in values[:PLAYER_EXPLORED_ZONES_SIZE])


def _mark_explored_zone_bit(session: Any, area: AreaMeta) -> bool:
    values = _normalized_explored_zones(getattr(session, "explored_zones_raw", ""))
    if area.explore_flag < 0:
        return False

    index = int(area.explore_flag) // 32
    bit = 1 << (int(area.explore_flag) % 32)
    if not 0 <= index < len(values):
        return False
    if int(values[index]) & int(bit):
        return False

    values[index] = int(values[index]) | int(bit)
    session.explored_zones_raw = _serialize_explored_zones(values)
    return True


def _sync_explored_zone_bits_from_discovery(session: Any) -> None:
    areas = _load_area_meta()
    changed = False
    for area_id in _session_discovered_areas(session):
        area = areas.get(int(area_id))
        if area is None:
            continue
        changed = _mark_explored_zone_bit(session, area) or changed

    if not changed:
        return

    char_guid = int(getattr(session, "char_guid", 0) or 0)
    realm_id = int(getattr(session, "realm_id", 1) or 1)
    if char_guid > 0:
        DatabaseConnection.save_character_explored_zones(
            char_guid,
            realm_id,
            str(getattr(session, "explored_zones_raw", "") or ""),
        )


def _load_achievements() -> dict[int, AchievementMeta]:
    global _ACHIEVEMENTS
    if _ACHIEVEMENTS is not None:
        return _ACHIEVEMENTS

    path = get_dbc_root() / "Achievement.dbc"
    achievements: dict[int, AchievementMeta] = {}
    if not path.exists():
        Logger.warning("[Achievement] Achievement.dbc missing")
        _ACHIEVEMENTS = achievements
        return achievements

    try:
        rows = read_dbc(path, ACHIEVEMENT_DBC_FMT)
    except Exception as exc:
        Logger.warning(f"[Achievement] Achievement.dbc load failed: {exc}")
        _ACHIEVEMENTS = achievements
        return achievements

    for row in rows:
        achievement_id = int(row[0] or 0)
        if achievement_id <= 0:
            continue
        achievements[achievement_id] = AchievementMeta(
            achievement_id=achievement_id,
            required_faction=int(row[1] or 0),
            map_id=int(row[2] or 0),
            parent_achievement=int(row[3] or 0),
            name=str(row[4] or ""),
            flags=int(row[7] or 0),
        )

    _ACHIEVEMENTS = achievements
    Logger.info("[Achievement] loaded achievements=%s", len(achievements))
    return achievements


def _load_criteria() -> dict[int, CriteriaMeta]:
    global _CRITERIA_BY_ID, _CRITERIA_BY_ACHIEVEMENT, _EXPLORE_CRITERIA_BY_AREA, _LEVEL_CRITERIA
    if _CRITERIA_BY_ID is not None:
        return _CRITERIA_BY_ID

    path = get_dbc_root() / "Achievement_Criteria.dbc"
    by_id: dict[int, CriteriaMeta] = {}
    by_achievement: dict[int, list[CriteriaMeta]] = {}
    explore_by_area: dict[int, list[CriteriaMeta]] = {}
    level_criteria: list[CriteriaMeta] = []

    if not path.exists():
        Logger.warning("[Achievement] Achievement_Criteria.dbc missing")
        _CRITERIA_BY_ID = by_id
        _CRITERIA_BY_ACHIEVEMENT = by_achievement
        _EXPLORE_CRITERIA_BY_AREA = explore_by_area
        _LEVEL_CRITERIA = level_criteria
        return by_id

    try:
        rows = read_dbc(path, ACHIEVEMENT_CRITERIA_DBC_FMT)
    except Exception as exc:
        Logger.warning(f"[Achievement] Achievement_Criteria.dbc load failed: {exc}")
        _CRITERIA_BY_ID = by_id
        _CRITERIA_BY_ACHIEVEMENT = by_achievement
        _EXPLORE_CRITERIA_BY_AREA = explore_by_area
        _LEVEL_CRITERIA = level_criteria
        return by_id

    for row in rows:
        criteria = CriteriaMeta(
            criteria_id=int(row[0] or 0),
            achievement_id=int(row[1] or 0),
            criteria_type=int(row[2] or 0),
            asset=int(row[3] or 0),
            quantity=max(1, int(row[4] or 1)),
            description=str(row[10] or ""),
        )
        if criteria.criteria_id <= 0 or criteria.achievement_id <= 0:
            continue
        by_id[criteria.criteria_id] = criteria
        by_achievement.setdefault(criteria.achievement_id, []).append(criteria)
        if criteria.criteria_type == ACHIEVEMENT_CRITERIA_TYPE_EXPLORE_AREA:
            explore_by_area.setdefault(criteria.asset, []).append(criteria)
        elif criteria.criteria_type == ACHIEVEMENT_CRITERIA_TYPE_REACH_LEVEL:
            level_criteria.append(criteria)

    _CRITERIA_BY_ID = by_id
    _CRITERIA_BY_ACHIEVEMENT = by_achievement
    _EXPLORE_CRITERIA_BY_AREA = explore_by_area
    _LEVEL_CRITERIA = sorted(level_criteria, key=lambda item: (item.quantity, item.criteria_id))
    Logger.info(
        "[Achievement] loaded criteria=%s explore=%s level=%s",
        len(by_id),
        sum(len(items) for items in explore_by_area.values()),
        len(level_criteria),
    )
    return by_id


def _criteria_by_achievement() -> dict[int, list[CriteriaMeta]]:
    _load_criteria()
    return _CRITERIA_BY_ACHIEVEMENT or {}


def _explore_criteria_by_area() -> dict[int, list[CriteriaMeta]]:
    _load_criteria()
    return _EXPLORE_CRITERIA_BY_AREA or {}


def _level_criteria() -> list[CriteriaMeta]:
    _load_criteria()
    return _LEVEL_CRITERIA or []


def _load_area_meta() -> dict[int, AreaMeta]:
    global _AREA_META_BY_ID
    if _AREA_META_BY_ID is not None:
        return _AREA_META_BY_ID

    path = get_dbc_root() / "AreaTable.dbc"
    area_meta: dict[int, AreaMeta] = {}
    if not path.exists():
        Logger.warning("[Explore] AreaTable.dbc missing")
        _AREA_META_BY_ID = area_meta
        return area_meta

    try:
        rows = read_dbc(path, AREA_TABLE_DBC_FMT)
    except Exception as exc:
        Logger.warning(f"[Explore] AreaTable.dbc load failed: {exc}")
        _AREA_META_BY_ID = area_meta
        return area_meta

    for row in rows:
        area_id = int(row[0] or 0)
        if area_id <= 0:
            continue
        area_meta[area_id] = AreaMeta(
            area_id=area_id,
            map_id=int(row[1] or 0),
            parent_area_id=int(row[2] or 0),
            explore_flag=int(row[3] or 0),
        )

    _AREA_META_BY_ID = area_meta
    Logger.info("[Explore] loaded areas=%s", len(area_meta))
    return area_meta


def _session_completed_achievements(session: Any) -> dict[int, int]:
    achievement_data = getattr(session, "achievements", None)
    if isinstance(achievement_data, dict) and "completed" in achievement_data:
        return {
            int(key): int(value or 0)
            for key, value in dict(achievement_data.get("completed") or {}).items()
        }
    completed = getattr(session, "achievement_completed", None)
    if isinstance(completed, dict):
        return completed
    completed = {}
    session.achievement_completed = completed
    return completed


def _session_completed_criteria(session: Any) -> dict[int, dict]:
    achievement_data = getattr(session, "achievements", None)
    if isinstance(achievement_data, dict) and "criteria" in achievement_data:
        return {
            int(key): dict(value or {})
            for key, value in dict(achievement_data.get("criteria") or {}).items()
        }
    progress = getattr(session, "achievement_criteria_progress", None)
    if isinstance(progress, dict):
        return progress
    progress = {}
    session.achievement_criteria_progress = progress
    return progress


def _session_discovered_areas(session: Any) -> dict[int, int]:
    discovered = getattr(session, "discovered_areas", None)
    if isinstance(discovered, dict):
        return discovered
    discovered = {}
    session.discovered_areas = discovered
    return discovered


def _complete_criteria(
    session: Any,
    criteria: CriteriaMeta,
    *,
    completed_at: int | None = None,
    persist: bool = True,
) -> tuple[bool, bytes | None]:
    completed = _session_completed_criteria(session)
    if criteria.criteria_id in completed:
        return False, None

    timestamp = int(completed_at or _now())
    completed[criteria.criteria_id] = {"counter": int(criteria.quantity), "completed_at": timestamp}
    if persist:
        DatabaseConnection.save_character_criteria_progress(
            int(getattr(session, "char_guid", 0) or 0),
            int(getattr(session, "realm_id", 1) or 1),
            int(criteria.criteria_id),
            int(criteria.quantity),
            timestamp,
        )

    Logger.info(
        "[Achievement] criteria complete id=%s achievement=%s player=%s",
        int(criteria.criteria_id),
        int(criteria.achievement_id),
        _player_name(session),
    )
    return True, build_criteria_update_payload(session, criteria.criteria_id, criteria.quantity, timestamp)


def _award_achievement(
    session: Any,
    achievement_id: int,
    *,
    completed_at: int | None = None,
    persist: bool = True,
) -> tuple[bool, bytes | None]:
    completed = _session_completed_achievements(session)
    achievement_id = int(achievement_id)
    if achievement_id <= 0 or achievement_id in completed:
        return False, None

    timestamp = int(completed_at or _now())
    completed[achievement_id] = timestamp
    if persist:
        DatabaseConnection.save_character_achievement_progress(
            int(getattr(session, "char_guid", 0) or 0),
            int(getattr(session, "realm_id", 1) or 1),
            achievement_id,
            timestamp,
        )

    Logger.info("[Achievement] earned id=%s player=%s", achievement_id, _player_name(session))
    return True, build_achievement_earned_payload(session, achievement_id, timestamp)


def _achievement_is_complete(session: Any, achievement_id: int) -> bool:
    required = _criteria_by_achievement().get(int(achievement_id), [])
    if not required:
        return False
    progress = _session_completed_criteria(session)
    return all(criteria.criteria_id in progress for criteria in required)


def _evaluate_achievement(session: Any, achievement_id: int, *, completed_at: int | None = None) -> bytes | None:
    if not _achievement_is_complete(session, int(achievement_id)):
        return None
    _earned, payload = _award_achievement(session, int(achievement_id), completed_at=completed_at)
    return payload


def initialize_session_achievements(session: Any) -> list[tuple[str, bytes]]:
    char_guid = int(getattr(session, "char_guid", 0) or 0)
    realm_id = int(getattr(session, "realm_id", 1) or 1)
    player_level = int(getattr(session, "level", 1) or 1)
    responses: list[tuple[str, bytes]] = []

    _load_achievements()
    _load_criteria()
    _load_area_meta()

    if char_guid > 0:
        _session_discovered_areas(session).update(
            DatabaseConnection.load_character_exploration(char_guid, realm_id)
        )
        _session_completed_criteria(session).update(
            DatabaseConnection.load_character_criteria_progress(char_guid, realm_id)
        )
        _session_completed_achievements(session).update(
            DatabaseConnection.load_character_achievement_progress(char_guid, realm_id)
        )

    _sync_explored_zone_bits_from_discovery(session)

    now = _now()
    for criteria in _level_criteria():
        Logger.info(
            "[Achievement] player_level=%s required=%s achievement=%s",
            player_level,
            int(criteria.quantity),
            int(criteria.achievement_id),
        )
        if player_level < int(criteria.quantity):
            continue
        changed, payload = _complete_criteria(session, criteria, completed_at=now)
        if changed and payload:
            responses.append(("SMSG_CRITERIA_UPDATE", payload))
        earned_payload = _evaluate_achievement(session, criteria.achievement_id, completed_at=now)
        if earned_payload:
            responses.append(("SMSG_ACHIEVEMENT_EARNED", earned_payload))

    current_area = int(getattr(session, "zone", 0) or 0)
    if current_area > 0:
        responses.extend(discover_area(session, current_area, send_map_update=False))

    Logger.info(
        "[Achievement] login sync player=%s player_level=%s completed=%s criteria=%s explored=%s",
        _player_name(session),
        player_level,
        len(_session_completed_achievements(session)),
        len(_session_completed_criteria(session)),
        len(_session_discovered_areas(session)),
    )
    return responses


def discover_area(session: Any, area_id: int, *, send_map_update: bool = True) -> list[tuple[str, bytes]]:
    area_id = int(area_id or 0)
    if area_id <= 0:
        return []

    area = _load_area_meta().get(area_id)
    if area is None:
        return []

    discovered = _session_discovered_areas(session)
    if area_id in discovered:
        return []

    timestamp = _now()
    discovered[area_id] = timestamp
    char_guid = int(getattr(session, "char_guid", 0) or 0)
    realm_id = int(getattr(session, "realm_id", 1) or 1)

    if char_guid > 0:
        DatabaseConnection.save_character_exploration(char_guid, realm_id, area_id, timestamp)

    if _mark_explored_zone_bit(session, area) and char_guid > 0:
        DatabaseConnection.save_character_explored_zones(
            char_guid,
            realm_id,
            str(getattr(session, "explored_zones_raw", "") or ""),
        )

    Logger.info(
        "[Explore] discovered area=%s zone=%s player=%s",
        area_id,
        int(getattr(session, "zone", 0) or 0),
        _player_name(session),
    )

    responses: list[tuple[str, bytes]] = []
    if send_map_update:
        explored_response = build_explored_zones_update_response(session)
        if explored_response is not None:
            responses.append(explored_response)

    for criteria in _explore_criteria_by_area().get(area_id, []):
        changed, criteria_payload = _complete_criteria(session, criteria, completed_at=timestamp)
        if changed and criteria_payload:
            responses.append(("SMSG_CRITERIA_UPDATE", criteria_payload))
        earned_payload = _evaluate_achievement(session, criteria.achievement_id, completed_at=timestamp)
        if earned_payload:
            responses.append(("SMSG_ACHIEVEMENT_EARNED", earned_payload))

    return responses


def build_all_achievement_data_payload(ctx: Any) -> bytes:
    achievements = sorted(_session_completed_achievements(ctx).items())
    criteria = sorted(_session_completed_criteria(ctx).items())
    guid = _world_guid(ctx)
    raw_guid = _guid_bytes(guid)
    realm_id = int(getattr(ctx, "realm_id", 1) or 1)

    bits = BitWriter()
    bits.write_bits(len(criteria), 19)
    for _criteria_id, progress in criteria:
        counter_guid = int(progress.get("counter", 1) or 1)
        _write_guid_bits(bits, _guid_bytes(counter_guid), (1, 6, 3, 0, 4, 7, 2, 5))
    bits.write_bits(len(achievements), 20)
    for _achievement_id, _completion_time in achievements:
        _write_guid_bits(bits, raw_guid, (0, 7, 1, 5, 2, 4, 6, 3))

    payload = bytearray(bits.getvalue())
    for achievement_id, completion_time in achievements:
        payload.extend(struct.pack("<II", int(achievement_id), realm_id))
        _append_xor_guid_bytes(payload, raw_guid, (5, 7))
        payload.extend(struct.pack("<II", realm_id, _packed_wow_time(int(completion_time or _now()))))
        _append_xor_guid_bytes(payload, raw_guid, (0, 4, 1, 6, 2, 3))

    for criteria_id, progress in criteria:
        counter = int(progress.get("counter", 1) or 1)
        completed_at = int(progress.get("completed_at", 0) or _now())
        counter_raw = _guid_bytes(counter)
        payload.extend(struct.pack("<i", int(criteria_id)))
        _append_xor_guid_bytes(payload, counter_raw, (3, 6, 2))
        payload.extend(struct.pack("<q", counter))
        _append_xor_guid_bytes(payload, counter_raw, (5, 1))
        payload.extend(struct.pack("<Iii", _packed_wow_time(completed_at), 0, 0))
        _append_xor_guid_bytes(payload, counter_raw, (4, 7, 0))

    return bytes(payload)


def build_criteria_update_payload(
    session: Any,
    criteria_id: int,
    counter: int = 1,
    completed_at: int | None = None,
) -> bytes:
    counter_raw = _guid_bytes(int(counter or 1))
    bits = BitWriter()
    _write_guid_bits(bits, counter_raw, (4, 6, 2, 3, 7, 1, 5, 0))
    payload = bytearray(bits.getvalue())
    _append_xor_guid_bytes(payload, counter_raw, (3, 6, 2))
    payload.extend(struct.pack("<ii", int(criteria_id), 0))
    _append_xor_guid_bytes(payload, counter_raw, (5, 1))
    payload.extend(struct.pack("<Iii", _packed_wow_time(completed_at), 0, 0))
    _append_xor_guid_bytes(payload, counter_raw, (4, 7, 0))
    payload.extend(struct.pack("<q", int(counter or 1)))
    return bytes(payload)


def build_achievement_earned_payload(
    session: Any,
    achievement_id: int,
    completion_time: int | None = None,
) -> bytes:
    raw = _guid_bytes(_world_guid(session))
    raw2 = raw
    bits = BitWriter()
    for raw_value, index in (
        (raw2, 6),
        (raw2, 2),
        (raw, 4),
        (raw, 5),
        (raw, 0),
        (raw, 3),
    ):
        bits.write_bits(1 if raw_value[index] else 0, 1)
    bits.write_bits(0, 1)
    for raw_value, index in (
        (raw2, 7),
        (raw, 7),
        (raw, 1),
        (raw2, 3),
        (raw2, 0),
        (raw2, 4),
        (raw, 6),
        (raw2, 1),
        (raw, 2),
        (raw2, 5),
    ):
        bits.write_bits(1 if raw_value[index] else 0, 1)

    payload = bytearray(bits.getvalue())
    _append_xor_guid_bytes(payload, raw2, (5,))
    _append_xor_guid_bytes(payload, raw, (3,))
    _append_xor_guid_bytes(payload, raw2, (6,))
    _append_xor_guid_bytes(payload, raw, (6,))
    payload.extend(struct.pack("<I", _packed_wow_time(completion_time)))
    _append_xor_guid_bytes(payload, raw2, (1,))
    _append_xor_guid_bytes(payload, raw, (2, 0, 7))
    _append_xor_guid_bytes(payload, raw2, (3,))
    _append_xor_guid_bytes(payload, raw, (4,))
    _append_xor_guid_bytes(payload, raw2, (7,))
    payload.extend(struct.pack("<I", int(achievement_id)))
    _append_xor_guid_bytes(payload, raw2, (4,))
    _append_xor_guid_bytes(payload, raw, (1, 5))
    return bytes(payload)
