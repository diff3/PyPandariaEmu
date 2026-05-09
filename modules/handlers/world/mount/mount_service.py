#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from typing import Any

try:
    from sqlalchemy import text
except ImportError:
    def text(sql: str) -> str:
        return sql

from shared.Logger import Logger
from shared.PathUtils import get_dbc_root
from server.modules.dbc import read_dbc

ALL_MOUNT_SPELLS: set[int] = set()
_DBC_SPELL_EFFECT_FMT = "i" * 30
_DBC_MOUNT_TYPE_FMT = "i" * 25
_DBC_MOUNT_CAPABILITY_FMT = "i" * 8
_SPELL_EFFECT_EFFECT_INDEX = 2
_SPELL_EFFECT_AURA_INDEX = 4
_SPELL_EFFECT_MISC_VALUE_INDEX = 13
_SPELL_EFFECT_MISC_VALUE_B_INDEX = 14
_SPELL_EFFECT_SPELL_ID_INDEX = 27
_SPELL_EFFECT_APPLY_AURA = 6
_SPELL_AURA_MOUNTED = 78
_MOUNT_CAPABILITY_FLAGS_INDEX = 1
_MOUNT_CAPABILITY_FLYING_FLAGS = {7, 15}
_FLYING_MOUNT_NAME_MARKERS = (
    "al'ar",
    "broom",
    "carpet",
    "cloud serpent",
    "dragonhawk",
    "drake",
    "flying",
    "flying cloud",
    "frostbrood",
    "frost wyrm",
    "gryphon",
    "hippogryph",
    "nether ray",
    "rocket",
    "wind rider",
    "winged steed",
)
MOUNT_RIDING_SKILL_ID = 762
MOUNT_RIDING_SKILL_VALUE = 375
MOUNT_SUPPORT_SPELLS: tuple[int, ...] = (
    33388,   # Apprentice Riding
    33391,   # Journeyman Riding
    34090,   # Expert Riding
    34091,   # Artisan Riding
    54197,   # Cold Weather Flying
    90265,   # Master Riding
    90267,   # Flight Master's License
    115913,  # Wisdom of the Four Winds
    130487,  # Cloud Serpent Riding
)
FALLBACK_MOUNT_SPELLS: tuple[int, ...] = (
    # Minimal no-DBC/no-world-DB fallback. The normal path loads every mount
    # and display ID from SpellEffect.dbc + creature_template.
    458,    # Brown Horse
    72286,  # Invincible
)
MOUNT_DISPLAY_BY_SPELL: dict[int, int] = {
    458: 2404,       # Brown Horse
    72286: 31007,    # Invincible
}
FLYING_MOUNT_SPELLS: set[int] = {
    72286,  # Invincible
}
DEFAULT_TEST_MOUNT_DISPLAY_ID = 31007


def _row_value(row: Any, attr: str, index: int) -> Any:
    if hasattr(row, attr):
        return getattr(row, attr)
    return row[index]


def _table_exists(db, table_name: str) -> bool:
    query = text(
        """
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = :table_name
        LIMIT 1
        """
    )
    row = db.execute(query, {"table_name": str(table_name)}).fetchone()
    return row is not None


def _is_flying_mount_name(name: str) -> bool:
    lowered = str(name or "").lower()
    return any(marker in lowered for marker in _FLYING_MOUNT_NAME_MARKERS)


def _load_flying_mount_type_ids_from_dbc(dbc_root) -> set[int]:
    mount_type_path = dbc_root / "MountType.dbc"
    mount_capability_path = dbc_root / "MountCapability.dbc"
    if not mount_type_path.is_file() or not mount_capability_path.is_file():
        return set()

    flying_capability_ids: set[int] = set()
    try:
        for record in read_dbc(mount_capability_path, _DBC_MOUNT_CAPABILITY_FMT):
            capability_id = int(record[0] or 0)
            flags = int(record[_MOUNT_CAPABILITY_FLAGS_INDEX] or 0)
            if capability_id > 0 and flags in _MOUNT_CAPABILITY_FLYING_FLAGS:
                flying_capability_ids.add(capability_id)
    except Exception as exc:
        Logger.warning("[Mount] Failed to read MountCapability.dbc: %s", exc)
        return set()

    if not flying_capability_ids:
        return set()

    flying_mount_type_ids: set[int] = set()
    try:
        for record in read_dbc(mount_type_path, _DBC_MOUNT_TYPE_FMT):
            mount_type_id = int(record[0] or 0)
            if mount_type_id <= 0:
                continue
            capability_ids = {int(value or 0) for value in record[1:] if int(value or 0) > 0}
            if capability_ids & flying_capability_ids:
                flying_mount_type_ids.add(mount_type_id)
    except Exception as exc:
        Logger.warning("[Mount] Failed to read MountType.dbc: %s", exc)
        return set()

    return flying_mount_type_ids


def _load_mount_spell_rows_from_dbc(db) -> tuple[list[tuple[int, int, bool]], str | None]:
    if not _table_exists(db, "creature_template"):
        return [], None

    dbc_root = get_dbc_root()
    if not dbc_root:
        return [], None
    spell_effect_path = dbc_root / "SpellEffect.dbc"
    if not spell_effect_path.is_file():
        return [], None

    creature_by_spell: dict[int, int] = {}
    mount_type_by_spell: dict[int, int] = {}
    try:
        for record in read_dbc(spell_effect_path, _DBC_SPELL_EFFECT_FMT):
            if int(record[_SPELL_EFFECT_EFFECT_INDEX] or 0) != _SPELL_EFFECT_APPLY_AURA:
                continue
            if int(record[_SPELL_EFFECT_AURA_INDEX] or 0) != _SPELL_AURA_MOUNTED:
                continue
            spell_id = int(record[_SPELL_EFFECT_SPELL_ID_INDEX] or 0)
            creature_id = int(record[_SPELL_EFFECT_MISC_VALUE_INDEX] or 0)
            mount_type_id = int(record[_SPELL_EFFECT_MISC_VALUE_B_INDEX] or 0)
            if spell_id > 0 and creature_id > 0:
                creature_by_spell.setdefault(spell_id, creature_id)
                if mount_type_id > 0:
                    mount_type_by_spell.setdefault(spell_id, mount_type_id)
    except Exception as exc:
        Logger.warning("[Mount] Failed to read SpellEffect.dbc: %s", exc)
        return [], None

    if not creature_by_spell:
        return [], None

    creature_ids = sorted(set(creature_by_spell.values()))
    creature_sql = ",".join(str(int(creature_id)) for creature_id in creature_ids)
    rows = db.execute(
        text(
            f"""
            SELECT entry, name, modelid1
            FROM creature_template
            WHERE entry IN ({creature_sql}) AND modelid1 > 0
            """
        )
    ).fetchall()

    creature_info: dict[int, tuple[str, int]] = {}
    for row in rows:
        try:
            entry = int(_row_value(row, "entry", 0) or 0)
            name = str(_row_value(row, "name", 1) or "")
            display_id = int(_row_value(row, "modelid1", 2) or 0)
        except Exception:
            continue
        if entry > 0 and display_id > 0:
            creature_info[entry] = (name, display_id)

    flying_mount_type_ids = _load_flying_mount_type_ids_from_dbc(dbc_root)
    mount_rows: list[tuple[int, int, bool]] = []
    for spell_id, creature_id in creature_by_spell.items():
        info = creature_info.get(int(creature_id))
        if not info:
            continue
        name, display_id = info
        mount_type_id = int(mount_type_by_spell.get(int(spell_id), 0) or 0)
        is_flying = (
            bool(mount_type_id and mount_type_id in flying_mount_type_ids)
            or _is_flying_mount_name(name)
        )
        mount_rows.append((int(spell_id), int(display_id), bool(is_flying)))
    return mount_rows, "SpellEffect.dbc+creature_template"


def _load_mount_spell_rows(db):
    if _table_exists(db, "spell_effect"):
        return db.execute(
            text(
                """
                SELECT DISTINCT spell
                FROM spell_effect
                WHERE effect IN (6, 35)
                """
            )
        ).fetchall(), "spell_effect"

    dbc_rows, source = _load_mount_spell_rows_from_dbc(db)
    if dbc_rows:
        return dbc_rows, source

    return [], None


def load_mount_spells(db) -> None:
    """
    Load all mount-related spells from the world DB into memory once.
    """
    rows, source = _load_mount_spell_rows(db)

    ALL_MOUNT_SPELLS.clear()
    for row in rows:
        try:
            spell_id = int(_row_value(row, "spell", 0) or 0)
        except Exception:
            continue
        if spell_id > 0:
            ALL_MOUNT_SPELLS.add(spell_id)
            try:
                display_id = int(_row_value(row, "display_id", 1) or 0)
                if display_id > 0:
                    MOUNT_DISPLAY_BY_SPELL[spell_id] = display_id
            except Exception:
                pass
            try:
                if bool(_row_value(row, "is_flying", 2)):
                    FLYING_MOUNT_SPELLS.add(spell_id)
            except Exception:
                pass

    if not ALL_MOUNT_SPELLS:
        _load_fallback_mount_spells()
        return

    Logger.info("[Mount] Loaded %s mounts source=%s", len(ALL_MOUNT_SPELLS), source or "unknown")


def is_mount_spell(spell_id: int) -> bool:
    try:
        return int(spell_id) in ALL_MOUNT_SPELLS
    except Exception:
        return False


def is_flying_mount_spell(spell_id: int) -> bool:
    try:
        return int(spell_id) in FLYING_MOUNT_SPELLS
    except Exception:
        return False


def _load_fallback_mount_spells() -> None:
    ALL_MOUNT_SPELLS.clear()
    ALL_MOUNT_SPELLS.update(int(spell_id) for spell_id in FALLBACK_MOUNT_SPELLS)
    Logger.info("[Mount] Loaded %s mounts", len(ALL_MOUNT_SPELLS))


def granted_mount_spells() -> list[int]:
    spells = {int(spell_id) for spell_id in ALL_MOUNT_SPELLS}
    spells.update(int(spell_id) for spell_id in MOUNT_SUPPORT_SPELLS)
    return sorted(spells)


def get_mount_display_id(spell_id: int) -> int:
    try:
        normalized_spell_id = int(spell_id)
        explicit_display = int(MOUNT_DISPLAY_BY_SPELL.get(normalized_spell_id, 0) or 0)
        if explicit_display > 0:
            return explicit_display
        if normalized_spell_id in ALL_MOUNT_SPELLS:
            return int(DEFAULT_TEST_MOUNT_DISPLAY_ID)
        return 0
    except Exception:
        return 0
