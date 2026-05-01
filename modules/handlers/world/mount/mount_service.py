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

ALL_MOUNT_SPELLS: set[int] = set()
MOUNT_RIDING_SKILL_ID = 762
MOUNT_RIDING_SKILL_VALUE = 375
MOUNT_SUPPORT_SPELLS: tuple[int, ...] = (
    33388,   # Apprentice Riding
    33391,   # Journeyman Riding
    34090,   # Expert Riding
    34091,   # Artisan Riding
    54197,   # Cold Weather Flying
    115913,  # Wisdom of the Four Winds
)
FALLBACK_MOUNT_SPELLS: tuple[int, ...] = (
    458,    # Brown Horse
    470,    # Black Stallion
    580,    # Timber Wolf
    6648,   # Chestnut Mare
    59535,  # Black Polar Bear
    59542,  # Black War Mammoth
    61437,  # Grand Ice Mammoth
    61455,  # Grand Black War Mammoth
    63644,  # Argent Hippogryph
    63645,  # White Skeletal Warhorse
    68398,  # Big Love Rocket
    68975,  # Wooly White Rhino
    68976,  # X-53 Touring Rocket
    68978,  # White Kodo
    68992,  # Green Kodo
    68996,  # Brown Kodo
    76271,  # X-53 Touring Rocket
    76282,  # X-53 Touring Rocket
    76292,  # X-53 Touring Rocket
    76294,  # X-53 Touring Rocket
    79741,  # Vicious War Steed
    79742,  # Vicious War Wolf
    82246,  # Vicious War Steed
    87840,  # Azure Water Strider
    89832,  # Drake of the West Wind
    89964,  # Vicious War Wolf
    94293,  # Vicious War Steed
    96220,  # Swift Red Hawkstrider
    111621, # Yak
    113873, # Pandaren Kite
    134735, # Grand Expedition Yak
    72286,  # Invincible
    32235,  # Golden Gryphon
    61425,  # Traveler's Tundra Mammoth
    34769,  # Summon Warhorse
    578,    # Summon Felsteed
)
MOUNT_DISPLAY_BY_SPELL: dict[int, int] = {
    458: 2404,       # Brown Horse
    470: 2402,       # Black Stallion
    578: 2346,       # Felsteed
    580: 247,        # Timber Wolf
    6648: 2405,      # Chestnut Mare
    32235: 17697,    # Golden Gryphon
    34769: 19296,    # Thalassian Warhorse
    59535: 27659,    # Black Polar Bear Mount
    59542: 27247,    # Black War Mammoth
    61425: 27237,    # Traveler's Tundra Mammoth
    61437: 27239,    # Grand Ice Mammoth
    61455: 27240,    # Grand Black War Mammoth
    63644: 22471,    # Argent Hippogryph
    63645: 28605,    # White Skeletal Warhorse
    68398: 30989,    # Big Love Rocket
    68975: 31721,    # Wooly White Rhino
    68976: 31992,    # X-53 Touring Rocket
    68978: 12241,    # White Kodo
    68992: 12245,    # Green Kodo
    68996: 11641,    # Brown Kodo
    76271: 31992,    # X-53 Touring Rocket
    76282: 31992,    # X-53 Touring Rocket
    76292: 31992,    # X-53 Touring Rocket
    76294: 31992,    # X-53 Touring Rocket
    79741: 38668,    # Vicious War Steed
    79742: 38607,    # Vicious War Wolf
    82246: 38668,    # Vicious War Steed
    87840: 41711,    # Azure Water Strider
    89832: 35754,    # Drake of the West Wind
    89964: 38607,    # Vicious War Wolf
    94293: 38668,    # Vicious War Steed
    96220: 28607,    # Swift Red Hawkstrider
    111621: 41089,   # White Riding Yak
    113873: 41903,   # Pandaren Kite
    134735: 42703,   # Grand Expedition Yak
    72286: 31007,    # Invincible
}
FLYING_MOUNT_SPELLS: frozenset[int] = frozenset(
    {
        32235,  # Golden Gryphon
        63644,  # Argent Hippogryph
        68398,  # Big Love Rocket
        68976,  # X-53 Touring Rocket
        72286,  # Invincible
        76271,  # X-53 Touring Rocket
        76282,  # X-53 Touring Rocket
        76292,  # X-53 Touring Rocket
        76294,  # X-53 Touring Rocket
        89832,  # Drake of the West Wind
        113873, # Pandaren Kite
    }
)
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

    if not ALL_MOUNT_SPELLS:
        _load_fallback_mount_spells()
        return

    Logger.info("[Mount] Loaded %s mounts", len(ALL_MOUNT_SPELLS))


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
