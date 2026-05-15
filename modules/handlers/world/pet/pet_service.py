#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import struct
from typing import Any

try:
    from sqlalchemy import text
except ImportError:
    def text(sql: str) -> str:
        return sql

from DSL.modules.bitsHandler import BitWriter
from shared.Logger import Logger
from shared.PathUtils import get_dbc_root, get_project_root

BATTLE_PET_TRAINING_SPELLS: tuple[int, ...] = (
    119467,  # Battle Pet Training
    122026,  # Track Pets
    125439,  # Revive Battle Pets
)
BATTLE_PET_JOURNAL_FLAG_COLLECTED = 0x02
BATTLE_PET_DEFAULT_JOURNAL_FLAGS = 0
BATTLE_PET_MAX_LOADOUT_SLOTS = 3
BATTLE_PET_FALLBACK_SPECIES: tuple[tuple[int, int, int], ...] = (
    # species, creature, spell
    (1204, 70082, 138824),  # Pierre
)
BATTLE_PET_DEBUG_WHITELIST_ENABLED = False
BATTLE_PET_FILTER_VALID_ENABLED = False
BATTLE_PET_SPECIES_WHITELIST: tuple[int, ...] = ()
BATTLE_PET_DEBUG_WHITELIST_SPECIES: tuple[int, ...] = (
    39,  # Mechanical Squirrel
    40,  # Bombay Cat
    41,  # Cornish Rex Cat
    42,  # Black Tabby Cat
    43,  # Orange Tabby Cat
    44,  # Siamese Cat
    45,  # Silver Tabby Cat
    46,  # White Kitten
    47,  # Cockatiel
    49,  # Hyacinth Macaw
)


@dataclass(frozen=True)
class BattlePetJournalEntry:
    species_id: int
    creature_id: int
    spell_id: int
    species_flags: int = 0
    display_id: int = 0


ALL_BATTLE_PETS: tuple[BattlePetJournalEntry, ...] = ()


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


def _candidate_battle_pet_species_paths() -> list[Path]:
    paths: list[Path] = []

    env_path = os.getenv("PP_BATTLE_PET_SPECIES_DB2", "").strip()
    if env_path:
        paths.append(Path(env_path))

    dbc_root = get_dbc_root()
    if dbc_root:
        root = Path(dbc_root)
        paths.extend([
            root / "BattlePetSpecies.db2",
            root / "DBFilesClient" / "BattlePetSpecies.db2",
            root.parent / "db2" / "BattlePetSpecies.db2",
            root.parent / "DBFilesClient" / "BattlePetSpecies.db2",
        ])

    project_root = get_project_root()
    paths.extend([
        project_root / "data" / "dbc" / "BattlePetSpecies.db2",
        project_root / "data" / "db2" / "BattlePetSpecies.db2",
        project_root.parent / "mistofpandaria" / "BattlePetSpecies.db2",
    ])

    unique_paths: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.expanduser()
        if not resolved.is_absolute():
            resolved = (project_root / resolved).resolve()
        else:
            resolved = resolved.resolve()
        if resolved not in seen:
            unique_paths.append(resolved)
            seen.add(resolved)
    return unique_paths


def _read_battle_pet_species_db2(path: Path) -> list[tuple[int, int, int, int]]:
    rows: list[tuple[int, int, int, int]] = []
    with path.open("rb") as f:
        magic, record_count, field_count, record_size, _string_size = struct.unpack("<4sIIII", f.read(20))
        if magic != b"WDB2":
            raise RuntimeError(f"Invalid BattlePetSpecies DB2 header: {magic!r}")
        if field_count < 7 or record_size < field_count * 4:
            raise RuntimeError(
                f"Unsupported BattlePetSpecies DB2 layout fields={field_count} size={record_size}"
            )
        # MoP WDB2 has seven more uint32 header fields after string size.
        f.read(28)
        for _ in range(record_count):
            record = f.read(record_size)
            if len(record) != record_size:
                raise RuntimeError("Unexpected EOF while reading BattlePetSpecies.db2")
            fields = struct.unpack_from("<" + ("I" * field_count), record)
            species_id = int(fields[0] or 0)
            creature_id = int(fields[1] or 0)
            spell_id = int(fields[3] or 0)
            species_flags = int(fields[6] or 0)
            if species_id > 0 and species_id < 0xFFFF and creature_id > 0:
                rows.append((species_id, creature_id, spell_id, species_flags))
    return rows


def _load_battle_pet_species_rows() -> tuple[list[tuple[int, int, int, int]], str | None]:
    for path in _candidate_battle_pet_species_paths():
        if not path.is_file():
            continue
        try:
            rows = _read_battle_pet_species_db2(path)
        except Exception as exc:
            Logger.warning("[BattlePet] failed to read %s: %s", path, exc)
            continue
        if rows:
            return rows, str(path)
    return [], None


def _load_display_ids(db, creature_ids: list[int]) -> dict[int, int]:
    if not creature_ids or db is None:
        return {}
    try:
        if not _table_exists(db, "creature_template"):
            return {}
    except Exception as exc:
        Logger.warning("[BattlePet] creature_template check failed: %s", exc)
        return {}

    display_by_creature: dict[int, int] = {}
    for start in range(0, len(creature_ids), 500):
        batch = creature_ids[start:start + 500]
        creature_sql = ",".join(str(int(creature_id)) for creature_id in batch)
        try:
            rows = db.execute(
                text(
                    f"""
                    SELECT entry, modelid1
                    FROM creature_template
                    WHERE entry IN ({creature_sql}) AND modelid1 > 0
                    """
                )
            ).fetchall()
        except Exception as exc:
            Logger.warning("[BattlePet] display query failed: %s", exc)
            return display_by_creature
        for row in rows:
            try:
                entry = int(_row_value(row, "entry", 0) or 0)
                display_id = int(_row_value(row, "modelid1", 1) or 0)
            except Exception:
                continue
            if entry > 0 and display_id > 0:
                display_by_creature[entry] = display_id
    return display_by_creature


def _row_value(row: Any, attr: str, index: int) -> Any:
    if hasattr(row, attr):
        return getattr(row, attr)
    return row[index]


def load_battle_pets(db=None) -> None:
    global ALL_BATTLE_PETS

    rows, source = _load_battle_pet_species_rows()
    if not rows:
        rows = [(species_id, creature_id, spell_id, 0) for species_id, creature_id, spell_id in BATTLE_PET_FALLBACK_SPECIES]
        source = "fallback"

    unique_rows = sorted(set(rows), key=lambda item: item[0])
    display_by_creature = _load_display_ids(db, sorted({row[1] for row in unique_rows}))
    ALL_BATTLE_PETS = tuple(
            BattlePetJournalEntry(
                species_id=int(species_id),
                creature_id=int(creature_id),
                spell_id=int(spell_id),
                species_flags=int(species_flags),
                display_id=int(display_by_creature.get(int(creature_id), 0) or 0),
            )
        for species_id, creature_id, spell_id, species_flags in unique_rows
    )
    Logger.info("[BattlePet] Loaded %s journal pets source=%s", len(ALL_BATTLE_PETS), source or "unknown")


def granted_battle_pet_spells() -> list[int]:
    return []


def battle_pet_summon_spells() -> set[int]:
    if not ALL_BATTLE_PETS:
        load_battle_pets(None)
    summon_spells = {
        int(pet.spell_id)
        for pet in ALL_BATTLE_PETS
        if int(pet.spell_id) > 0
    }
    summon_spells.update(
        int(spell_id)
        for spell_id in BATTLE_PET_TRAINING_SPELLS
        if int(spell_id) > 0
    )
    return summon_spells


def _env_enabled(name: str) -> bool:
    value = os.getenv(name, "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _env_species_whitelist() -> set[int]:
    raw_value = os.getenv("PP_BATTLE_PET_SPECIES_WHITELIST", "").strip()
    if not raw_value:
        return set()

    species_ids: set[int] = set()
    for value in raw_value.replace(";", ",").split(","):
        try:
            species_id = int(value.strip())
        except Exception:
            continue
        if species_id > 0:
            species_ids.add(species_id)
    return species_ids


def _journal_pets() -> list[BattlePetJournalEntry]:
    pets = list(ALL_BATTLE_PETS)
    whitelist = set(int(species_id) for species_id in BATTLE_PET_SPECIES_WHITELIST)
    mode = "all"

    if whitelist:
        pets = [pet for pet in pets if int(pet.species_id) in whitelist]
        mode = "explicit_whitelist"
    elif BATTLE_PET_DEBUG_WHITELIST_ENABLED or _env_enabled("PP_BATTLE_PET_DEBUG_WHITELIST"):
        whitelist = set(
            int(species_id)
            for species_id in BATTLE_PET_DEBUG_WHITELIST_SPECIES
        )
        pets = [pet for pet in pets if int(pet.species_id) in whitelist]
        mode = "debug_whitelist"
    elif BATTLE_PET_FILTER_VALID_ENABLED or _env_enabled("PP_BATTLE_PET_FILTER_VALID"):
        pets = [
            pet
            for pet in pets
            if (
                int(pet.spell_id) > 0
                and int(pet.creature_id) > 0
                and int(pet.display_id) > 0
            )
        ]
        mode = "valid_spell_display"

    Logger.info("[BattlePet] journal pets mode=%s count=%s", mode, len(pets))
    return pets


def build_battle_pet_journal_lock_payload() -> bytes:
    return b""


def _guid_bytes(value: int) -> list[int]:
    return [(int(value) >> (index * 8)) & 0xFF for index in range(8)]


def _write_guid_bits(bits: BitWriter, guid: list[int], order: tuple[int, ...]) -> None:
    for index in order:
        bits.write_bits(1 if int(guid[index]) else 0, 1)


def _append_guid_bytes(payload: bytearray, guid: list[int], order: tuple[int, ...]) -> None:
    for index in order:
        value = int(guid[index]) & 0xFF
        if value:
            payload.append(value)


def _battle_pet_guid(species_id: int) -> int:
    return int(species_id) & 0xFFFFFFFF


def battle_pet_guid_for_species(species_id: int) -> int:
    return _battle_pet_guid(int(species_id))


def battle_pet_by_guid(guid: int) -> BattlePetJournalEntry | None:
    if not ALL_BATTLE_PETS:
        load_battle_pets(None)

    species_id = int(guid) & 0xFFFFFFFF
    for pet in ALL_BATTLE_PETS:
        if int(pet.species_id) == int(species_id):
            return pet
    return None


def battle_pet_by_spell(spell_id: int) -> BattlePetJournalEntry | None:
    if not ALL_BATTLE_PETS:
        load_battle_pets(None)

    for pet in ALL_BATTLE_PETS:
        if int(pet.spell_id) == int(spell_id) and int(spell_id) > 0:
            return pet
    return None


def _journal_flags(_pet: BattlePetJournalEntry) -> int:
    return BATTLE_PET_DEFAULT_JOURNAL_FLAGS


def build_battle_pet_update_payload(
    pet: BattlePetJournalEntry,
    notification: bool = True,
) -> bytes:
    guid = _guid_bytes(_battle_pet_guid(int(pet.species_id)))
    journal_flags = _journal_flags(pet)
    bits = BitWriter()

    bits.write_bits(1, 19)
    bits.write_bits(1 if guid[4] else 0, 1)
    bits.write_bits(1 if guid[1] else 0, 1)
    bits.write_bits(1 if guid[7] else 0, 1)
    bits.write_bits(0, 1)  # has quality
    bits.write_bits(0, 1)  # has breed
    bits.write_bits(1 if guid[5] else 0, 1)
    bits.write_bits(0, 1)
    bits.write_bits(1 if guid[2] else 0, 1)
    bits.write_bits(1 if journal_flags == 0 else 0, 1)
    bits.write_bits(0, 1)  # account bound
    bits.write_bits(1 if guid[6] else 0, 1)
    bits.write_bits(1 if guid[3] else 0, 1)
    bits.write_bits(0, 7)  # nickname length
    bits.write_bits(1 if guid[0] else 0, 1)
    bits.write_bits(1 if notification else 0, 1)

    payload = bytearray(bits.getvalue())
    _append_guid_bytes(payload, guid, (1,))
    payload.extend(struct.pack("<I", 1400))
    payload.extend(struct.pack("<I", int(pet.species_id)))
    _append_guid_bytes(payload, guid, (0,))
    payload.extend(struct.pack("<I", 260))
    payload.extend(struct.pack("<I", 260))
    payload.extend(struct.pack("<H", 3))
    _append_guid_bytes(payload, guid, (4,))
    payload.extend(struct.pack("<I", int(pet.creature_id)))
    payload.extend(struct.pack("<I", 1400))
    _append_guid_bytes(payload, guid, (6,))
    payload.extend(struct.pack("<B", 3))
    _append_guid_bytes(payload, guid, (2, 3))
    payload.extend(struct.pack("<H", 0))
    _append_guid_bytes(payload, guid, (7,))
    if journal_flags:
        payload.extend(struct.pack("<H", journal_flags))
    _append_guid_bytes(payload, guid, (5,))
    payload.extend(struct.pack("<I", int(pet.display_id)))
    payload.extend(struct.pack("<H", 25))
    return bytes(payload)


def build_battle_pet_journal_payload() -> bytes:
    if not ALL_BATTLE_PETS:
        load_battle_pets(None)

    pets = _journal_pets()
    bits = BitWriter()
    journal_data = bytearray()
    slot_data = bytearray()

    bits.write_bits(len(pets), 19)
    for pet in pets:
        guid = _guid_bytes(_battle_pet_guid(int(pet.species_id)))
        journal_flags = _journal_flags(pet)
        bits.write_bits(1 if journal_flags == 0 else 0, 1)
        bits.write_bits(1 if guid[3] else 0, 1)
        bits.write_bits(1 if guid[7] else 0, 1)
        bits.write_bits(0, 7)  # nickname length
        bits.write_bits(0, 1)  # account bound
        bits.write_bits(1 if guid[0] else 0, 1)
        bits.write_bits(1 if guid[2] else 0, 1)
        bits.write_bits(1 if guid[6] else 0, 1)
        bits.write_bits(0, 1)
        bits.write_bits(1 if guid[1] else 0, 1)
        bits.write_bits(1 if guid[5] else 0, 1)
        bits.write_bits(0, 1)  # has breed
        bits.write_bits(1 if guid[4] else 0, 1)
        bits.write_bits(0, 1)  # has quality

        journal_data.extend(struct.pack("<B", 3))
        journal_data.extend(struct.pack("<I", 260))
        _append_guid_bytes(journal_data, guid, (7,))
        journal_data.extend(struct.pack("<H", 25))
        journal_data.extend(struct.pack("<I", 1400))
        journal_data.extend(struct.pack("<H", 3))
        journal_data.extend(struct.pack("<I", int(pet.species_id)))
        _append_guid_bytes(journal_data, guid, (2,))
        if journal_flags:
            journal_data.extend(struct.pack("<H", journal_flags))
        journal_data.extend(struct.pack("<I", int(pet.creature_id)))
        journal_data.extend(struct.pack("<I", int(pet.display_id)))
        journal_data.extend(struct.pack("<I", 260))
        _append_guid_bytes(journal_data, guid, (6, 5))
        journal_data.extend(struct.pack("<I", 1400))
        _append_guid_bytes(journal_data, guid, (4,))
        journal_data.extend(struct.pack("<H", 0))
        _append_guid_bytes(journal_data, guid, (0, 1, 3))

    bits.write_bits(1, 1)  # slots enabled
    bits.write_bits(BATTLE_PET_MAX_LOADOUT_SLOTS, 25)
    for slot in range(BATTLE_PET_MAX_LOADOUT_SLOTS):
        empty_guid = [0] * 8
        bits.write_bits(1, 1)  # no slotted pet
        bits.write_bits(1, 1)
        bits.write_bits(0, 1)
        bits.write_bits(0, 1)
        _write_guid_bits(bits, empty_guid, (0, 1, 7, 6, 4, 2, 5, 3))
        slot_data.append(slot & 0xFF)

    payload = bytearray(bits.getvalue())
    payload.extend(slot_data)
    payload.extend(journal_data)
    payload.extend(struct.pack("<H", 0))
    return bytes(payload)
