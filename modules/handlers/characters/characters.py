#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import copy
import json
import re
import struct
import time
from pathlib import Path
from typing import Dict, Callable, Tuple, Optional

from DSL.modules.DecoderHandler import DecoderHandler
from DSL.modules.EncoderHandler import EncoderHandler
from DSL.modules.NodeTreeParser import NodeTreeParser
from DSL.modules.Processor import load_case
from DSL.modules.Session import get_session
from shared.Logger import Logger
from shared.PathUtils import get_captures_root, get_dbc_root, get_json_root
# from server.modules.OpcodeLoader import load_world_opcodes
from server.modules.interpretation.utils import to_safe_json
from server.modules.dbc import read_dbc
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.database.CharactersModel import (
    Characters,
    CharacterAction,
    CharacterSpell,
)
from server.session.runtime import session
from server.modules.opcodes.WorldOpcodes import (
    WORLD_CLIENT_OPCODES,
    WORLD_SERVER_OPCODES,
)
from server.modules.PacketContext import PacketContext

# Lookup maps (opcode int -> name)
# WORLD_CLIENT_OPCODES, WORLD_SERVER_OPCODES, _ = load_world_opcodes()
# Reverse map for server opcodes: name -> opcode int
SERVER_OPCODE_BY_NAME = {name: code for code, name in WORLD_SERVER_OPCODES.items()}
_EQUIPMENT_SLOTS = 23

_DEFAULT_EQUIPMENT_CACHE: Optional[str] = None
_DEFAULT_EXPLORED_ZONES: Optional[str] = None
_DEFAULT_KNOWN_TITLES: Optional[str] = None
_MAX_CHARACTERS_PER_REALM = 30

from server.modules.handlers.worldLogin.packets import (
    build_ENUM_CHARACTERS_RESULT,
)

_ITEM_TEMPLATE_CACHE: dict[int, tuple[int, int]] = {}
_INVTYPE_SLOT_MAP = {
    1: [0],   # head
    2: [1],   # neck
    3: [2],   # shoulders
    4: [3],   # shirt
    5: [4],   # chest
    20: [4],  # robe -> chest slot
    6: [5],   # waist
    7: [6],   # legs
    8: [7],   # feet
    9: [8],   # wrists
    10: [9],  # hands
    11: [10, 11],  # finger
    12: [12, 13],  # trinket
    16: [14],  # cloak
    13: [15],  # weapon
    17: [15],  # 2H weapon
    21: [15],  # weapon main hand
    22: [16],  # weapon off hand
    14: [16],  # shield
    23: [16],  # holdable
    15: [17],  # ranged
    25: [17],  # thrown
    26: [17],  # ranged right
    28: [17],  # relic
    19: [18],  # tabard
    18: [19, 20, 21, 22],  # bag slots
}
_DBC_CHAR_START_OUTFIT_FMT = (
    "dbbbX"
    "iiiiiiiiiiiiiiiiiiiiiiii"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
)
_DBC_CHAR_START_OUTFIT_CACHE: Optional[dict[tuple[int, int, int], list[int]]] = None
_DBC_CHAR_START_OUTFIT_MERGED: Optional[dict[tuple[int, int], list[int]]] = None
_EQUIPMENT_SLOTS = 23
_GUID_MASK_KEYS = [f"guid_{i}_mask" for i in range(8)]
_GUILD_MASK_KEYS = [
    "guildguid_0_mask",
    "guildguid_1_mask",
    "guildguid_2_mask",
    "guildguid_3_mask",
    "guildguid_4_mask",
    "guildguid_5_mask",
    "guildguid_6_mask",
    "guildguid_7_mask",
]

def load_expected(case_name: str) -> dict:
    path = get_json_root() / f"{case_name}.json"

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def _load_template(case_name: str) -> dict:
    try:
        return load_expected(case_name)
    except Exception as exc:
        Logger.error(f"[WorldHandlers] Missing template {case_name}: {exc}")
        return {}


def _get_shared_world_session():
    try:
        from server.modules.handlers import WorldHandlers as world_handlers
    except Exception:
        return None
    return getattr(world_handlers, "session", None)


def _seed_character_account_data_defaults(char_guid: int) -> None:
    if int(char_guid or 0) <= 0:
        return

    try:
        from server.modules.handlers import WorldHandlers as world_handlers
    except Exception as exc:
        Logger.warning(
            f"[CHAR CREATE] account-data seed skipped guid={char_guid}: {exc}"
        )
        return

    now = int(time.time())
    account_name = ""
    shared_session = _get_shared_world_session()
    if shared_session is not None:
        account_name = str(getattr(shared_session, "account_name", "") or "")

    seeded_types: list[int] = []
    for data_type in (1, 3, 7):
        data_text = world_handlers._account_data_text_for_type(data_type, account_name)
        data_text = world_handlers._normalize_account_data_text(
            data_type,
            str(data_text or ""),
        )
        if not DatabaseConnection.save_account_data(
            int(char_guid),
            int(data_type),
            now,
            str(data_text or ""),
            per_character=True,
        ):
            Logger.warning(
                f"[CHAR CREATE] failed to seed character_account_data guid={char_guid} type={data_type}"
            )
            continue
        seeded_types.append(int(data_type))

    if seeded_types:
        Logger.info(
            "[CHAR CREATE] seeded character_account_data guid=%s types=%s"
            % (int(char_guid), ",".join(str(v) for v in seeded_types))
        )


def _get_auth_response_template() -> dict:
    return _load_template("SMSG_AUTH_RESPONSE")

def _default_known_titles() -> str:
    global _DEFAULT_KNOWN_TITLES
    if _DEFAULT_KNOWN_TITLES is None:
        _DEFAULT_KNOWN_TITLES = "0 0 0 0 0 0 0 0"
    return _DEFAULT_KNOWN_TITLES

def _resolve_dbc_root() -> Optional[Path]:
    return get_dbc_root()



def _load_char_start_outfit() -> dict[tuple[int, int, int], list[int]]:
    global _DBC_CHAR_START_OUTFIT_CACHE, _DBC_CHAR_START_OUTFIT_MERGED
    if _DBC_CHAR_START_OUTFIT_CACHE is not None:
        return _DBC_CHAR_START_OUTFIT_CACHE

    dbc_root = _resolve_dbc_root()
    if not dbc_root:
        Logger.warning("[WorldHandlers] DBC root not configured for CharStartOutfit.")
        _DBC_CHAR_START_OUTFIT_CACHE = {}
        _DBC_CHAR_START_OUTFIT_MERGED = {}
        return _DBC_CHAR_START_OUTFIT_CACHE

    dbc_path = dbc_root / "CharStartOutfit.dbc"
    if not dbc_path.is_file():
        Logger.warning(f"[WorldHandlers] CharStartOutfit.dbc not found at {dbc_path}.")
        _DBC_CHAR_START_OUTFIT_CACHE = {}
        _DBC_CHAR_START_OUTFIT_MERGED = {}
        return _DBC_CHAR_START_OUTFIT_CACHE

    try:
        records = read_dbc(dbc_path, _DBC_CHAR_START_OUTFIT_FMT)
    except Exception as exc:
        Logger.warning(f"[WorldHandlers] Failed to read CharStartOutfit.dbc: {exc}")
        _DBC_CHAR_START_OUTFIT_CACHE = {}
        _DBC_CHAR_START_OUTFIT_MERGED = {}
        return _DBC_CHAR_START_OUTFIT_CACHE

    outfits: dict[tuple[int, int, int], list[int]] = {}
    merged: dict[tuple[int, int], set[int]] = {}
    for row in records:
        if len(row) < 28:
            continue
        race = int(row[1])
        class_ = int(row[2])
        gender = int(row[3])
        items = [int(item_id) for item_id in row[4:4 + 24] if int(item_id) > 0]
        if not items:
            continue
        outfits[(race, class_, gender)] = items
        key = (race, class_)
        merged.setdefault(key, set()).update(items)

    _DBC_CHAR_START_OUTFIT_CACHE = outfits
    _DBC_CHAR_START_OUTFIT_MERGED = {k: sorted(v) for k, v in merged.items()}
    Logger.info(f"[WorldHandlers] Loaded CharStartOutfit entries: {len(outfits)}")
    return _DBC_CHAR_START_OUTFIT_CACHE


def preload_cache() -> None:
    """Warm up DBC caches used during character create/enum."""
    _load_char_start_outfit()


def character_name_exists(name: str) -> bool:
    if not name:
        return False
    session = DatabaseConnection.chars()
    existing = session.query(Characters).filter(Characters.name == name).first()
    return existing is not None


def _validate_character_name(name: str) -> Optional[int]:
    if not name:
        return 0x59  # CHAR_NAME_NO_NAME
    if len(name) < 2:
        return 0x5A  # CHAR_NAME_TOO_SHORT
    if len(name) > 12:
        return 0x5B  # CHAR_NAME_TOO_LONG
    if not all(ch.isalpha() for ch in name):
        return 0x5C  # CHAR_NAME_INVALID_CHARACTER
    return None



def _apply_item_template_info(entries: list[dict]) -> list[dict]:
    entry_ids = {
        e.get("display_id")
        for e in entries
        if e.get("display_id") and (e.get("int_type") or 0) == 0
    }
    if not entry_ids:
        return entries

    template_map = _resolve_item_template_map(list(entry_ids))
    if not template_map:
        return entries

    for entry in entries:
        if (entry.get("int_type") or 0) != 0:
            continue
        item_entry = entry.get("display_id")
        if not item_entry:
            continue
        mapped = template_map.get(item_entry)
        if not mapped:
            continue
        display_id, inv_type = mapped
        if display_id:
            entry["display_id"] = display_id
        if inv_type is not None:
            entry["int_type"] = inv_type
    return entries

def _default_equipment() -> list[dict]:
    return [
        {"enchant": 0, "int_type": 0, "display_id": 0}
        for _ in range(_EQUIPMENT_SLOTS)
    ]


def _default_equipment_cache() -> str:
    global _DEFAULT_EQUIPMENT_CACHE
    if _DEFAULT_EQUIPMENT_CACHE is None:
        _DEFAULT_EQUIPMENT_CACHE = " ".join("0" for _ in range(_EQUIPMENT_SLOTS * 2))
    return _DEFAULT_EQUIPMENT_CACHE


def _default_explored_zones(session=None) -> str:
    global _DEFAULT_EXPLORED_ZONES
    if _DEFAULT_EXPLORED_ZONES is not None:
        return _DEFAULT_EXPLORED_ZONES

    count = 0
    if session is None:
        try:
            session = DatabaseConnection.chars()
        except Exception:
            session = None
    if session is not None:
        try:
            row = session.query(Characters.exploredZones).filter(
                Characters.exploredZones.isnot(None)
            ).first()
        except Exception:
            row = None
        if row and row[0]:
            count = len(re.findall(r"-?\d+", row[0]))

    if count <= 0:
        count = 128
    _DEFAULT_EXPLORED_ZONES = " ".join("0" for _ in range(count))
    return _DEFAULT_EXPLORED_ZONES
def _get_outfit_items(race: int, class_: int, gender: int | None = None) -> list[int]:
    outfits = _load_char_start_outfit()
    if not outfits:
        return []
    if gender is not None:
        items = outfits.get((race, class_, gender))
        if items:
            return items
    if _DBC_CHAR_START_OUTFIT_MERGED:
        items = _DBC_CHAR_START_OUTFIT_MERGED.get((race, class_))
        if items:
            return items
    return []

def _build_equipment_cache_from_starting_items(race: int, class_: int, gender: int | None = None) -> Optional[str]:
    dbc_entries = _get_outfit_items(race, class_, gender)
    db_entries = DatabaseConnection.get_starting_item_entries(race, class_, gender)
    if not dbc_entries and not db_entries:
        Logger.warning(
            "[WorldHandlers] No starting items found for equipmentCache (DBC or DB) "
            f"(race={race}, class={class_}, gender={gender})"
        )
        return None

    merged_entries = list(dict.fromkeys(dbc_entries + db_entries))
    items = DatabaseConnection.get_item_template_map(merged_entries)
    if not items:
        return None

    pairs = [0] * (_EQUIPMENT_SLOTS * 2)
    used_slots = set()
    inv_type_counts: dict[int, int] = {}

    def _apply_entries(entries: list[int], allow_override: bool) -> None:
        for entry in entries:
            mapped = items.get(entry)
            if not mapped:
                continue
            _display_id, inv_type = mapped
            inv_type_counts[inv_type] = inv_type_counts.get(inv_type, 0) + 1
            if inv_type <= 0:
                continue
            slots = _INVTYPE_SLOT_MAP.get(inv_type)
            if not slots:
                continue
            for slot in slots:
                if not allow_override and slot in used_slots:
                    continue
                pairs[slot * 2] = entry
                pairs[slot * 2 + 1] = 0
                used_slots.add(slot)
                break

    _apply_entries(dbc_entries, allow_override=False)
    _apply_entries(db_entries, allow_override=True)

    if all(val == 0 for val in pairs):
        inv_summary = ", ".join(
            f"{inv}:{count}" for inv, count in sorted(inv_type_counts.items())
        )
        Logger.warning(
            "[WorldHandlers] Starting items found, but no equipment slots mapped "
            f"(race={race}, class={class_}, gender={gender}, inv_types=[{inv_summary}])"
        )
        return None
    return " ".join(str(val) for val in pairs)


def _resolve_item_template_map(entries: list[int]) -> dict[int, tuple[int, int]]:
    if not entries:
        return {}
    missing = [entry for entry in entries if entry not in _ITEM_TEMPLATE_CACHE]
    if missing:
        fetched = DatabaseConnection.get_item_template_map(missing)
        if fetched:
            _ITEM_TEMPLATE_CACHE.update(fetched)
    return {entry: _ITEM_TEMPLATE_CACHE.get(entry) for entry in entries if entry in _ITEM_TEMPLATE_CACHE}


def _equipment_is_empty(entries: list[dict]) -> bool:
    if not entries:
        return True
    return all((e.get("display_id") or 0) == 0 for e in entries)


def _build_empty_enum_characters_payload() -> bytes:
    fields = {
        "faction_mask_bits": 0,
        "char_count_bits": 0,
        "success": 1,
        "chars_meta": [],
        "chars": [],
    }
    return EncoderHandler.encode_packet("SMSG_ENUM_CHARACTERS_RESULT", fields)

def _parse_equipment_cache(cache: str) -> Optional[list[dict]]:
    if not cache:
        return None
    values = [int(x) for x in re.findall(r"-?\d+", cache)]
    if len(values) < 3:
        return None

    def _triples(seq, offset):
        trimmed = seq[offset:]
        max_items = min(len(trimmed), _EQUIPMENT_SLOTS * 3)
        max_items -= max_items % 3
        if max_items <= 0:
            return []
        return [trimmed[i:i + 3] for i in range(0, max_items, 3)]

    def _pairs(seq, offset):
        trimmed = seq[offset:]
        max_items = min(len(trimmed), _EQUIPMENT_SLOTS * 2)
        max_items -= max_items % 2
        if max_items <= 0:
            return []
        return [trimmed[i:i + 2] for i in range(0, max_items, 2)]

    def _score_triples(triples, order):
        if not triples:
            return -1
        display_idx, inv_idx, enchant_idx = order
        score = 0
        for t in triples:
            display = t[display_idx]
            inv_type = t[inv_idx]
            enchant = t[enchant_idx]
            if 0 <= inv_type <= 30:
                score += 4
            if 0 <= display <= 200000:
                score += 2
            if display != 0:
                score += 1
            if 0 <= enchant <= 100000:
                score += 1
        return score

    def _score_pairs(pairs, order):
        if not pairs:
            return -1
        display_idx, inv_idx = order
        score = 0
        for p in pairs:
            display = p[display_idx]
            inv_type = p[inv_idx]
            if 0 <= inv_type <= 30:
                score += 4
            if 0 <= display <= 200000:
                score += 2
            if display != 0:
                score += 1
        return score

    triple_orders = [
        (0, 1, 2),  # display, inv_type, enchant (expected)
        (0, 2, 1),
        (1, 0, 2),
        (1, 2, 0),
        (2, 0, 1),
        (2, 1, 0),
    ]
    pair_orders = [
        (0, 1),  # display, inv_type (expected)
        (1, 0),
    ]

    best_kind = None
    best_offset = 0
    best_order = None
    best_score = -1

    for offset in (0, 1, 2):
        triples = _triples(values, offset)
        for order in triple_orders:
            score = _score_triples(triples, order)
            if score > best_score:
                best_kind = "triples"
                best_score = score
                best_offset = offset
                best_order = order

    for offset in (0, 1):
        pairs = _pairs(values, offset)
        for order in pair_orders:
            score = _score_pairs(pairs, order)
            if score > best_score:
                best_kind = "pairs"
                best_score = score
                best_offset = offset
                best_order = order

    if best_kind is None:
        return None

    if best_offset != 0 or (best_kind == "triples" and best_order != triple_orders[0]) or (
        best_kind == "pairs" and best_order != pair_orders[0]
    ):
        Logger.info(
            f"[WorldHandlers] Equipment cache parsed with kind={best_kind} offset={best_offset} order={best_order}"
        )

    entries = []
    if best_kind == "triples":
        triples = _triples(values, best_offset)
        display_idx, inv_idx, enchant_idx = best_order
        for display_id, inv_type, enchant in (
            (t[display_idx], t[inv_idx], t[enchant_idx]) for t in triples
        ):
            entries.append(
                {"enchant": enchant, "int_type": inv_type, "display_id": display_id}
            )
    else:
        pairs = _pairs(values, best_offset)
        display_idx, inv_idx = best_order
        for display_id, inv_type in ((p[display_idx], p[inv_idx]) for p in pairs):
            entries.append(
                {"enchant": 0, "int_type": inv_type, "display_id": display_id}
            )

    entries = _apply_item_template_info(entries)

    while len(entries) < _EQUIPMENT_SLOTS:
        entries.append({"enchant": 0, "int_type": 0, "display_id": 0})

    return entries
def _default_taximask() -> str:
    return " ".join(["0"] * 16)

def _next_character_guid(session) -> int:
    row = session.query(Characters.guid).order_by(Characters.guid.desc()).first()
    if row and row[0]:
        return int(row[0]) + 1
    return 1


def _normalize_character_slots(session, account_id: int, realm_id: int) -> list[Characters]:
    rows = (
        session.query(Characters)
        .filter(
            Characters.account == account_id,
            Characters.realm == realm_id,
        )
        .order_by(Characters.slot.asc(), Characters.guid.asc())
        .all()
    )
    for idx, row in enumerate(rows):
        if int(row.slot or 0) != idx:
            row.slot = idx
    return rows


def _next_character_slot(session, account_id: int, realm_id: int) -> int:
    rows = _normalize_character_slots(session, account_id, realm_id)
    return len(rows)



    if realm_id is None:
        try:
            realm = DatabaseConnection.get_realmlist()
            realm_id = int(realm.id) if realm else None
            if session:
                session.realm_id = realm_id
            else:
                _session_state["realm_id"] = realm_id
        except Exception:
            realm_id = None

    return account_id, realm_id

def _decode_player_bytes(player_bytes: int, player_bytes2: int) -> dict:
    return {
        "skin": player_bytes & 0xFF,
        "face": (player_bytes >> 8) & 0xFF,
        "hair_style": (player_bytes >> 16) & 0xFF,
        "hair_color": (player_bytes >> 24) & 0xFF,
        "facial_hair": player_bytes2 & 0xFF,
    }
def _guid_bytes_and_masks(guid: int) -> tuple[list[int], dict]:
    guid_val = int(guid or 0)
    raw = guid_val.to_bytes(8, "little", signed=False)
    masks = {f"guid_{i}_mask": 1 if raw[i] != 0 else 0 for i in range(8)}
    return list(raw), masks

def _build_equipment_from_starting_items(race: int, class_: int, gender: int | None = None) -> Optional[list[dict]]:
    dbc_entries = _get_outfit_items(race, class_, gender)
    db_entries = DatabaseConnection.get_starting_item_entries(race, class_, gender)
    if not dbc_entries and not db_entries:
        return None

    merged_entries = list(dict.fromkeys(dbc_entries + db_entries))
    items = DatabaseConnection.get_item_template_map(merged_entries)
    if not items:
        return None

    equipment = _default_equipment()
    used_slots = set()

    def _apply_entries(entries: list[int], allow_override: bool) -> None:
        for entry in entries:
            mapped = items.get(entry)
            if not mapped:
                continue
            display_id, inv_type = mapped
            if not display_id or inv_type <= 0:
                continue
            slots = _INVTYPE_SLOT_MAP.get(inv_type)
            if not slots:
                continue
            for slot in slots:
                if not allow_override and slot in used_slots:
                    continue
                equipment[slot] = {
                    "enchant": 0,
                    "int_type": inv_type,
                    "display_id": display_id,
                }
                used_slots.add(slot)
                break

    _apply_entries(dbc_entries, allow_override=False)
    _apply_entries(db_entries, allow_override=True)

    if _equipment_is_empty(equipment):
        return None
    return equipment

def _resolve_session_ids() -> tuple[Optional[int], Optional[int]]:
    # --- Account ID ---
    if session.account_id is None and session.account_name:
        acc = DatabaseConnection.get_user_by_username(session.account_name)
        if not acc:
            acc = DatabaseConnection.get_user_by_username(session.account_name.upper())
        if acc:
            session.account_id = acc.id

    # --- Realm ID ---
    if session.realm_id is None:
        try:
            realm = DatabaseConnection.get_realmlist()
            session.realm_id = int(realm.id) if realm else None
        except Exception:
            session.realm_id = None

    return session.account_id, session.realm_id

def build_world_packet(opcode_name: str, payload: bytes) -> bytes:
    """
    Prepend packed world header (size<<13 | opcode) to payload.
    Handles SMSG_AUTH_RESPONSE quirk where size includes header bytes.
    """
    opcode = SERVER_OPCODE_BY_NAME.get(opcode_name)
    if opcode is None:
        raise KeyError(f"Unknown server opcode: {opcode_name}")

    size = len(payload)
    if opcode == 0x01F6:  # legacy opcode uses size including header
        size += 4

    header = struct.pack("<I", (size << 13) | (opcode & 0x1FFF))
    return header + payload

def _bits_needed(n: int) -> int:
    if n <= 1:
        return 1
    return n.bit_length()


def _build_enum_characters_payload(account_id: int, realm_id: int) -> bytes:
    template = _load_template("SMSG_ENUM_CHARACTERS_RESULT") or {}
    base_char = (template.get("chars") or [{}])[0]
    base_meta = (template.get("chars_meta") or [{}])[0]

    chars_meta: list[dict] = []
    chars: list[dict] = []

    try:
        rows = DatabaseConnection.get_characters_for_account(account_id, realm_id)
    except Exception as exc:
        Logger.error(f"[WorldHandlers] Failed to load characters: {exc}")
        rows = []

    for idx, row in enumerate(rows):
        try:
            meta = copy.deepcopy(base_meta) if base_meta else {}
            for key in _GUID_MASK_KEYS + _GUILD_MASK_KEYS:
                meta.setdefault(key, 0)
            meta.setdefault("boosted", 0)
            meta.setdefault("at_login_first", 0)

            name = row.name or ""
            name_bytes = name.encode("utf-8")
            if len(name_bytes) > 63:
                name_bytes = name_bytes[:63]
                name = name_bytes.decode("utf-8", errors="ignore")

            guid_bytes, guid_masks = _guid_bytes_and_masks(row.guid)
            meta.update(guid_masks)
            meta["name_len"] = len(name_bytes)
            meta["at_login_first"] = 1 if (row.at_login or 0) != 0 else 0

            char = copy.deepcopy(base_char) if base_char else {}
            appearance = _decode_player_bytes(row.playerBytes or 0, row.playerBytes2 or 0)
            equipment = _parse_equipment_cache(row.equipmentCache or "") or _default_equipment()
            if _equipment_is_empty(equipment):
                fallback = _build_equipment_from_starting_items(
                    int(row.race or 0),
                    int(row.class_ or 0),
                    int(row.gender or 0),
                )
                if fallback:
                    equipment = fallback

            char.update(
                {
                    "unk02": 0,
                    "slot": row.slot or idx,
                    "hair_style": appearance["hair_style"],
                    "name": name,
                    "x": float(row.position_x or 0.0),
                    "unk00": 0,
                    "face": appearance["face"],
                    "class": int(row.class_ or 0),
                    "equipment": equipment,
                    "customizationFlag": int(row.at_login or 0),
                    "petFamily": 0,
                    "mapId": int(row.map or 0),
                    "race": int(row.race or 0),
                    "skin": appearance["skin"],
                    "level": int(row.level or 1),
                    "hair_color": appearance["hair_color"],
                    "gender": int(row.gender or 0),
                    "facial_hair": appearance["facial_hair"],
                    "pet_level": 0,
                    "y": float(row.position_y or 0.0),
                    "petDisplayID": 0,
                    "unk3": 0,
                    "char_flags": int(row.playerFlags or 0),
                    "zone": int(row.zone or 0),
                    "z": float(row.position_z or 0.0),
                    "guid": 0,
                    "guildguid": 0,
                }
            )

            for i in range(8):
                if guid_masks.get(f"guid_{i}_mask"):
                    char[f"guid_{i}"] = guid_bytes[i]

            chars_meta.append(meta)
            chars.append(char)
        except Exception as exc:
            try:
                Logger.error(
                    f"[WorldHandlers] Failed to build character entry guid={row.guid} name={getattr(row, 'name', None)}: {exc}"
                )
            except Exception:
                Logger.error(f"[WorldHandlers] Failed to build character entry: {exc}")
            continue

    fields = {
        "faction_mask_bits": 0,
        "char_count_bits": len(chars),
        "chars_meta": chars_meta,
        "success": 1,
        "chars": chars,
    }

    return EncoderHandler.encode_packet("SMSG_ENUM_CHARACTERS_RESULT", fields)

def _coerce_guid_int(value) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.startswith("0x") else int(value)
        except Exception:
            return None
    try:
        return int(value)
    except Exception:
        return None
    
def _log_ctx(ctx: PacketContext) -> dict:
    decoded = ctx.decoded or {}
    Logger.success(f"[CMSG] {ctx.name}\n{json.dumps(to_safe_json(decoded), indent=2)}")
    return decoded

def handle_CMSG_CHAR_DELETE(ctx: PacketContext):
    decoded = _log_ctx(ctx)

    CHAR_DELETE_SUCCESS = 0x47
    CHAR_DELETE_FAILED = 0x48

    Logger.info(f"[CHAR DELETE] decoded={to_safe_json(decoded)}")

    # --------------------------------------------------
    # Resolve GUID (robust)
    # --------------------------------------------------
    guid = _coerce_guid_int(decoded.get("guid"))

    if guid is None:
        for key in ("guid_low", "guidLo", "guid_id"):
            guid = _coerce_guid_int(decoded.get(key))
            if guid is not None:
                break

    if guid is None:
        guid_bytes = [0] * 8
        found_guid_parts = False
        for i in range(8):
            key = f"guid_{i}"
            if key in decoded:
                try:
                    guid_bytes[i] = int(decoded.get(key)) & 0xFF
                    found_guid_parts = True
                except Exception:
                    guid_bytes[i] = 0
        if found_guid_parts:
            guid = int.from_bytes(bytes(guid_bytes), "little")

    if guid is None:
        Logger.error(f"[CHAR DELETE] Failed to decode GUID from payload: {decoded}")
        result = CHAR_DELETE_FAILED
        account_id = None
        realm_id = None
    else:
        guid &= 0xFFFFFFFF
        Logger.info(f"[CHAR DELETE] Requested delete GUID={guid}")

        # --------------------------------------------------
        # Delete character (GUID ONLY, but capture account/realm)
        # --------------------------------------------------
        result = CHAR_DELETE_FAILED
        account_id = None
        realm_id = None

        shared_session = _get_shared_world_session()
        if shared_session is not None:
            account_id = getattr(shared_session, "account_id", None)
            realm_id = getattr(shared_session, "realm_id", None)

        if account_id is None or realm_id is None:
            account_id, realm_id = _resolve_session_ids()

        db = DatabaseConnection.chars()
        try:
            row = db.query(Characters).filter(
                Characters.guid == guid,
                Characters.account == account_id,
                Characters.realm == realm_id,
            ).first()

            if row is None:
                fallback_row = db.query(Characters).filter(
                    Characters.guid == guid,
                ).first()
                if fallback_row is not None:
                    if account_id is None or realm_id is None:
                        row = fallback_row
                        account_id = int(fallback_row.account)
                        realm_id = int(fallback_row.realm)
                    else:
                        Logger.warning(
                            f"[CHAR DELETE] GUID={guid} exists but account/realm mismatch "
                            f"(session account={account_id} realm={realm_id}, "
                            f"row account={fallback_row.account} realm={fallback_row.realm})"
                        )

            if row:
                db.query(CharacterAction).filter(
                    CharacterAction.guid == guid
                ).delete(synchronize_session=False)
                db.query(CharacterSpell).filter(
                    CharacterSpell.guid == guid
                ).delete(synchronize_session=False)

                db.delete(row)
                db.commit()

                Logger.success(f"[CHAR DELETE] Deleted character GUID={guid}")
                result = CHAR_DELETE_SUCCESS
            else:
                Logger.warning(f"[CHAR DELETE] No character found for GUID={guid}")
                result = CHAR_DELETE_FAILED

        except Exception as exc:
            db.rollback()
            Logger.error(f"[WorldHandlers] CHAR_DELETE failed: {exc}")
            result = CHAR_DELETE_FAILED

    # --------------------------------------------------
    # Build responses
    # --------------------------------------------------
    responses = []

    # Result packet (ALWAYS)
    payload_out = EncoderHandler.encode_packet(
        "SMSG_CHAR_DELETE",
        {"result": result}
    )
    responses.append(("SMSG_CHAR_DELETE", payload_out))

    # Enum refresh (THIS is what kicks client back)
    if result == CHAR_DELETE_SUCCESS and account_id is not None and realm_id is not None:
        try:
            enum_payload = build_ENUM_CHARACTERS_RESULT(account_id, realm_id)
            responses.append(
                ("SMSG_ENUM_CHARACTERS_RESULT", enum_payload)
            )
        except Exception as exc:
            Logger.error(
                f"[WorldHandlers] ENUM_CHARACTERS refresh after delete failed: {exc}"
            )

    return 0, responses


def handle_CMSG_REORDER_CHARACTERS(ctx: PacketContext):
    decoded = _log_ctx(ctx)

    Logger.info(f"[CHAR REORDER] decoded={to_safe_json(decoded)}")

    entries = decoded.get("entries") or []
    if not entries:
        return 0, None

    account_id = None
    realm_id = None

    shared_session = _get_shared_world_session()
    if shared_session is not None:
        account_id = getattr(shared_session, "account_id", None)
        realm_id = getattr(shared_session, "realm_id", None)

    if account_id is None or realm_id is None:
        account_id, realm_id = _resolve_session_ids()

    if account_id is None or realm_id is None:
        Logger.warning("[CHAR REORDER] Missing session account/realm")
        return 0, None

    db = DatabaseConnection.chars()
    try:
        rows = _normalize_character_slots(db, int(account_id), int(realm_id))
        by_guid = {int(row.guid): row for row in rows}
        ordered_guids = [int(row.guid) for row in rows]

        for entry in entries:
            guid = _coerce_guid_int(entry.get("guid"))
            if not guid:
                raw = bytearray(8)
                has_guid_bytes = False
                for i in range(8):
                    key = f"guid_{i}"
                    if key in entry:
                        try:
                            raw[i] = int(entry.get(key)) & 0xFF
                            has_guid_bytes = True
                        except Exception:
                            raw[i] = 0
                if has_guid_bytes:
                    guid = int.from_bytes(bytes(raw), "little", signed=False)
            slot = entry.get("slot")
            if guid is None or slot is None:
                continue

            guid = int(guid) & 0xFFFFFFFF
            if guid not in by_guid:
                continue

            try:
                target_slot = max(0, min(int(slot), len(ordered_guids) - 1))
            except Exception:
                continue

            ordered_guids.remove(guid)
            ordered_guids.insert(target_slot, guid)

        for idx, guid in enumerate(ordered_guids):
            by_guid[guid].slot = idx

        db.commit()
        Logger.info(
            f"[CHAR REORDER] Saved {len(entries)} reorder entries for "
            f"account={account_id} realm={realm_id}"
        )
    except Exception as exc:
        db.rollback()
        Logger.error(f"[CHAR REORDER] Failed: {exc}")

    return 0, None


def handle_CMSG_CHAR_CREATE(ctx: PacketContext):
    data = _log_ctx(ctx)

    # WoW ResponseCode values for character creation.
    CHAR_CREATE_SUCCESS = 0x2F
    CHAR_CREATE_ERROR = 0x31
    CHAR_CREATE_NAME_IN_USE = 0x32
    CHAR_CREATE_ACCOUNT_LIMIT = 0x36
    CHAR_CREATE_RESTRICTED_RACECLASS = 0x3E

    # --------------------------------------------------
    # Decode
    # --------------------------------------------------
    Logger.info(f"[CHAR CREATE] decoded={to_safe_json(data)}")

    name = data.get("name")
    if isinstance(name, (bytes, bytearray)):
        name = name.decode("utf-8", errors="ignore")
    name_error = _validate_character_name(name or "")
    if name_error is not None:
        payload = EncoderHandler.encode_packet(
            "SMSG_CHAR_CREATE", {"result": name_error}
        )
        return 0, [("SMSG_CHAR_CREATE", payload)]

    # --------------------------------------------------
    # Name check (global, no session)
    # --------------------------------------------------
    if character_name_exists(name):
        payload = EncoderHandler.encode_packet(
            "SMSG_CHAR_CREATE", {"result": CHAR_CREATE_NAME_IN_USE}
        )
        return 0, [("SMSG_CHAR_CREATE", payload)]

    # --------------------------------------------------
    # Resolve account / realm from the shared world handler
    # --------------------------------------------------
    result = CHAR_CREATE_ERROR
    account_id = None
    realm_id = None

    shared_session = _get_shared_world_session()
    if shared_session is not None:
        account_id = getattr(shared_session, "account_id", None)
        realm_id = getattr(shared_session, "realm_id", None)

    if account_id is None or realm_id is None:
        account_id, realm_id = _resolve_session_ids()

    if account_id is None or realm_id is None:
        Logger.error("[WorldHandlers] Missing session account/realm for CHAR_CREATE")
        payload = EncoderHandler.encode_packet(
            "SMSG_CHAR_CREATE", {"result": CHAR_CREATE_ERROR}
        )
        return 0, [("SMSG_CHAR_CREATE", payload)]


    db = DatabaseConnection.chars()
    try:
        race_id = int(data.get("race", 0))
        class_id = int(data.get("class", 0))
        gender = int(data.get("gender", 0))
        if gender not in (0, 1):
            payload = EncoderHandler.encode_packet(
                "SMSG_CHAR_CREATE", {"result": CHAR_CREATE_ERROR}
            )
            return 0, [("SMSG_CHAR_CREATE", payload)]

        char_count = DatabaseConnection.count_characters_for_account(account_id, realm_id)
        if char_count >= _MAX_CHARACTERS_PER_REALM:
            payload = EncoderHandler.encode_packet(
                "SMSG_CHAR_CREATE", {"result": CHAR_CREATE_ACCOUNT_LIMIT}
            )
            return 0, [("SMSG_CHAR_CREATE", payload)]

        create_info = DatabaseConnection.get_player_create_info(race_id, class_id)
        if create_info is None:
            payload = EncoderHandler.encode_packet(
                "SMSG_CHAR_CREATE", {"result": CHAR_CREATE_RESTRICTED_RACECLASS}
            )
            return 0, [("SMSG_CHAR_CREATE", payload)]

        guid = _next_character_guid(db)
        slot = _next_character_slot(db, account_id, realm_id)

        skin = int(data.get("skin", 0))
        face = int(data.get("face", 0))
        hair_style = int(data.get("hair_style", 0))
        hair_color = int(data.get("hair_color", 0))
        facial_hair = int(data.get("facial_hair", 0))

        playerBytes = (
            (skin & 0xFF)
            | ((face & 0xFF) << 8)
            | ((hair_style & 0xFF) << 16)
            | ((hair_color & 0xFF) << 24)
        )
        playerBytes2 = facial_hair & 0xFF

        start_map = int(create_info.map or 0)
        start_zone = int(create_info.zone or 0)
        start_x = float(create_info.position_x or 0.0)
        start_y = float(create_info.position_y or 0.0)
        start_z = float(create_info.position_z or 0.0)
        start_o = float(create_info.orientation or 0.0)

        row = Characters(
            guid=guid,
            realm=int(realm_id),
            account=int(account_id),
            name=name,
            slot=slot,
            race=race_id,
            class_=class_id,
            gender=gender,
            level=1,
            playerBytes=playerBytes,
            playerBytes2=playerBytes2,
            map=start_map,
            zone=start_zone,
            position_x=start_x,
            position_y=start_y,
            position_z=start_z,
            orientation=start_o,
            health=1,
            money=0,
            taximask=_default_taximask(),
            knownTitles=_default_known_titles(),
            exploredZones=_default_explored_zones(db),
        )

        equipment_cache = _build_equipment_cache_from_starting_items(
            race_id,
            class_id,
            gender,
        )
        if equipment_cache:
            row.equipmentCache = equipment_cache
        else:
            Logger.warning(
                f"[WorldHandlers] No starting items for race={race_id} class={class_id}; "
                "defaulting equipmentCache to zeros"
            )
            row.equipmentCache = _default_equipment_cache()

        db.add(row)
        db.commit()
        account_id = int(row.account)
        realm_id = int(row.realm)
        result = CHAR_CREATE_SUCCESS
        Logger.success(f"[CHAR CREATE] Created character '{name}' GUID={guid}")

        _seed_character_account_data_defaults(int(guid))

        try:
            DatabaseConnection.apply_playercreateinfo_to_character(
                guid,
                race_id,
                class_id,
            )
        except Exception as exc:
            Logger.warning(f"[WorldHandlers] Apply playercreateinfo failed: {exc}")

    except Exception as exc:
        db.rollback()
        Logger.error(f"[WorldHandlers] CHAR_CREATE failed: {exc}")
        result = CHAR_CREATE_ERROR

    # --------------------------------------------------
    # Responses (NO headers)
    # --------------------------------------------------
    responses = []

    payload = EncoderHandler.encode_packet(
        "SMSG_CHAR_CREATE", {"result": result}
    )
    responses.append(("SMSG_CHAR_CREATE", payload))

    if result == CHAR_CREATE_SUCCESS and account_id is not None and realm_id is not None:
        try:
            enum_payload = build_ENUM_CHARACTERS_RESULT(account_id, realm_id)
            responses.append(
                ("SMSG_ENUM_CHARACTERS_RESULT", enum_payload)
            )
        except Exception as exc:
            Logger.error(
                f"[WorldHandlers] ENUM_CHARACTERS refresh after create failed: {exc}"
            )

    return 0, responses
