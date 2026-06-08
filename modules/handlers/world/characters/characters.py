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
# from server.modules.opcodes.OpcodeLoader import load_world_opcodes
from server.modules.interpretation.utils import to_safe_json
from server.modules.dbc import read_dbc
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.database.CharactersModel import (
    Characters,
    CharacterAction,
    CharacterInventory,
    CharacterSpell,
    ItemInstance,
)
from server.modules.handlers.world.account_data import (
    account_data_text_for_type,
    normalize_account_data_text,
)
from server.modules.game.equipment import _parse_equipment_cache
from server.modules.game.guid import _guid_bytes_and_masks, GuidHelper, HighGuid
from server.modules.game.player import _decode_player_bytes
from server.session.runtime import session
from server.modules.opcodes.WorldOpcodes import (
    WORLD_CLIENT_OPCODES,
    WORLD_SERVER_OPCODES,
)
from server.modules.protocol.PacketContext import PacketContext

# Lookup maps (opcode int -> name)
# WORLD_CLIENT_OPCODES, WORLD_SERVER_OPCODES, _ = load_world_opcodes()
# Reverse map for server opcodes: name -> opcode int
SERVER_OPCODE_BY_NAME = {name: code for code, name in WORLD_SERVER_OPCODES.items()}
AUTH_RESPONSE_OPCODE = SERVER_OPCODE_BY_NAME.get("SMSG_AUTH_RESPONSE", 0x0ABA)
_EQUIPMENT_SLOTS = 23

_DEFAULT_EQUIPMENT_CACHE: Optional[str] = None
_DEFAULT_EXPLORED_ZONES: Optional[str] = None
_DEFAULT_KNOWN_TITLES: Optional[str] = None
_MAX_CHARACTERS_PER_REALM = 30
_SANDBOX_RACE_REMAP = {
    24: 26,  # Neutral Pandaren -> Horde Pandaren until neutral faction choice exists.
}
_CINEMATIC_PENDING = 2

from server.modules.handlers.world.login.packets import (
    build_ENUM_CHARACTERS_RESULT,
)

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
STARTING_ITEM_HEARTHSTONE = 6948
STARTING_HEARTHSTONE_SLOT = 23
EQUIPMENT_SLOT_END = 19

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

    now = int(time.time())
    account_name = ""
    shared_session = _get_shared_world_session()
    if shared_session is not None:
        account_name = str(getattr(shared_session, "account_name", "") or "")

    seeded_types: list[int] = []
    for data_type in (1, 3, 7):
        data_text = account_data_text_for_type(data_type, account_name)
        data_text = normalize_account_data_text(
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
    Logger.info("[Characters] Loaded %s char outfits", len(outfits))
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


def _normalize_character_name(name: str) -> str:
    if not name:
        return ""
    return name[0].upper() + name[1:].lower()


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


def _get_starting_equipment_entries(race: int, class_: int, gender: int | None = None) -> list[int]:
    dbc_entries = _get_outfit_items(race, class_, gender)
    if dbc_entries:
        return list(dbc_entries)

    db_entries = DatabaseConnection.get_starting_item_entries(race, class_, gender)
    if db_entries:
        Logger.info(
            "[CHAR CREATE] using playercreateinfo_item as equipment fallback "
            "race=%s class=%s gender=%s",
            int(race),
            int(class_),
            gender,
        )
    return list(db_entries)


def _build_equipment_cache_from_starting_items(race: int, class_: int, gender: int | None = None) -> Optional[str]:
    equipment_entries = _get_starting_equipment_entries(race, class_, gender)
    if not equipment_entries:
        Logger.warning(
            "[WorldHandlers] No starting equipment found for equipmentCache "
            f"(race={race}, class={class_}, gender={gender})"
        )
        return None

    items = DatabaseConnection.get_item_template_map(equipment_entries)
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
                if int(slot) >= EQUIPMENT_SLOT_END:
                    continue
                if not allow_override and slot in used_slots:
                    continue
                pairs[slot * 2] = int(_display_id)
                pairs[slot * 2 + 1] = int(inv_type)
                used_slots.add(slot)
                break

    _apply_entries(equipment_entries, allow_override=False)

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

_TAXI_MASK_WORDS = 64
_ALLIANCE_STARTING_TAXI_NODES = (
    2,
    582,
    589,
    6,
    619,
    620,
    26,
    456,
    457,
    94,
    624,
    49,
    100,
    128,
    310,
)
_HORDE_STARTING_TAXI_NODES = (
    23,
    536,
    537,
    11,
    384,
    460,
    22,
    402,
    82,
    625,
    631,
    99,
    128,
    310,
)
_ALLIANCE_RACES = {1, 3, 4, 7, 11, 22, 25}
_HORDE_RACES = {2, 5, 6, 8, 9, 10, 26}


def _serialize_taximask_for_nodes(node_ids: tuple[int, ...]) -> str:
    words = [0] * _TAXI_MASK_WORDS
    for node_id in node_ids:
        node_id = int(node_id or 0)
        if node_id <= 0:
            continue
        protocol_bit = node_id - 1
        word_index = protocol_bit // 32
        if word_index >= len(words):
            continue
        words[word_index] |= 1 << (protocol_bit % 32)
    return " ".join(str(word) for word in words)


def _default_taximask(race: int) -> str:
    race = int(race or 0)
    if race in _ALLIANCE_RACES:
        return _serialize_taximask_for_nodes(_ALLIANCE_STARTING_TAXI_NODES)
    if race in _HORDE_RACES:
        return _serialize_taximask_for_nodes(_HORDE_STARTING_TAXI_NODES)
    return _serialize_taximask_for_nodes((128, 310))

def _next_character_guid(session) -> int:
    max_guid = 0
    for model, column_name in (
        (Characters, "guid"),
        (CharacterInventory, "guid"),
        (ItemInstance, "owner_guid"),
        (CharacterAction, "guid"),
        (CharacterSpell, "guid"),
    ):
        try:
            column = getattr(model, column_name)
            row = session.query(column).order_by(column.desc()).first()
        except Exception:
            continue
        if not row:
            continue
        try:
            value = getattr(row, column_name, None)
            if value is None:
                value = row[0]
            max_guid = max(max_guid, int(value or 0))
        except Exception:
            continue
    return max_guid + 1


def _normalize_character_slots(session, account_id: int, realm_id: int):
    rows = (
        session.query(Characters)
        .filter(
            Characters.account == int(account_id),
            Characters.realm == int(realm_id),
        )
        .order_by(
            Characters.slot.asc(),
            Characters.guid.asc(),
        )
        .all()
    )

    #
    # Rewrite all slots to stable 1-based ordering.
    #
    for index, row in enumerate(rows, start=1):
        row.slot = index

    session.commit()

    return rows


def _next_character_slot(session, account_id: int, realm_id: int) -> int:
    rows = _normalize_character_slots(
        session,
        account_id,
        realm_id,
    )

    if not rows:
        return 1

    max_slot = max(
        int(row.slot or 0)
        for row in rows
    )

    return max_slot + 1

def _build_equipment_from_starting_items(race: int, class_: int, gender: int | None = None) -> Optional[list[dict]]:
    equipment_entries = _get_starting_equipment_entries(race, class_, gender)
    if not equipment_entries:
        return None

    items = DatabaseConnection.get_item_template_map(equipment_entries)
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
                if int(slot) >= EQUIPMENT_SLOT_END:
                    continue
                if not allow_override and slot in used_slots:
                    continue
                equipment[slot] = {
                    "enchant": 0,
                    "int_type": inv_type,
                    "display_id": display_id,
                }
                used_slots.add(slot)
                break

    _apply_entries(equipment_entries, allow_override=False)

    if _equipment_is_empty(equipment):
        return None
    return equipment


def _starting_equipment_slots(race: int, class_: int, gender: int | None = None) -> list[tuple[int, int]]:
    equipment_entries = _get_starting_equipment_entries(race, class_, gender)
    if not equipment_entries:
        return []

    templates = DatabaseConnection.get_item_template_details(equipment_entries)
    planned_by_slot: dict[int, int] = {}
    used_slots: set[int] = set()

    for entry in equipment_entries:
        template = templates.get(int(entry))
        if not template:
            continue

        inv_type = int(template.get("inventory_type", 0) or 0)
        for candidate in _INVTYPE_SLOT_MAP.get(inv_type, []):
            slot = int(candidate)
            if slot >= EQUIPMENT_SLOT_END or slot in used_slots:
                continue
            used_slots.add(slot)
            planned_by_slot[slot] = int(entry)
            break

    return [(entry, slot) for slot, entry in sorted(planned_by_slot.items())]


def _starting_inventory_slots(race: int, class_: int, gender: int | None = None) -> list[tuple[int, int]]:
    planned = _starting_equipment_slots(race, class_, gender)
    planned.append((STARTING_ITEM_HEARTHSTONE, STARTING_HEARTHSTONE_SLOT))
    return planned


def _existing_inventory_positions(db, guid: int) -> set[tuple[int, int]]:
    rows = (
        db.query(CharacterInventory)
        .filter(CharacterInventory.guid == int(guid))
        .all()
    )
    positions: set[tuple[int, int]] = set()
    for row in rows:
        try:
            positions.add((int(row.bag or 0), int(row.slot or 0)))
        except Exception:
            continue
    return positions


def _seed_character_starting_inventory(db, guid: int, race: int, class_: int, gender: int | None = None) -> int:
    planned_items = _starting_inventory_slots(race, class_, gender)
    if not planned_items:
        return 0

    existing_positions = _existing_inventory_positions(db, int(guid))
    missing_items = [
        (int(entry), int(slot))
        for entry, slot in planned_items
        if (0, int(slot)) not in existing_positions
    ]
    if not missing_items:
        return 0

    max_guid_row = db.query(ItemInstance.guid).order_by(ItemInstance.guid.desc()).first()
    try:
        if max_guid_row is None:
            current_max_guid = 0
        elif hasattr(max_guid_row, "guid"):
            current_max_guid = int(max_guid_row.guid or 0)
        else:
            current_max_guid = int(max_guid_row[0] or 0)
        next_item_guid = current_max_guid + 1
    except Exception:
        next_item_guid = 1

    created = 0
    for entry, slot in missing_items:
        item_guid = int(next_item_guid)
        next_item_guid += 1
        db.add(
            ItemInstance(
                guid=item_guid,
                itemEntry=int(entry),
                owner_guid=int(guid),
                creatorGuid=0,
                giftCreatorGuid=0,
                count=1,
                duration=0,
                charges="",
                flags=0,
                enchantments="",
                randomPropertyId=0,
                reforgeID=0,
                durability=0,
                playedTime=0,
                text=None,
            )
        )
        db.add(
            CharacterInventory(
                guid=int(guid),
                bag=0,
                slot=int(slot),
                item=item_guid,
            )
        )
        created += 1

    return created


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
    if opcode == AUTH_RESPONSE_OPCODE:
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
        Logger.info("[CHAR REORDER] No entries to reorder.")
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
        rows = _normalize_character_slots(
            db,
            int(account_id),
            int(realm_id),
        )

        if not rows:
            Logger.warning(
                f"[CHAR REORDER] No characters found for "
                f"account={account_id} realm={realm_id}"
            )
            return 0, None

        by_guid = {
            int(row.guid): row
            for row in rows
        }

        ordered_guids = [
            int(row.guid)
            for row in rows
        ]

        Logger.info(
            "[CHAR REORDER] Current DB order: %s",
            [hex(g) for g in ordered_guids],
        )

        success_count = 0
        processed_guids = set()

        #
        # The client does NOT send full player GUIDs here.
        # It sends compact low-guid bytes.
        #
        success_count = 0
        processed_guids = set()

        for index, entry in enumerate(entries):
            try:
                low_guid = int(entry.get("guid_0", 0) or 1) & 0xFFFFFFFF
                position_token = int(entry.get("guid_1", 0) or 1)

                #
                # Client sends:
                #   0  -> first slot
                #   10 -> slot 1
                #   20 -> slot 2
                # etc
                #
                if position_token == 0:
                    target_slot = 1
                else:
                    target_slot = int(position_token // 10)

            except Exception as exc:
                Logger.warning(
                    "[CHAR REORDER] Failed to parse entry=%s err=%s",
                    entry,
                    exc,
                )
                continue

            Logger.debug(
                "[CHAR REORDER] entry=%s -> guid=%s target_slot=%s",
                entry,
                hex(low_guid),
                target_slot,
            )

            if low_guid not in by_guid:
                Logger.warning(
                    "[CHAR REORDER] GUID %s not found in DB",
                    hex(low_guid),
                )
                continue

            if low_guid in processed_guids:
                Logger.warning(
                    "[CHAR REORDER] Duplicate guid %s",
                    hex(low_guid),
                )
                continue

            try:
                ordered_guids.remove(low_guid)
            except ValueError:
                Logger.warning(
                    "[CHAR REORDER] GUID %s missing from current order",
                    hex(low_guid),
                )
                continue

            list_index = max(0, target_slot - 1)

            list_index = min(
                list_index,
                len(ordered_guids),
            )

            ordered_guids.insert(
                list_index,
                low_guid,
            )

            processed_guids.add(low_guid)
            success_count += 1

        #
        # Persist slots
        #
        for slot, guid in enumerate(ordered_guids, start=1):
            row = by_guid.get(guid)

            if row is None:
                continue

            row.slot = int(slot)

        db.commit()

        Logger.info(
            "[CHAR REORDER] SUCCESS saved=%s new_order=%s",
            success_count,
            [hex(g) for g in ordered_guids],
        )

    except Exception as exc:
        db.rollback()

        Logger.error(
            f"[CHAR REORDER] FAILED: {exc}",
            exc_info=True,
        )

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
    name = _normalize_character_name(name)

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
        requested_race_id = int(data.get("race", 0))
        race_id = int(_SANDBOX_RACE_REMAP.get(requested_race_id, requested_race_id))
        class_id = int(data.get("class", 0))
        gender = int(data.get("gender", 0))
        if race_id != requested_race_id:
            Logger.info(
                "[CHAR CREATE] sandbox race remap requested=%s stored=%s",
                int(requested_race_id),
                int(race_id),
            )
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
            cinematic=_CINEMATIC_PENDING,
            map=start_map,
            zone=start_zone,
            position_x=start_x,
            position_y=start_y,
            position_z=start_z,
            orientation=start_o,
            health=1,
            money=0,
            taximask=_default_taximask(race_id),
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

        try:
            seeded_items = _seed_character_starting_inventory(
                db,
                guid,
                race_id,
                class_id,
                gender,
            )
            if seeded_items:
                db.commit()
                Logger.info(
                    "[CHAR CREATE] Seeded %s starting inventory items GUID=%s",
                    int(seeded_items),
                    int(guid),
                )
        except Exception as exc:
            db.rollback()
            Logger.warning(f"[WorldHandlers] Seed starting inventory failed: {exc}")

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
