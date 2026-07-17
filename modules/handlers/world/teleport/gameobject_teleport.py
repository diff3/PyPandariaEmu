#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import time
from typing import Any

from shared.Logger import Logger
from shared.PathUtils import get_dbc_root
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.dbc import read_dbc
from server.modules.handlers.world.teleport.map_transfer import (
    TeleportDestination,
    apply_map_transfer,
)
from server.modules.handlers.world.teleport.teleport_service import find_teleport


GAMEOBJECT_TYPE_TRAP = 6
GAMEOBJECT_TYPE_GOOBER = 10
GAMEOBJECT_TYPE_SPELLCASTER = 22
GO_FLAG_LOCKED = 0x00000002
GO_FLAG_INTERACT_COND = 0x00000004
GO_FLAG_NOT_SELECTABLE = 0x00000010
TELEPORT_GAMEOBJECT_USE_RADIUS = 10.0
TELEPORT_GAMEOBJECT_SPAM_GUARD_SECONDS = 1.0
PORTAL_NAME_TOKENS = ("portal", "teleport")
_DBC_SPELL_EFFECT_FMT = "i" * 30
_SPELL_EFFECT_TRIGGER_SPELL_INDEX = 23
_SPELL_EFFECT_SPELL_ID_INDEX = 27
_triggered_spells_by_spell: dict[int, tuple[int, ...]] | None = None


def _entry_int(entry: dict[str, Any], key: str, default: int = 0) -> int:
    return int(entry.get(key, default) or default)


def _entry_float(entry: dict[str, Any], key: str, default: float = 0.0) -> float:
    return float(entry.get(key, default) or default)


def _normalize_orientation(value: float) -> float:
    orientation = math.fmod(float(value), math.tau)
    if orientation < 0.0:
        orientation += math.tau
    return float(orientation)


def _destination_from_row(row: dict[str, Any], *, name: str) -> TeleportDestination | None:
    try:
        return TeleportDestination(
            map_id=int(row["target_map"]),
            x=float(row["target_position_x"]),
            y=float(row["target_position_y"]),
            z=float(row["target_position_z"]),
            orientation=_normalize_orientation(float(row.get("target_orientation", 0.0) or 0.0)),
            name=str(name or row.get("name") or "gameobject"),
        )
    except Exception as exc:
        Logger.warning("[GO_TELEPORT] invalid destination row name=%s row=%r err=%s", name, row, exc)
        return None


def _destination_from_game_tele(row: dict[str, Any], *, name: str) -> TeleportDestination | None:
    try:
        return TeleportDestination(
            map_id=int(row["map"]),
            x=float(row["x"]),
            y=float(row["y"]),
            z=float(row["z"]),
            orientation=_normalize_orientation(float(row.get("o", 0.0) or 0.0)),
            name=str(name or row.get("name") or "game_tele"),
        )
    except Exception as exc:
        Logger.warning("[GO_TELEPORT] invalid game_tele row name=%s row=%r err=%s", name, row, exc)
        return None


def _template_for_entry(entry: dict[str, Any]) -> dict[str, Any]:
    result = dict(entry)
    if all(f"data{index}" in result for index in range(24)):
        return result

    template = DatabaseConnection.get_gameobject_template(_entry_int(entry, "entry"))
    if template:
        result.update(template)
    return result


def _spell_id_for_gameobject(entry: dict[str, Any]) -> int:
    gameobject_type = _entry_int(entry, "type")
    if gameobject_type == GAMEOBJECT_TYPE_SPELLCASTER:
        return _entry_int(entry, "data0")
    if gameobject_type == GAMEOBJECT_TYPE_GOOBER:
        return _entry_int(entry, "data10")
    if gameobject_type == GAMEOBJECT_TYPE_TRAP:
        return _entry_int(entry, "data3")
    return 0


def _load_triggered_spells_by_spell() -> dict[int, tuple[int, ...]]:
    global _triggered_spells_by_spell
    if _triggered_spells_by_spell is not None:
        return _triggered_spells_by_spell

    discovered: dict[int, list[int]] = {}
    dbc_root = get_dbc_root()
    spell_effect_path = dbc_root / "SpellEffect.dbc" if dbc_root else None
    if spell_effect_path and spell_effect_path.is_file():
        try:
            for record in read_dbc(spell_effect_path, _DBC_SPELL_EFFECT_FMT):
                spell_id = int(record[_SPELL_EFFECT_SPELL_ID_INDEX] or 0)
                triggered_spell_id = int(record[_SPELL_EFFECT_TRIGGER_SPELL_INDEX] or 0)
                if spell_id > 0 and triggered_spell_id > 0:
                    values = discovered.setdefault(spell_id, [])
                    if triggered_spell_id not in values:
                        values.append(triggered_spell_id)
        except Exception as exc:
            Logger.warning("[GO_TELEPORT] failed to read triggered spells from SpellEffect.dbc: %s", exc)

    _triggered_spells_by_spell = {
        spell_id: tuple(triggered_spell_ids)
        for spell_id, triggered_spell_ids in discovered.items()
    }
    return _triggered_spells_by_spell


def _teleport_spell_ids(spell_id: int) -> tuple[int, ...]:
    """Return the authored GO spell followed by any directly triggered spells."""
    root_spell_id = int(spell_id or 0)
    if root_spell_id <= 0:
        return ()
    return (root_spell_id, *_load_triggered_spells_by_spell().get(root_spell_id, ()))


def _is_named_portal(entry: dict[str, Any]) -> bool:
    name = str(entry.get("name", "") or "").strip().lower()
    return any(token in name for token in PORTAL_NAME_TOKENS)


def _portal_destination_names(name: str) -> list[str]:
    normalized = " ".join(str(name or "").replace(":", " ").split())
    if not normalized:
        return []

    lowered = normalized.lower()
    candidates: list[str] = []
    if " to " in lowered:
        index = lowered.rfind(" to ")
        candidates.append(normalized[index + 4:])

    for token in ("portal", "teleporter", "teleport"):
        lowered_candidate = normalized.lower()
        if token in lowered_candidate:
            token_index = lowered_candidate.find(token)
            stripped = normalized[:token_index] + normalized[token_index + len(token):]
            stripped = " ".join(stripped.split())
            if stripped:
                candidates.append(stripped)

    candidates.append(normalized)

    unique: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = candidate.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(candidate.strip())
    return unique


def _destination_from_portal_name(entry: dict[str, Any], *, spell_id: int = 0) -> TeleportDestination | None:
    if not _is_named_portal(entry):
        return None

    go_entry = _entry_int(entry, "entry")
    name = str(entry.get("name", "") or "")
    for candidate in _portal_destination_names(name):
        tele = find_teleport(candidate)
        if not tele:
            continue

        Logger.info(
            "[GO_TELEPORT] destination game_tele guid=%s entry=%s spell=%s portal=%r match=%r",
            _entry_int(entry, "guid"),
            int(go_entry),
            int(spell_id),
            name,
            candidate,
        )
        return _destination_from_game_tele(
            tele,
            name=f"go:{go_entry}:game_tele:{tele.get('name', candidate)}",
        )

    Logger.info(
        "[GO_TELEPORT] named portal has no game_tele match guid=%s entry=%s spell=%s name=%r candidates=%s",
        _entry_int(entry, "guid"),
        int(go_entry),
        int(spell_id),
        name,
        _portal_destination_names(name),
    )
    return None


def resolve_gameobject_teleport_destination(entry: dict[str, Any]) -> TeleportDestination | None:
    spawn_guid = _entry_int(entry, "guid")
    go_entry = _entry_int(entry, "entry")
    name = str(entry.get("name", "") or f"gameobject:{go_entry}")

    explicit_row = DatabaseConnection.get_gameobject_teleport(spawn_guid, go_entry)
    if explicit_row:
        Logger.info(
            "[GO_TELEPORT] destination explicit guid=%s entry=%s",
            int(spawn_guid),
            int(go_entry),
        )
        return _destination_from_row(explicit_row, name=f"gameobject:{go_entry}")

    template = _template_for_entry(entry)
    spell_id = _spell_id_for_gameobject(template)
    if spell_id <= 0:
        Logger.debug(
            "[GO_TELEPORT] no teleport spell guid=%s entry=%s type=%s name=%r",
            int(spawn_guid),
            int(go_entry),
            _entry_int(entry, "type"),
            name,
        )
        return None

    destination_spell_id = 0
    spell_row = None
    for candidate_spell_id in _teleport_spell_ids(spell_id):
        spell_row = DatabaseConnection.get_spell_target_position(candidate_spell_id)
        if spell_row:
            destination_spell_id = candidate_spell_id
            break

    if not spell_row:
        Logger.info(
            "[GO_TELEPORT] spell has no target guid=%s entry=%s spell=%s name=%r",
            int(spawn_guid),
            int(go_entry),
            int(spell_id),
            name,
        )
        return _destination_from_portal_name(template, spell_id=spell_id)

    Logger.info(
        "[GO_TELEPORT] destination spell guid=%s entry=%s spell=%s destination_spell=%s",
        int(spawn_guid),
        int(go_entry),
        int(spell_id),
        int(destination_spell_id),
    )
    return _destination_from_row(
        spell_row,
        name=f"go:{go_entry}:spell:{destination_spell_id}",
    )


def _has_invalid_interaction_flags(entry: dict[str, Any]) -> bool:
    flags = _entry_int(entry, "flags")
    invalid_flags = flags & (GO_FLAG_LOCKED | GO_FLAG_NOT_SELECTABLE)
    if invalid_flags:
        Logger.warning(
            "[GO_TELEPORT] invalid GO flags guid=%s entry=%s flags=0x%X invalid=0x%X",
            _entry_int(entry, "guid"),
            _entry_int(entry, "entry"),
            flags,
            invalid_flags,
        )
    if flags & GO_FLAG_INTERACT_COND:
        Logger.info(
            "[GO_TELEPORT] GO has interaction condition guid=%s entry=%s flags=0x%X; allowing teleport fallback",
            _entry_int(entry, "guid"),
            _entry_int(entry, "entry"),
            flags,
        )
    return bool(invalid_flags)


def _is_at_interaction_distance(session, entry: dict[str, Any]) -> bool:
    dx = _entry_float(entry, "x") - float(getattr(session, "x", 0.0) or 0.0)
    dy = _entry_float(entry, "y") - float(getattr(session, "y", 0.0) or 0.0)
    dz = _entry_float(entry, "z") - float(getattr(session, "z", 0.0) or 0.0)
    radius = max(TELEPORT_GAMEOBJECT_USE_RADIUS, float(entry.get("size", 1.0) or 1.0) * 5.0)
    return ((dx * dx) + (dy * dy) + (dz * dz)) <= (radius * radius)


def _spam_guard_allows(session, entry: dict[str, Any]) -> bool:
    now = time.monotonic()
    key = (_entry_int(entry, "guid"), _entry_int(entry, "entry"))
    previous_key = getattr(session, "_last_go_teleport_key", None)
    previous_at = float(getattr(session, "_last_go_teleport_at", 0.0) or 0.0)
    if key == previous_key and (now - previous_at) < TELEPORT_GAMEOBJECT_SPAM_GUARD_SECONDS:
        Logger.info(
            "[GO_TELEPORT] spam guard guid=%s entry=%s elapsed=%.3f",
            key[0],
            key[1],
            now - previous_at,
        )
        return False

    session._last_go_teleport_key = key
    session._last_go_teleport_at = now
    return True


def activate_gameobject_teleport(session, entry: dict[str, Any]) -> list[tuple[str, bytes]] | None:
    Logger.info(
        "[GO_INTERACT] player=%s guid=%s entry=%s type=%s name=%r",
        int(getattr(session, "char_guid", 0) or 0),
        _entry_int(entry, "guid"),
        _entry_int(entry, "entry"),
        _entry_int(entry, "type"),
        str(entry.get("name", "") or ""),
    )

    destination = resolve_gameobject_teleport_destination(entry)
    if destination is None:
        return None

    if _has_invalid_interaction_flags(entry):
        return []

    if not _is_at_interaction_distance(session, entry):
        Logger.info(
            "[GO_TELEPORT] too far player=%s guid=%s entry=%s",
            int(getattr(session, "char_guid", 0) or 0),
            _entry_int(entry, "guid"),
            _entry_int(entry, "entry"),
        )
        return []

    if not _spam_guard_allows(session, entry):
        return []

    Logger.info(
        "[GO_TELEPORT] activate player=%s guid=%s entry=%s dest=%s map=%s pos=(%.3f %.3f %.3f %.6f)",
        int(getattr(session, "char_guid", 0) or 0),
        _entry_int(entry, "guid"),
        _entry_int(entry, "entry"),
        destination.name,
        int(destination.map_id),
        float(destination.x),
        float(destination.y),
        float(destination.z),
        float(destination.orientation),
    )
    return apply_map_transfer(session, destination, reason="gameobject-teleport")
