#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Small helpers for MoP player title state."""

from __future__ import annotations

import struct
from typing import Iterable

from shared.Logger import Logger
from server.modules.database.DatabaseConnection import DatabaseConnection

_OBJECT_END = 0x8
_UNIT_END = _OBJECT_END + 0x98
PLAYER_FIELD_PLAYER_TITLE = _UNIT_END + 0x31F
PLAYER_FIELD_KNOWN_TITLES = _UNIT_END + 0x3D3
KNOWN_TITLES_FIELD_COUNT = 10
MAX_TITLE_BIT_INDEX = KNOWN_TITLES_FIELD_COUNT * 32
TITLE_ID_TO_BIT_INDEX = {
    # CharTitles.dbc: "%s el Explorador" / "%s the Explorer"
    78: 47,
}
TITLE_NAME_TO_BIT_INDEX = {
    "explorer": 47,
    "explorador": 47,
}
EXPLORER_TITLE_BIT_INDEX = 47


def normalize_known_titles(raw: str | Iterable[int] | None) -> list[int]:
    """Return the fixed MoP known-title uint32 mask."""
    if isinstance(raw, str):
        tokens = raw.replace(",", " ").split()
        values = []
        for token in tokens:
            try:
                values.append(int(token, 0) & 0xFFFFFFFF)
            except ValueError:
                continue
    else:
        values = [int(value) & 0xFFFFFFFF for value in (raw or [])]

    if len(values) < KNOWN_TITLES_FIELD_COUNT:
        values.extend([0] * (KNOWN_TITLES_FIELD_COUNT - len(values)))
    return values[:KNOWN_TITLES_FIELD_COUNT]


def serialize_known_titles(values: Iterable[int]) -> str:
    """Store known titles using the same space-separated style as other fields."""
    return " ".join(str(int(value) & 0xFFFFFFFF) for value in normalize_known_titles(values))


def title_is_known(known_titles: Iterable[int], bit_index: int) -> bool:
    """Check whether a title bit is set in the known-title mask."""
    bit_index = int(bit_index)
    if bit_index <= 0 or bit_index >= MAX_TITLE_BIT_INDEX:
        return False
    values = normalize_known_titles(known_titles)
    word_index = bit_index // 32
    bit_offset = bit_index % 32
    return bool(values[word_index] & (1 << bit_offset))


def grant_title_bit(known_titles: Iterable[int], bit_index: int) -> list[int]:
    """Set a title bit and return a normalized mask."""
    bit_index = int(bit_index)
    if bit_index <= 0 or bit_index >= MAX_TITLE_BIT_INDEX:
        raise ValueError(f"title bit index out of range: {bit_index}")
    values = normalize_known_titles(known_titles)
    word_index = bit_index // 32
    bit_offset = bit_index % 32
    values[word_index] |= 1 << bit_offset
    return values


def resolve_title_bit(value: int | str) -> int:
    """Resolve a command/client title value to the internal title bit index."""
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in TITLE_NAME_TO_BIT_INDEX:
            return int(TITLE_NAME_TO_BIT_INDEX[normalized])
        parsed = int(normalized, 0)
    else:
        parsed = int(value)

    return int(TITLE_ID_TO_BIT_INDEX.get(parsed, parsed))


def _session_guid(session) -> int:
    return int(
        getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or getattr(session, "char_guid", 0)
        or 0
    )


def _persist_title_state(session) -> None:
    try:
        DatabaseConnection.update_character_title_state(
            int(getattr(session, "char_guid", 0) or 0),
            int(getattr(session, "realm_id", 0) or 0),
            int(getattr(session, "chosen_title", 0) or 0),
            str(getattr(session, "known_titles_raw", "") or ""),
        )
    except Exception as exc:
        Logger.warning(
            "[Title] DB update failed guid=%s realm=%s chosen=%s error=%s",
            int(getattr(session, "char_guid", 0) or 0),
            int(getattr(session, "realm_id", 0) or 0),
            int(getattr(session, "chosen_title", 0) or 0),
            exc,
        )


def build_title_update_responses(session) -> list[tuple[str, bytes]]:
    """Build the player value update for active and known title state."""
    from server.modules.handlers.world.bootstrap.playerobjects import build_multi_u32_update_object_payload

    guid = _session_guid(session)
    if guid <= 0:
        return []

    known_titles = normalize_known_titles(getattr(session, "known_titles_raw", ""))
    field_updates = [(PLAYER_FIELD_PLAYER_TITLE, int(getattr(session, "chosen_title", 0) or 0))]
    field_updates.extend(
        (PLAYER_FIELD_KNOWN_TITLES + offset, value)
        for offset, value in enumerate(known_titles)
    )
    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_multi_u32_update_object_payload(
                map_id=int(getattr(session, "map_id", 0) or 0),
                guid=guid,
                field_updates=field_updates,
            ),
        )
    ]


def build_active_title_update_responses(session) -> list[tuple[str, bytes]]:
    """Build the small value update used when the player selects a known title."""
    from server.modules.handlers.world.bootstrap.playerobjects import build_multi_u32_update_object_payload

    guid = _session_guid(session)
    if guid <= 0:
        return []

    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_multi_u32_update_object_payload(
                map_id=int(getattr(session, "map_id", 0) or 0),
                guid=guid,
                field_updates=[
                    (PLAYER_FIELD_PLAYER_TITLE, int(getattr(session, "chosen_title", 0) or 0)),
                ],
            ),
        )
    ]


def _build_self_title_refresh_responses(session) -> list[tuple[str, bytes]]:
    """Ask the client to rebuild its local player snapshot after title changes."""
    try:
        from server.modules.handlers.world.state.runtime import build_self_player_appearance_responses
    except Exception as exc:
        Logger.warning("[Title] self refresh unavailable: %s", exc)
        return []

    try:
        return list(build_self_player_appearance_responses(session))
    except Exception as exc:
        Logger.warning("[Title] self refresh failed: %s", exc)
        return []


def _broadcast_active_title_to_visible_peers(session) -> None:
    """Send public active-title changes to players already seeing this player."""
    try:
        from server.modules.handlers.world.state.runtime import (
            _visible_guid_set,
            dispatch_responses_to_sessions,
            iter_in_world_sessions,
        )
    except Exception as exc:
        Logger.warning("[Title] peer refresh unavailable: %s", exc)
        return

    source_guid = _session_guid(session)
    if source_guid <= 0:
        return

    responses = build_active_title_update_responses(session)
    if not responses:
        return

    peers = [
        peer
        for peer in iter_in_world_sessions(map_id=int(getattr(session, "map_id", 0) or 0))
        if peer is not session and source_guid in _visible_guid_set(peer)
    ]
    if not peers:
        return

    dispatch_responses_to_sessions(peers, responses)
    Logger.info(
        "[Title] broadcast active title guid=%s chosen=%s peers=%s",
        int(getattr(session, "char_guid", 0) or 0),
        int(getattr(session, "chosen_title", 0) or 0),
        len(peers),
    )


def build_title_refresh_responses(session) -> list[tuple[str, bytes]]:
    """Build self-facing title refresh packets and broadcast public state to peers."""
    _broadcast_active_title_to_visible_peers(session)

    responses = build_title_update_responses(session)
    responses.extend(_build_self_title_refresh_responses(session))
    return responses


def apply_title(
    session,
    bit_index: int,
    *,
    grant_if_missing: bool,
    persist: bool = True,
) -> list[tuple[str, bytes]]:
    """Apply a player title and return update packets."""
    bit_index = int(bit_index)
    known_titles = normalize_known_titles(getattr(session, "known_titles_raw", ""))

    if bit_index <= 0:
        session.chosen_title = 0
        session.known_titles_raw = serialize_known_titles(known_titles)
    else:
        if bit_index >= MAX_TITLE_BIT_INDEX:
            raise ValueError(f"title bit index out of range: {bit_index}")
        if grant_if_missing:
            known_titles = grant_title_bit(known_titles, bit_index)
        elif not title_is_known(known_titles, bit_index):
            Logger.info("[Title] rejected unknown title bit=%s", bit_index)
            return []
        session.chosen_title = bit_index
        session.known_titles_raw = serialize_known_titles(known_titles)

    if persist:
        _persist_title_state(session)

    Logger.info(
        "[Title] set guid=%s chosen=%s known=%s",
        int(getattr(session, "char_guid", 0) or 0),
        int(getattr(session, "chosen_title", 0) or 0),
        str(getattr(session, "known_titles_raw", "") or ""),
    )
    return build_title_refresh_responses(session)


def select_known_title(session, bit_index: int, *, persist: bool = True) -> list[tuple[str, bytes]]:
    """Select or clear a title without changing the known-title mask."""
    bit_index = int(bit_index)
    known_titles = normalize_known_titles(getattr(session, "known_titles_raw", ""))

    if bit_index <= 0:
        session.chosen_title = 0
    elif bit_index >= MAX_TITLE_BIT_INDEX:
        raise ValueError(f"title bit index out of range: {bit_index}")
    elif not title_is_known(known_titles, bit_index):
        Logger.info("[Title] rejected unknown selected title bit=%s", bit_index)
        return []
    else:
        session.chosen_title = bit_index

    session.known_titles_raw = serialize_known_titles(known_titles)
    if persist:
        _persist_title_state(session)

    Logger.info(
        "[Title] selected guid=%s chosen=%s known=%s",
        int(getattr(session, "char_guid", 0) or 0),
        int(getattr(session, "chosen_title", 0) or 0),
        str(getattr(session, "known_titles_raw", "") or ""),
    )
    _broadcast_active_title_to_visible_peers(session)
    responses = build_active_title_update_responses(session)
    responses.extend(_build_self_title_refresh_responses(session))
    return responses


def build_title_earned_payload(bit_index: int) -> bytes:
    """Build SMSG_TITLE_EARNED payload."""
    return struct.pack("<I", int(bit_index) & 0xFFFFFFFF)


def grant_explorer_title_if_missing(session) -> list[tuple[str, bytes]]:
    """Grant Explorer from completed exploration state."""
    known_titles = normalize_known_titles(getattr(session, "known_titles_raw", ""))
    if title_is_known(known_titles, EXPLORER_TITLE_BIT_INDEX):
        return []

    responses = apply_title(session, EXPLORER_TITLE_BIT_INDEX, grant_if_missing=True)
    responses.append(("SMSG_TITLE_EARNED", build_title_earned_payload(EXPLORER_TITLE_BIT_INDEX)))
    Logger.info(
        "[Title] explorer granted guid=%s",
        int(getattr(session, "char_guid", 0) or 0),
    )
    return responses
