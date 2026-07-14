#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Character-identity lifetime store for passive runtime Players."""

from __future__ import annotations

from collections.abc import Iterator

from server.modules.handlers.world.runtime.player import Player


class PlayerRuntimeStore:
    """Retain one long-lived Player under its character GUID.

    The store owns only the identity index and object lifetime. It does not
    know about sessions, login, disconnect, world membership, movement,
    visibility, packets, persistence, networking, or gameplay behavior.
    """

    def __init__(self) -> None:
        self._by_character_guid: dict[int, Player] = {}

    def add(self, player: Player) -> Player:
        """Retain and return a Player under its character GUID."""
        self._by_character_guid[int(player.character_guid)] = player
        return player

    def remove(self, character_guid: int) -> Player | None:
        """Remove and return a Player for a character GUID, if present."""
        return self._by_character_guid.pop(int(character_guid), None)

    def get(self, character_guid: int) -> Player | None:
        """Return the retained Player for a character GUID."""
        return self._by_character_guid.get(int(character_guid))

    def contains(self, character_guid: int) -> bool:
        """Return whether a character GUID is retained."""
        return int(character_guid) in self._by_character_guid

    def clear(self) -> None:
        """Remove every retained Player."""
        self._by_character_guid.clear()

    def __iter__(self) -> Iterator[Player]:
        """Iterate over retained Players."""
        return iter(self._by_character_guid.values())


_PLAYER_RUNTIME_STORE = PlayerRuntimeStore()


def get_player_runtime_store() -> PlayerRuntimeStore:
    """Return the process-wide passive Player runtime store."""
    return _PLAYER_RUNTIME_STORE


def resolve_player_runtime(session) -> Player:
    """Return the stored Player or an unregistered session snapshot.

    Resolution does not change store membership. The fallback preserves paths
    that run before login registration or after runtime cleanup.
    """
    character_guid = int(getattr(session, "char_guid", 0) or 0)
    player = _PLAYER_RUNTIME_STORE.get(character_guid)
    if player is not None:
        return player
    return Player.from_session(session)


def sync_player_runtime_from_session(session) -> Player | None:
    """Copy session world geometry into an existing runtime Player.

    This explicit boundary never constructs or registers a Player. It is used
    when an existing teleport path has already committed its destination to
    ``WorldSession`` and must keep the long-lived runtime snapshot consistent.
    """
    character_guid = int(getattr(session, "char_guid", 0) or 0)
    player = _PLAYER_RUNTIME_STORE.get(character_guid)
    if player is None:
        return None

    player.map_id = int(getattr(session, "map_id", 0) or 0)
    player.instance_id = int(getattr(session, "instance_id", 0) or 0)
    player.x = float(getattr(session, "x", 0.0) or 0.0)
    player.y = float(getattr(session, "y", 0.0) or 0.0)
    player.z = float(getattr(session, "z", 0.0) or 0.0)
    player.orientation = float(getattr(session, "orientation", 0.0) or 0.0)
    return player
