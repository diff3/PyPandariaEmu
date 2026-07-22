#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Character-identity lifetime store for passive runtime Players."""

from __future__ import annotations

from collections.abc import Iterator

from server.modules.handlers.world.runtime.player import Player


_PLAYER_GEOMETRY_DEFAULTS = {
    "map_id": 0,
    "instance_id": 0,
    "x": 0.0,
    "y": 0.0,
    "z": 0.0,
    "orientation": 0.0,
}


class PlayerGeometryField:
    """WorldSession compatibility access to selected Player geometry."""

    def __init__(self, name: str) -> None:
        self.name = str(name)
        self.default = _PLAYER_GEOMETRY_DEFAULTS[self.name]
        self.bootstrap_name = f"_bootstrap_{self.name}"

    def __get__(self, instance, owner=None):
        if instance is None:
            return self.default
        player = getattr(instance, "selected_character", None)
        if isinstance(player, Player):
            return getattr(player, self.name)
        return getattr(instance, self.bootstrap_name, self.default)

    def __set__(self, instance, value) -> None:
        player = getattr(instance, "selected_character", None)
        if self.name in {"map_id", "instance_id"}:
            coerced = int(value or 0)
        else:
            coerced = float(value or 0.0)
        if isinstance(player, Player):
            setattr(player, self.name, coerced)
            return
        setattr(instance, self.bootstrap_name, coerced)


def attach_selected_character(connection, player: Player) -> Player:
    """Attach Player and discard temporary pre-runtime geometry."""
    connection.selected_character = player
    for name in _PLAYER_GEOMETRY_DEFAULTS:
        connection.__dict__.pop(f"_bootstrap_{name}", None)
    return player


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


def resolve_player_runtime(connection_or_player) -> Player:
    """Resolve the runtime Player selected by a connection.

    Resolution does not change store membership. Direct Player and explicit
    selected-character paths keep gameplay independent of WorldSession. The
    legacy store/snapshot fallback preserves bootstrap and existing callers.
    """
    if isinstance(connection_or_player, Player):
        return connection_or_player
    selected = getattr(connection_or_player, "selected_character", None)
    if isinstance(selected, Player):
        return selected
    character_guid = int(getattr(connection_or_player, "char_guid", 0) or 0)
    player = _PLAYER_RUNTIME_STORE.get(character_guid)
    if player is not None:
        return player
    return Player.from_session(connection_or_player)


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

    position = (
        int(getattr(session, "map_id", 0) or 0),
        int(getattr(session, "instance_id", 0) or 0),
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
        float(getattr(session, "orientation", 0.0) or 0.0),
    )
    attach_selected_character(session, player)

    from server.modules.handlers.world.position.publication import publish_absolute

    publish_absolute(
        session,
        map_id=position[0],
        instance_id=position[1],
        x=position[2],
        y=position[3],
        z=position[4],
        orientation=position[5],
    )
    return player
