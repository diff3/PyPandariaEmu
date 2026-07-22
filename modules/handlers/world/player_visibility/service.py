#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Canonical owner of player-to-player interest and known-object links."""

from __future__ import annotations

import math
import threading
import weakref
from dataclasses import dataclass
from typing import Callable

from server.modules.handlers.world.position.position_service import Position, position_delta
from server.modules.handlers.world.runtime.player_store import resolve_player_runtime


PLAYER_VISIBILITY_DISTANCE = 120.0
_KNOWN_GUIDS_BY_CONNECTION: weakref.WeakKeyDictionary[object, set[int]] = (
    weakref.WeakKeyDictionary()
)


def _normalized_guids(value) -> set[int]:
    return {
        int(guid)
        for guid in (value or ())
        if int(guid or 0) > 0
    }


def known_guids_for(connection) -> set[int]:
    """Return service-owned player visibility links for one connection."""
    legacy = getattr(connection, "__dict__", {}).get("visible_guids")
    if isinstance(legacy, set):
        return legacy
    try:
        known = _KNOWN_GUIDS_BY_CONNECTION.get(connection)
        if known is None:
            known = set()
            _KNOWN_GUIDS_BY_CONNECTION[connection] = known
        return known
    except TypeError:
        # Lightweight legacy test/handler doubles may not support weak keys.
        values = getattr(connection, "__dict__", {}).setdefault(
            "_visible_guids_compat",
            set(),
        )
        return values


class VisiblePlayerGuidsField:
    """Compatibility access to service-owned player visibility links."""

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        return known_guids_for(instance)

    def __set__(self, instance, value) -> None:
        known = known_guids_for(instance)
        known.clear()
        known.update(_normalized_guids(value))


@dataclass(frozen=True)
class VisibilityReconcileResult:
    created_for_source: bool = False
    created_for_other: bool = False
    removed_from_source: bool = False
    removed_from_other: bool = False
    source_observes_other: bool = False
    other_observes_source: bool = False


class PlayerVisibilityService:
    """Own bidirectional player interest decisions and known GUID mutation."""

    def __init__(self) -> None:
        self._lock = threading.RLock()

    @staticmethod
    def known_guids(session) -> set[int]:
        return known_guids_for(session)

    @staticmethod
    def player_guid(session) -> int:
        return int(resolve_player_runtime(session).character_guid)

    @staticmethod
    def sessions_share_phase(left, right) -> bool:
        left_phase = int(getattr(left, "phase_mask", 0) or 0)
        right_phase = int(getattr(right, "phase_mask", 0) or 0)
        return left_phase == 0 or right_phase == 0 or left_phase == right_phase

    def should_observe(self, left, right) -> bool:
        left_player = resolve_player_runtime(left)
        right_player = resolve_player_runtime(right)
        if int(left_player.map_id) != int(right_player.map_id):
            return False
        if int(left_player.instance_id) != int(right_player.instance_id):
            return False
        if not self.sessions_share_phase(left, right):
            return False
        delta = position_delta(
            Position(
                map=int(left_player.map_id),
                x=float(left_player.x),
                y=float(left_player.y),
                z=float(left_player.z),
                orientation=float(left_player.orientation),
            ),
            Position(
                map=int(right_player.map_id),
                x=float(right_player.x),
                y=float(right_player.y),
                z=float(right_player.z),
                orientation=float(right_player.orientation),
            ),
        )
        return (
            math.isfinite(float(delta.distance_3d))
            and float(delta.distance_3d) <= PLAYER_VISIBILITY_DISTANCE
        )

    def reconcile_pair(
        self,
        source_session,
        other_session,
        *,
        create: Callable[[object, object], bool],
        remove: Callable[[object, object], bool],
        should_observe: Callable[[object, object], bool] | None = None,
    ) -> VisibilityReconcileResult:
        """Atomically reconcile both directions of one player pair."""
        with self._lock:
            source_guid = self.player_guid(source_session)
            other_guid = self.player_guid(other_session)
            if source_guid <= 0 or other_guid <= 0 or source_session is other_session:
                return VisibilityReconcileResult()

            source_known = self.known_guids(source_session)
            other_known = self.known_guids(other_session)
            decision = should_observe or self.should_observe
            in_range = bool(decision(source_session, other_session))
            from server.modules.handlers.world.player_diagnostics import log_player_event

            log_player_event(
                "visibility_decision",
                source_session,
                other_guid=other_guid,
                visible=bool(in_range),
                source_known=bool(other_guid in source_known),
                other_known=bool(source_guid in other_known),
            )

            created_for_source = False
            created_for_other = False
            removed_from_source = False
            removed_from_other = False
            if in_range:
                if other_guid not in source_known:
                    created_for_source = bool(create(source_session, other_session))
                    if created_for_source:
                        source_known.add(other_guid)
                        log_player_event("observer_added", source_session, observer_guid=source_guid, known_guid=other_guid)
                if source_guid not in other_known:
                    created_for_other = bool(create(other_session, source_session))
                    if created_for_other:
                        other_known.add(source_guid)
                        log_player_event("observer_added", other_session, observer_guid=other_guid, known_guid=source_guid)
            else:
                if other_guid in source_known:
                    removed_from_source = bool(remove(source_session, other_session))
                    source_known.discard(other_guid)
                    log_player_event("observer_removed", source_session, observer_guid=source_guid, known_guid=other_guid)
                if source_guid in other_known:
                    removed_from_other = bool(remove(other_session, source_session))
                    other_known.discard(source_guid)
                    log_player_event("observer_removed", other_session, observer_guid=other_guid, known_guid=source_guid)

            return VisibilityReconcileResult(
                created_for_source=created_for_source,
                created_for_other=created_for_other,
                removed_from_source=removed_from_source,
                removed_from_other=removed_from_other,
                source_observes_other=other_guid in source_known,
                other_observes_source=source_guid in other_known,
            )

    def ensure_observer(self, observer, source, *, create: Callable[[object, object], bool]) -> bool:
        with self._lock:
            source_guid = self.player_guid(source)
            known = self.known_guids(observer)
            if source_guid <= 0 or source_guid in known:
                return False
            created = bool(create(observer, source))
            if created:
                known.add(source_guid)
            return created

    def remove_observer(self, observer, source, *, remove: Callable[[object, object], bool]) -> bool:
        with self._lock:
            source_guid = self.player_guid(source)
            known = self.known_guids(observer)
            if source_guid <= 0 or source_guid not in known:
                return False
            removed = bool(remove(observer, source))
            known.discard(source_guid)
            return removed

    def clear_player_links(
        self,
        target,
        peers,
        *,
        remove: Callable[[object, object], bool] | None = None,
    ) -> tuple[int, int]:
        """Remove every bilateral known link for one player atomically."""
        with self._lock:
            target_guid = self.player_guid(target)
            target_known = self.known_guids(target)
            removed_for_peers = 0
            cleared_for_target = 0
            for peer in list(peers or ()):
                if peer is target:
                    continue
                peer_guid = self.player_guid(peer)
                if peer_guid in target_known:
                    target_known.discard(peer_guid)
                    cleared_for_target += 1
                peer_known = self.known_guids(peer)
                if target_guid not in peer_known:
                    continue
                if remove is not None:
                    remove(peer, target)
                peer_known.discard(target_guid)
                removed_for_peers += 1
            target_known.clear()
            return removed_for_peers, cleared_for_target


_PLAYER_VISIBILITY_SERVICE = PlayerVisibilityService()


def get_player_visibility_service() -> PlayerVisibilityService:
    return _PLAYER_VISIBILITY_SERVICE
