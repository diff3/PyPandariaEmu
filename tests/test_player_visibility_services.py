#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import threading
import sys
from types import SimpleNamespace

from server.modules.handlers.world.movement_publisher import MovementPublisher
from server.modules.handlers.world.player_visibility.service import PlayerVisibilityService
from server.session.world_session import WorldSession


def _session(guid: int, x: float) -> WorldSession:
    session = WorldSession()
    session.char_guid = guid
    session.world_guid = guid
    session.map_id = 1
    session.instance_id = 7
    session.phase_mask = 1
    session.x = x
    session.y = 0.0
    session.z = 0.0
    session.login_state = "IN_WORLD"
    session.send_response = lambda _responses: None
    return session


def test_two_sessions_enter_leave_and_reenter_symmetrically():
    service = PlayerVisibilityService()
    left = _session(101, 0.0)
    right = _session(102, 20.0)
    creates = []
    removes = []
    create = lambda observer, source: creates.append((observer.char_guid, source.char_guid)) or True
    remove = lambda observer, source: removes.append((observer.char_guid, source.char_guid)) or True

    entered = service.reconcile_pair(left, right, create=create, remove=remove)
    assert entered.source_observes_other is True
    assert entered.other_observes_source is True
    assert left.visible_guids == {102}
    assert right.visible_guids == {101}
    assert creates == [(101, 102), (102, 101)]

    service.reconcile_pair(left, right, create=create, remove=remove)
    assert creates == [(101, 102), (102, 101)]

    right.x = 500.0
    left_result = service.reconcile_pair(left, right, create=create, remove=remove)
    assert left_result.source_observes_other is False
    assert left_result.other_observes_source is False
    assert left.visible_guids == set()
    assert right.visible_guids == set()
    assert removes == [(101, 102), (102, 101)]

    right.x = 20.0
    service.reconcile_pair(left, right, create=create, remove=remove)
    assert left.visible_guids == {102}
    assert right.visible_guids == {101}
    assert creates == [(101, 102), (102, 101), (101, 102), (102, 101)]


def test_concurrent_pair_evaluation_publishes_each_create_once():
    service = PlayerVisibilityService()
    left = _session(201, 0.0)
    right = _session(202, 20.0)
    creates = []
    barrier = threading.Barrier(8)

    def worker(source, other):
        barrier.wait()
        service.reconcile_pair(
            source,
            other,
            create=lambda observer, visible: creates.append(
                (observer.char_guid, visible.char_guid)
            ) or True,
            remove=lambda _observer, _visible: True,
        )

    threads = [
        threading.Thread(
            target=worker,
            args=(left, right) if index % 2 == 0 else (right, left),
        )
        for index in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(creates) == [(201, 202), (202, 201)]
    assert left.visible_guids == {202}
    assert right.visible_guids == {201}


def test_movement_publisher_sends_one_update_to_existing_observer(monkeypatch):
    from server.modules.handlers.world.state import runtime
    from server.modules.handlers.world import movement_publisher as publisher_module

    source = _session(301, 0.0)
    peer = _session(302, 20.0)
    source.visible_guids.add(302)
    peer.visible_guids.add(301)
    sent = []

    monkeypatch.setattr(runtime, "_is_session_in_world", lambda _session: True)
    monkeypatch.setattr(runtime, "iter_in_world_sessions", lambda map_id=None: [source, peer])
    monkeypatch.setattr(runtime, "_build_player_move_response", lambda _session: ("SMSG_PLAYER_MOVE", b"move"))
    monkeypatch.setattr(runtime, "_build_player_value_update_responses", lambda _session: [])
    monkeypatch.setattr(runtime, "_publish_player_create", lambda _observer, _source: True)
    monkeypatch.setattr(runtime, "_publish_player_remove", lambda _observer, _source: True)
    monkeypatch.setattr(
        runtime,
        "dispatch_responses_to_sessions",
        lambda targets, responses: sent.append(([target.char_guid for target in targets], list(responses))),
    )
    monkeypatch.setattr(publisher_module.time, "time", lambda: 100.0)

    MovementPublisher().publish(source)

    assert sent == [([302], [("SMSG_PLAYER_MOVE", b"move")])]
    assert source.visible_guids == {302}
    assert peer.visible_guids == {301}


def test_packet_send_failure_uses_canonical_disconnect_lifecycle(monkeypatch):
    from server.modules.handlers.world.state import runtime

    target = _session(401, 0.0)
    disconnected = []

    def fail_send(_responses):
        raise OSError("closed socket")

    target.send_response = fail_send
    monkeypatch.setitem(
        sys.modules,
        "server.modules.handlers.world.runtime.lifecycle",
        SimpleNamespace(
            handle_disconnect_session=lambda session: disconnected.append(session),
        ),
    )

    runtime.dispatch_responses_to_sessions(
        [target],
        [("SMSG_PLAYER_MOVE", b"move")],
    )

    assert disconnected == [target]
    assert target._packet_queue_depth == 0
