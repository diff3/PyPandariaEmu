from types import SimpleNamespace

from server.modules.handlers.world.world_refresh.service import WorldRefreshService


def _session(*, loaded: set[int]):
    return SimpleNamespace(loaded_gameobjects=loaded)


def test_moved_transport_refreshes_stationary_player_on_visibility_entry(monkeypatch):
    from server.modules.handlers.world.state import runtime as state_runtime
    from server.modules.handlers.world import transport_runtime

    guid = 77
    waiting_player = _session(loaded=set())
    sent = []
    service = WorldRefreshService()

    monkeypatch.setattr(
        state_runtime,
        "iter_in_world_sessions",
        lambda map_id=None: [waiting_player] if map_id == 1 else [],
    )
    monkeypatch.setattr(
        transport_runtime,
        "synthetic_transport_entries_near",
        lambda session, context: [{"world_guid": guid}],
    )

    def refresh(session, **kwargs):
        session.loaded_gameobjects.add(guid)
        return [("SMSG_UPDATE_OBJECT", b"create-boat")]

    monkeypatch.setattr(service, "refresh_player_world", refresh)
    monkeypatch.setattr(
        state_runtime,
        "dispatch_responses_to_sessions",
        lambda targets, responses: sent.append((list(targets), list(responses))),
    )

    assert service.refresh_for_moved_transport(
        world_guid=guid,
        previous_map_id=1,
        current_map_id=1,
    ) == 1
    assert sent == [
        ([waiting_player], [("SMSG_UPDATE_OBJECT", b"create-boat")]),
    ]


def test_moved_transport_refreshes_stationary_player_on_visibility_exit(monkeypatch):
    from server.modules.handlers.world.state import runtime as state_runtime
    from server.modules.handlers.world import transport_runtime

    guid = 77
    waiting_player = _session(loaded={guid})
    sent = []
    service = WorldRefreshService()

    monkeypatch.setattr(
        state_runtime,
        "iter_in_world_sessions",
        lambda map_id=None: [waiting_player] if map_id == 1 else [],
    )
    monkeypatch.setattr(
        transport_runtime,
        "synthetic_transport_entries_near",
        lambda session, context: [],
    )

    def refresh(session, **kwargs):
        session.loaded_gameobjects.discard(guid)
        return [("SMSG_UPDATE_OBJECT", b"remove-boat")]

    monkeypatch.setattr(service, "refresh_player_world", refresh)
    monkeypatch.setattr(
        state_runtime,
        "dispatch_responses_to_sessions",
        lambda targets, responses: sent.append((list(targets), list(responses))),
    )

    assert service.refresh_for_moved_transport(
        world_guid=guid,
        previous_map_id=1,
        current_map_id=1,
    ) == 1
    assert sent == [
        ([waiting_player], [("SMSG_UPDATE_OBJECT", b"remove-boat")]),
    ]


def test_moved_transport_does_not_refresh_when_visibility_is_unchanged(monkeypatch):
    from server.modules.handlers.world.state import runtime as state_runtime
    from server.modules.handlers.world import transport_runtime

    guid = 77
    waiting_player = _session(loaded={guid})
    service = WorldRefreshService()

    monkeypatch.setattr(
        state_runtime,
        "iter_in_world_sessions",
        lambda map_id=None: [waiting_player],
    )
    monkeypatch.setattr(
        transport_runtime,
        "synthetic_transport_entries_near",
        lambda session, context: [{"world_guid": guid}],
    )
    monkeypatch.setattr(
        service,
        "refresh_player_world",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("unchanged visibility must not refresh")
        ),
    )

    assert service.refresh_for_moved_transport(
        world_guid=guid,
        previous_map_id=1,
        current_map_id=1,
    ) == 0


def test_transport_transform_change_notifies_world_refresh(monkeypatch):
    from server.modules.handlers.world import transport_runtime, world_refresh

    state = SimpleNamespace(
        map_id=1,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        transfer_active=False,
        passengers={},
    )
    calls = []

    class Refresh:
        def refresh_for_moved_transport(self, **kwargs):
            calls.append(kwargs)

    monkeypatch.setattr(world_refresh, "get_world_refresh_service", lambda: Refresh())
    monkeypatch.setattr(
        transport_runtime,
        "get_movement_manager",
        lambda: SimpleNamespace(tick_instance=lambda *args, **kwargs: None),
    )
    monkeypatch.setattr(transport_runtime, "_transport_server_time_ms", lambda target: 0)
    monkeypatch.setattr(
        transport_runtime,
        "_commit_transport_state_from_movement_cache",
        lambda target: setattr(target, "x", 25.0),
    )
    monkeypatch.setattr(
        transport_runtime,
        "_trigger_boundary_on_runtime_map_transition",
        lambda *args, **kwargs: False,
    )
    monkeypatch.setattr(
        transport_runtime,
        "_canonical_runtime_passengers",
        lambda *args, **kwargs: {},
    )
    manager = transport_runtime.get_world_transport_manager()
    monkeypatch.setattr(manager, "update_entry_transform_from_state", lambda target: None)

    manager._tick_transport_state(77, state)

    assert calls == [
        {
            "world_guid": 77,
            "previous_map_id": 1,
            "current_map_id": 1,
        }
    ]
