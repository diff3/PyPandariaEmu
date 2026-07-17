from types import SimpleNamespace

from server.modules.handlers.world.world_refresh.service import WorldRefreshService


def _session():
    return SimpleNamespace(
        char_guid=7,
        map_id=1,
        x=10.0,
        y=20.0,
        z=30.0,
        loaded_gameobjects=set(),
        loaded_npcs=set(),
        loaded_transport_entries={},
        last_gameobject_stream_at=55.0,
        last_npc_stream_at=66.0,
    )


def test_movement_refresh_uses_throttled_existing_streamer():
    session = _session()
    calls = []

    responses = WorldRefreshService().refresh_player_world(
        session,
        context="movement:heartbeat",
        _object_streamer=lambda target: calls.append(target)
        or [("SMSG_UPDATE_OBJECT", b"movement")],
    )

    assert responses == [("SMSG_UPDATE_OBJECT", b"movement")]
    assert calls == [session]
    assert session.last_gameobject_stream_at == 55.0
    assert session.last_npc_stream_at == 66.0


def test_teleport_refresh_resyncs_then_forces_object_stream():
    session = _session()
    session.loaded_gameobjects = {101}
    session.loaded_npcs = {202}
    session.loaded_transport_entries = {303: {"entry": 1}}
    calls = []

    def resync(target, *, reason):
        calls.append(("resync", target, reason))
        return [("SMSG_PLAYER_MOVE", b"player")]

    def stream(target, *, transition_bootstrap=False):
        calls.append(
            (
                "stream",
                target,
                transition_bootstrap,
                set(target.loaded_gameobjects),
                set(target.loaded_npcs),
                dict(target.loaded_transport_entries),
            )
        )
        return [("SMSG_UPDATE_OBJECT", b"objects")]

    responses = WorldRefreshService().refresh_after_teleport(
        session,
        context="near-teleport-ack",
        _teleport_resync=resync,
        _object_streamer=stream,
    )

    assert responses == [
        ("SMSG_PLAYER_MOVE", b"player"),
        ("SMSG_UPDATE_OBJECT", b"objects"),
    ]
    assert calls == [
        ("resync", session, "near-teleport-ack"),
        ("stream", session, True, set(), set(), {}),
    ]
    assert session.last_gameobject_stream_at == 0.0
    assert session.last_npc_stream_at == 0.0


def test_transport_and_login_refresh_share_the_canonical_pipeline():
    session = _session()
    calls = []

    def stream(target, *, transition_bootstrap=False):
        calls.append(transition_bootstrap)
        return []

    service = WorldRefreshService()
    service.refresh_after_transport(
        session,
        context="transport-worldport",
        resync_multiplayer=False,
        _object_streamer=stream,
    )
    service.refresh_after_login(
        session,
        context="login-bootstrap",
        _object_streamer=stream,
    )

    assert calls == [True, True]
