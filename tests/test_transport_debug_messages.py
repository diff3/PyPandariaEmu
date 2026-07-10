from types import SimpleNamespace


def test_transport_debug_messages_config_defaults_off_and_accepts_runtime_true(monkeypatch):
    from server.modules.handlers.world import feature_config

    monkeypatch.setattr(feature_config.ConfigLoader, "get_config", lambda: {})
    assert feature_config.transport_debug_messages_enabled() is False

    monkeypatch.setattr(
        feature_config.ConfigLoader,
        "get_config",
        lambda: {"Transport": {"DebugMessages": True}},
    )
    assert feature_config.transport_debug_messages_enabled() is True


def test_autonomous_transport_visibility_config_defaults_off_and_accepts_runtime_true(monkeypatch):
    from server.modules.handlers.world import feature_config

    monkeypatch.setattr(feature_config.ConfigLoader, "get_config", lambda: {})
    assert feature_config.autonomous_transport_visibility_enabled() is False

    monkeypatch.setattr(
        feature_config.ConfigLoader,
        "get_config",
        lambda: {"Transport": {"AutonomousVisibility": True}},
    )
    assert feature_config.autonomous_transport_visibility_enabled() is True


def test_transport_debug_messages_disabled_builds_nothing(monkeypatch):
    from server.modules.handlers.world import feature_config
    from server.modules.handlers.world import transport_debug_messages as debug

    monkeypatch.setattr(feature_config, "transport_debug_messages_enabled", lambda: False)
    session = SimpleNamespace()

    assert debug.build_message(session, "teleport", "[Transport] TELEPORT") is None
    assert not hasattr(session, "transport_debug_message_stages")


def test_transport_debug_message_is_player_only_and_deduplicated(monkeypatch):
    from server.modules.handlers.world import feature_config
    from server.modules.handlers.world import transport_debug_messages as debug

    monkeypatch.setattr(feature_config, "transport_debug_messages_enabled", lambda: True)
    monkeypatch.setattr(
        "server.modules.handlers.world.chat.codec.encode_skyfire_messagechat_system_payload",
        lambda message: message.encode("utf-8"),
    )
    sent = []
    session = SimpleNamespace(send_response=lambda responses: sent.extend(responses))

    assert debug.send_message(
        session,
        "world_loaded",
        "[Transport] WORLD LOADED map=1",
        transfer_id="16-1",
    )
    assert not debug.send_message(
        session,
        "world_loaded",
        "[Transport] WORLD LOADED map=1",
        transfer_id="16-1",
    )
    assert sent == [("SMSG_MESSAGECHAT", b"[Transport] WORLD LOADED map=1")]


def test_transport_debug_same_stage_is_allowed_for_next_transfer(monkeypatch):
    from server.modules.handlers.world import feature_config
    from server.modules.handlers.world import transport_debug_messages as debug

    monkeypatch.setattr(feature_config, "transport_debug_messages_enabled", lambda: True)
    monkeypatch.setattr(
        "server.modules.handlers.world.chat.codec.encode_skyfire_messagechat_system_payload",
        lambda message: message.encode("utf-8"),
    )
    session = SimpleNamespace()

    first = debug.build_message(
        session,
        "reattach",
        "[Transport] REATTACH guid=1 success=yes",
        transfer_id="16-1",
    )
    second = debug.build_message(
        session,
        "reattach",
        "[Transport] REATTACH guid=1 success=yes",
        transfer_id="16-2",
    )

    assert first is not None
    assert second is not None
