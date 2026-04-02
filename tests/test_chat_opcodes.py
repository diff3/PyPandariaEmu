import importlib
import sys
import types
from types import SimpleNamespace

from server.modules.handlers.world.state.global_state import GlobalState
from server.session.world_session import WorldSession


def _import_chat_handlers():
    stub_modules = {
        "server.modules.database.DatabaseConnection": {
            "DatabaseConnection": type("DatabaseConnection", (), {}),
        },
        "server.modules.handlers.world.opcodes.login": {
            "_build_world_login_context": lambda session: SimpleNamespace(motd=""),
            "_reset_login_flow_state": lambda session: None,
        },
        "server.modules.handlers.world.opcodes.entities": {
            "build_query_player_name_response": lambda session, guid: b"",
        },
        "server.modules.handlers.world.opcodes.movement": {
            "_save_current_position_like_command": lambda *args, **kwargs: True,
        },
        "server.modules.handlers.world.teleport.runtime": {
            "teleport_player": lambda *args, **kwargs: [],
        },
        "server.modules.handlers.world.teleport.teleport_service": {
            "add_teleport": lambda *args, **kwargs: {},
            "find_teleport": lambda *args, **kwargs: None,
            "nearest_teleport": lambda *args, **kwargs: None,
            "remove_teleport": lambda *args, **kwargs: False,
            "search_teleports": lambda *args, **kwargs: [],
        },
    }

    for module_name, attrs in stub_modules.items():
        module = types.ModuleType(module_name)
        for attr_name, value in attrs.items():
            setattr(module, attr_name, value)
        sys.modules[module_name] = module

    sys.modules.pop("server.modules.handlers.world.opcodes.chat", None)
    return importlib.import_module("server.modules.handlers.world.opcodes.chat")


chat_handlers = _import_chat_handlers()


def _make_session(state: GlobalState, name: str, guid: int):
    session = WorldSession()
    session.global_state = state
    session.player_name = name
    session.char_guid = guid
    session.send_response_log = []
    session.send_response = lambda responses, target=session: target.send_response_log.append(responses)
    state.sessions.add(session)
    state.chat_channels.setdefault("world", set()).add(session)
    return session


def test_yell_broadcasts_to_world_sessions(monkeypatch):
    def fake_encode_messagechat_payload(**fields):
        return f"{fields['chat_type']}|{fields['sender_name']}|{fields['message']}".encode()

    monkeypatch.setattr(chat_handlers, "encode_messagechat_payload", fake_encode_messagechat_payload)

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    ctx = SimpleNamespace(
        name="CMSG_MESSAGECHAT_YELL",
        payload=b"",
        decoded={"msg": "hej varlden", "language": 0},
    )

    code, responses = chat_handlers.handle_messagechat_yell(alice, ctx)

    assert code == 0
    assert responses is None
    assert alice.send_response_log == [[("SMSG_MESSAGECHAT", b"6|Alice|hej varlden")]]
    assert bob.send_response_log == [[("SMSG_MESSAGECHAT", b"6|Alice|hej varlden")]]


def test_whisper_routes_to_active_target_and_returns_echo(monkeypatch):
    def fake_encode_messagechat_payload(**fields):
        return (
            f"{fields['chat_type']}|{fields['sender_name']}|{fields['target_name']}|{fields['message']}"
        ).encode()

    monkeypatch.setattr(chat_handlers, "encode_messagechat_payload", fake_encode_messagechat_payload)

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    ctx = SimpleNamespace(
        name="CMSG_MESSAGECHAT_WHISPER",
        payload=b"",
        decoded={"msg": "psst", "language": 0, "target": "Bob"},
    )

    code, responses = chat_handlers.handle_messagechat_whisper(alice, ctx)

    assert code == 0
    assert responses == [("SMSG_MESSAGECHAT", b"8|Alice|Bob|psst")]
    assert bob.send_response_log == [[("SMSG_MESSAGECHAT", b"7|Alice|Bob|psst")]]
    assert alice.send_response_log == []


def test_whisper_returns_system_message_when_target_missing(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    ctx = SimpleNamespace(
        name="CMSG_MESSAGECHAT_WHISPER",
        payload=b"",
        decoded={"msg": "psst", "language": 0, "target": "Bob"},
    )

    code, responses = chat_handlers.handle_messagechat_whisper(alice, ctx)

    assert code == 0
    assert responses == [("SMSG_MESSAGECHAT", b"system|Bob is not online")]
    assert alice.send_response_log == []
