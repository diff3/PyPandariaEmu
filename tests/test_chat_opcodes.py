import importlib
import sys
import types
from types import SimpleNamespace

from DSL.modules.bitsHandler import BitWriter
from server.modules.handlers.world.state.global_state import GlobalState
from server.session.world_session import WorldSession


def _import_chat_handlers():
    stub_modules = {
        "server.modules.handlers.world.bootstrap.replay": {
            "load_sniff_payload": lambda path: b"",
            "build_single_u32_update_object_payload": lambda **fields: b"",
            "send_raw_packet": lambda *args, **kwargs: ("SMSG_MESSAGECHAT", b""),
        },
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


def _import_chat_codec():
    module = types.ModuleType("server.modules.handlers.world.bootstrap.replay")
    module.load_sniff_payload = lambda path: b""
    module.build_single_u32_update_object_payload = lambda **fields: b""
    module.send_raw_packet = lambda *args, **kwargs: ("SMSG_MESSAGECHAT", b"")
    sys.modules["server.modules.handlers.world.bootstrap.replay"] = module
    sys.modules.pop("server.modules.handlers.world.chat.codec", None)
    return importlib.import_module("server.modules.handlers.world.chat.codec")


chat_handlers = _import_chat_handlers()
chat_codec = _import_chat_codec()


def _make_session(state: GlobalState, name: str, guid: int):
    session = WorldSession()
    session.global_state = state
    session.player_name = name
    session.char_guid = guid
    session.map_id = 1
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


def test_whisper_returns_afk_auto_reply(monkeypatch):
    def fake_encode_messagechat_payload(**fields):
        return (
            f"{fields['chat_type']}|{fields['sender_name']}|{fields['target_name']}|{fields['message']}"
        ).encode()

    monkeypatch.setattr(chat_handlers, "encode_messagechat_payload", fake_encode_messagechat_payload)
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    bob.is_afk = True
    bob.auto_reply_msg = "snart tillbaka"
    ctx = SimpleNamespace(
        name="CMSG_MESSAGECHAT_WHISPER",
        payload=b"",
        decoded={"msg": "psst", "language": 0, "target": "Bob"},
    )

    code, responses = chat_handlers.handle_messagechat_whisper(alice, ctx)

    assert code == 0
    assert responses == [
        ("SMSG_MESSAGECHAT", b"8|Alice|Bob|psst"),
        ("SMSG_MESSAGECHAT", b"system|Bob is AFK: snart tillbaka"),
    ]
    assert bob.send_response_log == [[("SMSG_MESSAGECHAT", b"7|Alice|Bob|psst")]]


def test_afk_toggle_sets_player_flags(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "build_single_u32_update_object_payload",
        lambda **fields: f"update|{fields['field_index']}|{fields['value']}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    ctx = SimpleNamespace(
        name="CMSG_CHAT_MESSAGE_AFK",
        payload=b"",
        decoded={"msg": "bio"},
    )

    code, responses = chat_handlers.handle_messagechat_afk(alice, ctx)

    assert code == 0
    assert responses is None
    assert alice.is_afk is True
    assert alice.is_dnd is False
    assert alice.auto_reply_msg == "bio"
    assert alice.player_flags & 0x2
    assert alice.send_response_log == [
        [("SMSG_UPDATE_OBJECT", b"update|162|2")],
        [("SMSG_MESSAGECHAT", b"system|Alice is AFK")],
    ]
    assert bob.send_response_log == [
        [("SMSG_UPDATE_OBJECT", b"update|162|2")],
        [("SMSG_MESSAGECHAT", b"system|Alice is AFK")],
    ]


def test_afk_toggle_off_broadcasts_world_message(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "build_single_u32_update_object_payload",
        lambda **fields: f"update|{fields['field_index']}|{fields['value']}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    alice.is_afk = True
    alice.player_flags = 0x2
    ctx = SimpleNamespace(
        name="CMSG_CHAT_MESSAGE_AFK",
        payload=b"",
        decoded={"msg": ""},
    )

    code, responses = chat_handlers.handle_messagechat_afk(alice, ctx)

    assert code == 0
    assert responses is None
    assert alice.is_afk is False
    assert alice.player_flags == 0
    assert alice.send_response_log == [
        [("SMSG_UPDATE_OBJECT", b"update|162|0")],
        [("SMSG_MESSAGECHAT", b"system|Alice is no longer AFK")],
    ]
    assert bob.send_response_log == [
        [("SMSG_UPDATE_OBJECT", b"update|162|0")],
        [("SMSG_MESSAGECHAT", b"system|Alice is no longer AFK")],
    ]


def test_dnd_toggle_clears_afk_and_sets_dnd_flag(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "build_single_u32_update_object_payload",
        lambda **fields: f"update|{fields['field_index']}|{fields['value']}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    alice.is_afk = True
    alice.player_flags = 0x2
    ctx = SimpleNamespace(
        name="CMSG_MESSAGECHAT_DND",
        payload=b"",
        decoded={"msg": "upptagen"},
    )

    code, responses = chat_handlers.handle_messagechat_dnd(alice, ctx)

    assert code == 0
    assert responses is None
    assert alice.is_afk is False
    assert alice.is_dnd is True
    assert alice.auto_reply_msg == "upptagen"
    assert alice.player_flags == 0x4
    assert alice.send_response_log == [
        [("SMSG_UPDATE_OBJECT", b"update|162|4")],
        [("SMSG_MESSAGECHAT", b"system|Alice is DND")],
    ]
    assert bob.send_response_log == [
        [("SMSG_UPDATE_OBJECT", b"update|162|4")],
        [("SMSG_MESSAGECHAT", b"system|Alice is DND")],
    ]


def test_emote_broadcasts_to_same_map_sessions(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.EncoderHandler,
        "encode_packet",
        lambda opcode, fields: f"{opcode}|{fields['emote_id']}|{fields['guid']}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    other_map = _make_session(state, "Charlie", 1003)
    other_map.map_id = 530
    ctx = SimpleNamespace(
        name="CMSG_EMOTE",
        payload=b"",
        decoded={"emote_id": 66},
    )

    code, responses = chat_handlers.handle_emote(alice, ctx)

    assert code == 0
    assert responses is None
    assert alice.send_response_log == [[("SMSG_EMOTE", b"SMSG_EMOTE|66|1001")]]
    assert bob.send_response_log == [[("SMSG_EMOTE", b"SMSG_EMOTE|66|1001")]]
    assert other_map.send_response_log == []


def test_text_emote_broadcasts_text_and_followup_emote(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "encode_text_emote_payload",
        lambda **fields: f"text|{fields['player_guid']}|{fields['text_emote']}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers.EncoderHandler,
        "encode_packet",
        lambda opcode, fields: f"{opcode}|{fields['emote_id']}|{fields['guid']}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    ctx = SimpleNamespace(
        name="CMSG_SEND_TEXT_EMOTE",
        payload=b"",
        decoded={"emote_id": 84, "emote_num": 1, "target_guid": 0},
    )

    code, responses = chat_handlers.handle_send_text_emote(alice, ctx)

    assert code == 0
    assert responses is None
    expected = [
        ("SMSG_TEXT_EMOTE", b"text|1001|84"),
        ("SMSG_EMOTE", b"SMSG_EMOTE|24|1001"),
    ]
    assert alice.send_response_log == [expected]
    assert bob.send_response_log == [expected]


def test_laugh_text_emote_maps_to_laugh_animation(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "encode_text_emote_payload",
        lambda **fields: f"text|{fields['player_guid']}|{fields['text_emote']}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers.EncoderHandler,
        "encode_packet",
        lambda opcode, fields: f"{opcode}|{fields['emote_id']}|{fields['guid']}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    ctx = SimpleNamespace(
        name="CMSG_SEND_TEXT_EMOTE",
        payload=b"",
        decoded={"emote_id": 60, "emote_num": 1, "target_guid": 0},
    )

    code, responses = chat_handlers.handle_send_text_emote(alice, ctx)

    assert code == 0
    assert responses is None
    expected = [
        ("SMSG_TEXT_EMOTE", b"text|1001|60"),
        ("SMSG_EMOTE", b"SMSG_EMOTE|11|1001"),
    ]
    assert alice.send_response_log == [expected]
    assert bob.send_response_log == [expected]


def test_sit_text_emote_sets_stand_state(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "encode_text_emote_payload",
        lambda **fields: f"text|{fields['player_guid']}|{fields['text_emote']}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers,
        "build_single_u32_update_object_payload",
        lambda **fields: f"update|{fields['field_index']}|{fields['value']}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    ctx = SimpleNamespace(
        name="CMSG_SEND_TEXT_EMOTE",
        payload=b"",
        decoded={"emote_id": 86, "emote_num": 1, "target_guid": 0},
    )

    code, responses = chat_handlers.handle_send_text_emote(alice, ctx)

    assert code == 0
    assert responses is None
    assert alice.player_stand_state == 1
    expected = [
        ("SMSG_TEXT_EMOTE", b"text|1001|86"),
        ("SMSG_UPDATE_OBJECT", b"update|76|1"),
    ]
    assert alice.send_response_log == [expected]
    assert bob.send_response_log == [expected]


def test_sleep_text_emote_sets_sleep_state(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "encode_text_emote_payload",
        lambda **fields: f"text|{fields['player_guid']}|{fields['text_emote']}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers,
        "build_single_u32_update_object_payload",
        lambda **fields: f"update|{fields['field_index']}|{fields['value']}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    ctx = SimpleNamespace(
        name="CMSG_SEND_TEXT_EMOTE",
        payload=b"",
        decoded={"emote_id": 87, "emote_num": 1, "target_guid": 0},
    )

    code, responses = chat_handlers.handle_send_text_emote(alice, ctx)

    assert code == 0
    assert responses is None
    assert alice.player_stand_state == 3
    expected = [
        ("SMSG_TEXT_EMOTE", b"text|1001|87"),
        ("SMSG_UPDATE_OBJECT", b"update|76|3"),
    ]
    assert alice.send_response_log == [expected]
    assert bob.send_response_log == [expected]


def test_normal_emote_clears_sleep_state_before_animation(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.EncoderHandler,
        "encode_packet",
        lambda opcode, fields: f"{opcode}|{fields['emote_id']}|{fields['guid']}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers,
        "build_single_u32_update_object_payload",
        lambda **fields: f"update|{fields['field_index']}|{fields['value']}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    alice.player_stand_state = 3
    ctx = SimpleNamespace(
        name="CMSG_EMOTE",
        payload=b"",
        decoded={"emote_id": 66},
    )

    code, responses = chat_handlers.handle_emote(alice, ctx)

    assert code == 0
    assert responses is None
    assert alice.player_stand_state == 0
    expected = [
        ("SMSG_UPDATE_OBJECT", b"update|76|0"),
        ("SMSG_EMOTE", b"SMSG_EMOTE|66|1001"),
    ]
    assert alice.send_response_log == [expected]
    assert bob.send_response_log == [expected]


def test_decode_chat_message_fallback_for_yell_payload():
    payload = (0).to_bytes(4, "little") + bytes([3]) + b"hej"
    decoded = chat_codec.decode_chat_message("CMSG_MESSAGECHAT_YELL", payload, {})

    assert decoded["message"] == "hej"


def test_decode_chat_message_fallback_for_whisper_payload():
    bits = BitWriter()
    bits.write_bits(4, 8)
    bits.write_bits(3, 9)
    payload = (0).to_bytes(4, "little") + bits.getvalue() + b"test" + b"bob"

    decoded = chat_codec.decode_chat_message("CMSG_MESSAGECHAT_WHISPER", payload, {})

    assert decoded["message"] == "test"
    assert decoded["target"] == "bob"


def test_new_emote_clears_previous_dance_state(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.EncoderHandler,
        "encode_packet",
        lambda opcode, fields: f"{opcode}|{fields['emote_id']}|{fields['guid']}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers,
        "build_single_u32_update_object_payload",
        lambda **fields: f"update|{fields['field_index']}|{fields['value']}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    alice.npc_emote_state = 10
    ctx = SimpleNamespace(
        name="CMSG_EMOTE",
        payload=b"",
        decoded={"emote_id": 66},
    )

    code, responses = chat_handlers.handle_emote(alice, ctx)

    assert code == 0
    assert responses is None
    expected = [
        ("SMSG_UPDATE_OBJECT", b"update|89|0"),
        ("SMSG_EMOTE", b"SMSG_EMOTE|66|1001"),
    ]
    assert alice.send_response_log == [expected]
    assert bob.send_response_log == [expected]
