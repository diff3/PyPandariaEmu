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
            "build_multi_u32_update_object_payload": lambda **fields: b"",
            "build_single_u32_update_object_payload": lambda **fields: b"",
            "send_raw_packet": lambda *args, **kwargs: ("SMSG_MESSAGECHAT", b""),
        },
        "server.modules.database.DatabaseConnection": {
            "DatabaseConnection": type("DatabaseConnection", (), {}),
        },
        "server.modules.game.inventory": {
            "add_item_to_character": lambda *args, **kwargs: None,
            "auto_equip_item": lambda *args, **kwargs: None,
            "swap_character_item": lambda *args, **kwargs: None,
        },
        "server.modules.handlers.world.opcodes.login": {
            "_build_world_login_context": lambda session: SimpleNamespace(motd=""),
            "_reset_login_flow_state": lambda session: None,
        },
        "server.modules.handlers.world.opcodes.entities": {
            "build_query_player_name_response": lambda session, guid: b"",
        },
        "server.modules.handlers.world.opcodes.spells": {
            "_DEFAULT_RUN_SPEED": 7.0,
            "_restore_default_movement_speeds": lambda session: (
                setattr(session, "walk_speed", 2.5),
                setattr(session, "run_speed", 7.0),
                setattr(session, "swim_speed", 4.7),
                setattr(session, "fly_speed", 7.0),
            ),
            "set_custom_run_speed": lambda session, value: (
                setattr(session, "walk_speed", float(value) * (2.5 / 7.0)),
                setattr(session, "run_speed", float(value)),
                setattr(session, "swim_speed", float(value) * (4.7 / 7.0)),
                setattr(session, "fly_speed", float(value)),
            ),
        },
        "server.modules.handlers.world.opcodes.movement": {
            "build_move_set_speed_payload": (
                lambda session, opcode_name, value: f"{opcode_name}|{float(value):.2f}".encode()
            ),
            "build_move_set_run_speed_payload": lambda session: b"speed-packet",
            "resync_movement": lambda session: [("SMSG_PLAYER_MOVE", b"move-resync")],
            "_save_current_position_like_command": lambda *args, **kwargs: True,
        },
        "server.modules.handlers.world.inventory_sync": {
            "build_login_inventory_sync_responses": lambda session: [],
            "build_inventory_delta_responses": lambda session, result: [],
            "build_item_snapshot_responses": lambda session, item: [],
            "build_self_visible_item_update_responses": lambda session: [],
            "inventory_result_affects_equipment": lambda result: False,
            "trigger_inventory_activation": lambda session: [],
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

    sys.modules.pop("server.modules.handlers.world.bootstrap", None)
    sys.modules.pop("server.modules.handlers.world.chat.codec", None)
    sys.modules.pop("server.modules.handlers.world.state.runtime", None)
    sys.modules.pop("server.modules.handlers.world.opcodes.chat", None)
    module = importlib.import_module("server.modules.handlers.world.opcodes.chat")
    sys.modules.pop("server.modules.handlers.world.inventory_sync", None)
    return module


def _import_chat_codec():
    module = types.ModuleType("server.modules.handlers.world.bootstrap.replay")
    module.load_sniff_payload = lambda path: b""
    module.build_multi_u32_update_object_payload = lambda **fields: b""
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


def _install_movement_stub(monkeypatch, **overrides):
    module = types.ModuleType("server.modules.handlers.world.opcodes.movement")
    module.build_move_set_speed_payload = (
        lambda session, opcode_name, value: f"{opcode_name}|{float(value):.2f}".encode()
    )
    module.build_move_set_run_speed_payload = lambda session: b"speed-packet"
    module.build_move_set_flight_speed_payload = lambda session: b"flight-speed-packet"
    module.build_move_set_can_fly_payload = (
        lambda session, enabled: f"can-fly|{int(bool(enabled))}".encode()
    )
    module.resync_movement = lambda session: [("SMSG_PLAYER_MOVE", b"move-resync")]
    module.build_same_map_teleport_payload = lambda session: b"teleport-payload"
    module._save_current_position_like_command = lambda *args, **kwargs: True
    module._capture_persist_position_from_session = lambda session: None
    module._mark_position_dirty = lambda session: None
    module._movement_state = lambda session: SimpleNamespace(
        x=float(getattr(session, "x", 0.0) or 0.0),
        y=float(getattr(session, "y", 0.0) or 0.0),
        z=float(getattr(session, "z", 0.0) or 0.0),
        orientation=float(getattr(session, "orientation", 0.0) or 0.0),
        flags=0,
        flags2=0,
        counter=0,
    )
    for name, value in overrides.items():
        setattr(module, name, value)
    monkeypatch.setitem(sys.modules, "server.modules.handlers.world.opcodes.movement", module)
    return module


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


def test_unknown_dot_command_returns_system_message_and_does_not_broadcast(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers,
        "encode_messagechat_payload",
        lambda **fields: f"{fields['chat_type']}|{fields['sender_name']}|{fields['message']}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    ctx = SimpleNamespace(
        name="CMSG_MESSAGECHAT_SAY",
        payload=b"",
        decoded={"msg": ".notacommand", "language": 0},
    )

    code, responses = chat_handlers.handle_messagechat_say(alice, ctx)

    assert code == 0
    assert responses == [("SMSG_MESSAGECHAT", b"system|Unknown command: .notacommand")]
    assert alice.send_response_log == []
    assert bob.send_response_log == []


def test_dot_inside_normal_text_still_broadcasts_as_chat(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "encode_messagechat_payload",
        lambda **fields: f"{fields['chat_type']}|{fields['sender_name']}|{fields['message']}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    ctx = SimpleNamespace(
        name="CMSG_MESSAGECHAT_SAY",
        payload=b"",
        decoded={"msg": "hej. detta ar vanlig text", "language": 0},
    )

    code, responses = chat_handlers.handle_messagechat_say(alice, ctx)

    assert code == 0
    assert responses is None
    assert alice.send_response_log == [[("SMSG_MESSAGECHAT", b"1|Alice|hej. detta ar vanlig text")]]
    assert bob.send_response_log == [[("SMSG_MESSAGECHAT", b"1|Alice|hej. detta ar vanlig text")]]


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


def test_speed_command_updates_run_speed_and_returns_speed_packet(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.spells_handlers,
        "set_custom_run_speed",
        lambda session, value: (
            setattr(session, "walk_speed", float(value) * (2.5 / 7.0)),
            setattr(session, "run_speed", float(value)),
            setattr(session, "swim_speed", float(value) * (4.7 / 7.0)),
            setattr(session, "fly_speed", float(value)),
        ),
    )
    _install_movement_stub(monkeypatch)
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = chat_handlers._handle_chat_command(alice, ".speed 5")

    assert alice.run_speed == 35.0
    assert responses == [
        ("SMSG_MOVE_SET_WALK_SPEED", b"SMSG_MOVE_SET_WALK_SPEED|12.50"),
        ("SMSG_MOVE_SET_RUN_SPEED", b"SMSG_MOVE_SET_RUN_SPEED|35.00"),
        ("SMSG_MOVE_SET_SWIM_SPEED", b"SMSG_MOVE_SET_SWIM_SPEED|23.50"),
        ("SMSG_MOVE_SET_FLIGHT_SPEED", b"SMSG_MOVE_SET_FLIGHT_SPEED|35.00"),
        ("SMSG_PLAYER_MOVE", b"move-resync"),
        ("SMSG_MESSAGECHAT", b"system|[Speed] run=35.00"),
    ]


def test_fly_on_sends_enable_packet_flight_speed_and_move(monkeypatch):
    _install_movement_stub(monkeypatch)
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = chat_handlers._handle_chat_command(alice, ".fly on")

    assert alice.can_fly is True
    assert alice.is_flying is True
    assert responses == [
        ("SMSG_MOVE_SET_CAN_FLY", b"can-fly|1"),
        ("SMSG_MOVE_SET_FLIGHT_SPEED", b"flight-speed-packet"),
        ("SMSG_PLAYER_MOVE", b"move-resync"),
        ("SMSG_MESSAGECHAT", b"system|[Fly] on"),
    ]


def test_fly_off_sends_disable_packet_and_move(monkeypatch):
    _install_movement_stub(monkeypatch)
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.can_fly = True
    alice.is_flying = True

    responses = chat_handlers._handle_chat_command(alice, ".fly off")

    assert alice.can_fly is False
    assert alice.is_flying is False
    assert responses == [
        ("SMSG_MOVE_UNSET_CAN_FLY", b"can-fly|0"),
        ("SMSG_PLAYER_MOVE", b"move-resync"),
        ("SMSG_MESSAGECHAT", b"system|[Fly] off"),
    ]


def test_roll_command_broadcasts_world_system_message(monkeypatch):
    monkeypatch.setattr(chat_handlers.random, "randint", lambda start, end: 42)

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    sent = []

    def fake_broadcast_system_message(message, **kwargs):
        responses = [("SMSG_MESSAGECHAT", f"system|{message}".encode())]
        alice.send_response(responses)
        bob.send_response(responses)
        sent.append((message, kwargs))

    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "broadcast_system_message",
        fake_broadcast_system_message,
    )

    responses = chat_handlers._handle_chat_command(alice, ".roll")

    assert responses == []
    expected = [("SMSG_MESSAGECHAT", b"system|Alice rolls 42 (1-100)")]
    assert sent == [("Alice rolls 42 (1-100)", {"scope": "world"})]
    assert alice.send_response_log == [expected]
    assert bob.send_response_log == [expected]


def test_level_without_args_adds_one_level(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        chat_handlers.DatabaseConnection,
        "get_level_stats_for_class",
        staticmethod(lambda race, class_id: [SimpleNamespace(level=value) for value in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)]),
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers.DatabaseConnection,
        "save_character_level",
        staticmethod(
            lambda char_guid, realm_id, level, xp=0: captured.update(
                {
                    "char_guid": int(char_guid),
                    "realm_id": int(realm_id),
                    "level": int(level),
                    "xp": int(xp),
                }
            )
            or True
        ),
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_helper",
        lambda name: (
            (lambda session: [("SMSG_UPDATE_OBJECT", b"level-update")])
            if name == "build_level_command_responses"
            else (lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())])
        ),
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.realm_id = 1
    alice.level = 5
    alice.race = 2
    alice.class_id = 8

    responses = chat_handlers._handle_chat_command(alice, ".level")

    assert alice.level == 6
    assert captured == {"char_guid": 1001, "realm_id": 1, "level": 6, "xp": 0}
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"level-update"),
        ("SMSG_MESSAGECHAT", b"system|[Level] 5 -> 6"),
    ]


def test_level_relative_change_clamps_to_valid_range(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        chat_handlers.DatabaseConnection,
        "get_level_stats_for_class",
        staticmethod(lambda race, class_id: [SimpleNamespace(level=value) for value in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)]),
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers.DatabaseConnection,
        "save_character_level",
        staticmethod(
            lambda char_guid, realm_id, level, xp=0: captured.update({"level": int(level), "xp": int(xp)}) or True
        ),
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_helper",
        lambda name: (
            (lambda session: [("SMSG_UPDATE_OBJECT", b"level-update")])
            if name == "build_level_command_responses"
            else (lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())])
        ),
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.realm_id = 1
    alice.level = 5
    alice.race = 2
    alice.class_id = 8

    responses = chat_handlers._handle_chat_command(alice, ".level -10")

    assert alice.level == 1
    assert captured == {"level": 1, "xp": 0}
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"level-update"),
        ("SMSG_MESSAGECHAT", b"system|[Level] 5 -> 1"),
    ]


def test_level_set_uses_exact_level(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        chat_handlers.DatabaseConnection,
        "get_level_stats_for_class",
        staticmethod(lambda race, class_id: [SimpleNamespace(level=value) for value in range(1, 91)]),
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers.DatabaseConnection,
        "save_character_level",
        staticmethod(
            lambda char_guid, realm_id, level, xp=0: captured.update({"level": int(level), "xp": int(xp)}) or True
        ),
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_helper",
        lambda name: (
            (lambda session: [("SMSG_UPDATE_OBJECT", b"level-update")])
            if name == "build_level_command_responses"
            else (lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())])
        ),
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.realm_id = 1
    alice.level = 5
    alice.race = 2
    alice.class_id = 8

    responses = chat_handlers._handle_chat_command(alice, ".level set 42")

    assert alice.level == 42
    assert captured == {"level": 42, "xp": 0}
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"level-update"),
        ("SMSG_MESSAGECHAT", b"system|[Level] 5 -> 42"),
    ]


def test_build_level_command_responses_appends_explicit_level_field(monkeypatch):
    runtime_module = sys.modules["server.modules.handlers.world.state.runtime"]
    monkeypatch.setattr(
        runtime_module,
        "_build_player_value_update_responses",
        lambda session: [("SMSG_UPDATE_OBJECT", b"base-values")],
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers,
        "build_single_u32_update_object_payload",
        lambda *, map_id, guid, field_index, value: (
            f"map={int(map_id)}|guid={int(guid)}|field={int(field_index)}|value={int(value)}".encode()
        ),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.map_id = 1
    alice.level = 42

    responses = chat_handlers._build_level_command_responses(alice)

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"base-values"),
        ("SMSG_UPDATE_OBJECT", b"map=1|guid=1001|field=55|value=42"),
    ]


def test_map_on_reveals_all_explored_zones(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        chat_handlers,
        "build_explored_zones_update_response",
        lambda session: captured.update({"explored_zones_raw": session.explored_zones_raw})
        or ("SMSG_UPDATE_OBJECT", b"map-update"),
    )
    monkeypatch.setattr(
        chat_handlers.DatabaseConnection,
        "save_character_explored_zones",
        staticmethod(
            lambda char_guid, realm_id, explored_zones: captured.update(
                {
                    "char_guid": int(char_guid),
                    "realm_id": int(realm_id),
                    "saved_explored_zones": str(explored_zones),
                }
            )
            or True
        ),
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.realm_id = 1

    responses = chat_handlers._handle_chat_command(alice, "map on")

    assert captured["char_guid"] == 1001
    assert captured["realm_id"] == 1
    assert len(captured["saved_explored_zones"].split()) == 200
    assert set(captured["saved_explored_zones"].split()) == {"4294967295"}
    assert captured["explored_zones_raw"] == captured["saved_explored_zones"]
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"map-update"),
        ("SMSG_MESSAGECHAT", b"system|[Map] all explored"),
    ]


def test_map_zero_clears_all_explored_zones(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        chat_handlers,
        "build_explored_zones_update_response",
        lambda session: captured.update({"explored_zones_raw": session.explored_zones_raw})
        or ("SMSG_UPDATE_OBJECT", b"map-update"),
    )
    monkeypatch.setattr(
        chat_handlers.DatabaseConnection,
        "save_character_explored_zones",
        staticmethod(
            lambda char_guid, realm_id, explored_zones: captured.update(
                {
                    "char_guid": int(char_guid),
                    "realm_id": int(realm_id),
                    "saved_explored_zones": str(explored_zones),
                }
            )
            or True
        ),
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.realm_id = 1

    responses = chat_handlers._handle_chat_command(alice, "map 0")

    assert captured["char_guid"] == 1001
    assert captured["realm_id"] == 1
    assert len(captured["saved_explored_zones"].split()) == 200
    assert set(captured["saved_explored_zones"].split()) == {"0"}
    assert captured["explored_zones_raw"] == captured["saved_explored_zones"]
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"map-update"),
        ("SMSG_MESSAGECHAT", b"system|[Map] exploration reset"),
    ]


def test_player_value_updates_include_persisted_map_exploration(monkeypatch):
    runtime_module = sys.modules["server.modules.handlers.world.state.runtime"]
    context_module = importlib.import_module("server.modules.handlers.world.login.context")
    packets_module = importlib.import_module("server.modules.handlers.world.login.packets")

    monkeypatch.setattr(
        context_module.WorldLoginContext,
        "from_session",
        staticmethod(lambda session: SimpleNamespace()),
    )
    monkeypatch.setattr(
        packets_module,
        "build_login_packet",
        lambda opcode_name, ctx: f"{opcode_name}|pkt".encode(),
    )
    monkeypatch.setattr(
        runtime_module,
        "build_explored_zones_update_response",
        lambda session: ("SMSG_UPDATE_OBJECT", b"explored-zones"),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = runtime_module._build_player_value_update_responses(alice)

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"SMSG_UPDATE_OBJECT_1773613176_0004|pkt"),
        ("SMSG_UPDATE_OBJECT", b"SMSG_UPDATE_OBJECT_1773613185_0006|pkt"),
        ("SMSG_UPDATE_OBJECT", b"explored-zones"),
    ]


def test_invfix_returns_full_inventory_sync_via_login_pipeline(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        chat_handlers,
        "build_login_inventory_sync_responses",
        lambda session: captured.update(
            {
                "known_inventory_guids": set(getattr(session, "known_inventory_guids", set())),
                "inventory_activated": bool(getattr(session, "inventory_activated", True)),
            }
        )
        or [("SMSG_UPDATE_OBJECT", b"invfix")],
    )
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.known_inventory_guids = {111, 222}
    alice.inventory_activated = True

    responses = chat_handlers._handle_chat_command(alice, ".invfix")

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"invfix"),
        ("SMSG_MESSAGECHAT", b"system|[InvFix] full inventory resync sent"),
    ]
    assert captured["known_inventory_guids"] == set()
    assert captured["inventory_activated"] is False
    assert alice.known_inventory_guids == set()
    assert alice.inventory_activated is False


def test_mount_command_sends_minimal_visual_update(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers,
        "apply_player_state_change",
        lambda session, **kwargs: [("SMSG_UPDATE_OBJECT", f"mount|{int(kwargs['mount_display_id'])}".encode())],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = chat_handlers._handle_chat_command(alice, ".mount")

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"mount|2404"),
        ("SMSG_MESSAGECHAT", b"system|[Mount] mount requested"),
    ]
    assert alice.is_mounted is True
    assert alice.mount_spell is None


def test_dismount_command_clears_mount_display(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers,
        "apply_player_state_change",
        lambda session, **kwargs: [("SMSG_UPDATE_OBJECT", f"mount|{int(kwargs['mount_display_id'])}".encode())],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.is_mounted = True
    alice.mount_spell = 123

    responses = chat_handlers._handle_chat_command(alice, ".dismount")

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"mount|0"),
        ("SMSG_MESSAGECHAT", b"system|[Mount] dismount requested"),
    ]
    assert alice.is_mounted is False
    assert alice.mount_spell is None


def test_morph_command_uses_display_only_update(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_helper",
        lambda name: (
            (lambda session, display_id: [("SMSG_UPDATE_OBJECT", f"display|{int(display_id)}".encode())])
            if name == "build_display_id_responses"
            else (lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())])
        ),
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.display_id = 12345

    responses = chat_handlers._handle_chat_command(alice, ".morph 29266")

    assert alice.original_display_id == 12345
    assert alice.native_display_id == 12345
    assert alice.morph_display_id == 29266
    assert alice.display_id == 29266
    assert alice.is_morphed is True
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"display|29266"),
        ("SMSG_MESSAGECHAT", b"system|[Morph] display=29266"),
    ]


def test_morph_command_resolves_name_lookup(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_helper",
        lambda name: (
            (lambda session, display_id: [("SMSG_UPDATE_OBJECT", f"display|{int(display_id)}".encode())])
            if name == "build_display_id_responses"
            else (lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())])
        ),
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.display_id = 12345

    responses = chat_handlers._handle_chat_command(alice, ".morph sylvanas")

    assert alice.display_id == 28213
    assert alice.is_morphed is True
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"display|28213"),
        ("SMSG_MESSAGECHAT", b"system|[Morph] display=28213"),
    ]


def test_demorph_restores_native_display_without_inventory_or_appearance_resync(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_helper",
        lambda name: (
            (lambda session, display_id: [("SMSG_UPDATE_OBJECT", f"display|{int(display_id)}".encode())])
            if name == "build_display_id_responses"
            else (lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())])
        ),
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.display_id = 29266
    alice.original_display_id = 15476
    alice.native_display_id = 15476
    alice.morph_display_id = 29266
    alice.is_morphed = True

    responses = chat_handlers._handle_chat_command(alice, ".demorph")

    assert alice.display_id == 15476
    assert alice.original_display_id is None
    assert alice.native_display_id == 15476
    assert alice.morph_display_id is None
    assert alice.is_morphed is False
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"display|15476"),
        ("SMSG_MESSAGECHAT", b"system|[Morph] restored=15476"),
    ]


def test_morph_chain_keeps_original_display_until_demorph(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_helper",
        lambda name: (
            (lambda session, display_id: [("SMSG_UPDATE_OBJECT", f"display|{int(display_id)}".encode())])
            if name == "build_display_id_responses"
            else (lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())])
        ),
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.display_id = 12345

    chat_handlers._handle_chat_command(alice, ".morph 29266")
    chat_handlers._handle_chat_command(alice, ".morph 28213")
    responses = chat_handlers._handle_chat_command(alice, ".demorph")

    assert alice.display_id == 12345
    assert alice.original_display_id is None
    assert alice.morph_display_id is None
    assert alice.is_morphed is False
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"display|12345"),
        ("SMSG_MESSAGECHAT", b"system|[Morph] restored=12345"),
    ]


def test_demorph_returns_not_morphed_when_idle(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = chat_handlers._handle_chat_command(alice, ".demorph")

    assert responses == [("SMSG_MESSAGECHAT", b"system|Not morphed")]


def test_demorph_restores_native_display_when_morph_flag_is_missing(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_helper",
        lambda name: (
            (lambda session, display_id: [("SMSG_UPDATE_OBJECT", f"display|{int(display_id)}".encode())])
            if name == "build_display_id_responses"
            else (lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())])
        ),
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.display_id = 28213
    alice.native_display_id = 15476
    alice.is_morphed = False

    responses = chat_handlers._handle_chat_command(alice, ".demorph")

    assert alice.display_id == 15476
    assert alice.original_display_id is None
    assert alice.native_display_id == 15476
    assert alice.morph_display_id is None
    assert alice.is_morphed is False
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"display|15476"),
        ("SMSG_MESSAGECHAT", b"system|[Morph] restored=15476"),
    ]


def test_build_state_responses_duplicates_display_id_into_native_display(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "_build_movement_resync_responses",
        lambda session: [],
    )
    monkeypatch.setattr(
        chat_handlers,
        "build_multi_u32_update_object_payload",
        lambda *, map_id, guid, field_updates: (
            f"map={int(map_id)}|guid={int(guid)}|fields={field_updates}".encode()
        ),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = chat_handlers.build_state_responses(alice, {69: 29266})

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"map=1|guid=1001|fields=[(69, 29266)]"),
    ]


def test_apply_state_and_resync_appends_player_move_when_missing(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "_build_movement_resync_responses",
        lambda session: [("SMSG_PLAYER_MOVE", b"move")],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = chat_handlers.apply_state_and_resync(alice, [("SMSG_UPDATE_OBJECT", b"values")])

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"values"),
        ("SMSG_PLAYER_MOVE", b"move"),
    ]


def test_build_state_responses_uses_direct_update_when_morphed(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "_build_movement_resync_responses",
        lambda session: [],
    )
    monkeypatch.setattr(
        chat_handlers,
        "build_multi_u32_update_object_payload",
        lambda *, map_id, guid, field_updates: (
            f"map={int(map_id)}|guid={int(guid)}|fields={field_updates}".encode()
        ),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.is_morphed = True

    responses = chat_handlers.build_state_responses(alice, {})

    assert responses == []


def test_build_state_responses_updates_display_and_visible_items_without_self_create(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "_build_movement_resync_responses",
        lambda session: [],
    )
    monkeypatch.setattr(
        chat_handlers,
        "build_multi_u32_update_object_payload",
        lambda *, map_id, guid, field_updates: (
            f"map={int(map_id)}|guid={int(guid)}|fields={field_updates}".encode()
        ),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = chat_handlers.build_state_responses(alice, {69: 28213})

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"map=1|guid=1001|fields=[(69, 28213)]"),
    ]


def test_build_display_id_responses_updates_self_and_visible_peers(monkeypatch):
    runtime_module = sys.modules["server.modules.handlers.world.state.runtime"]
    monkeypatch.setattr(
        chat_handlers,
        "build_multi_u32_update_object_payload",
        lambda *, map_id, guid, field_updates: (
            f"map={int(map_id)}|guid={int(guid)}|fields={field_updates}".encode()
        ),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    alice.login_state = "IN_WORLD"
    bob.login_state = "IN_WORLD"
    bob.visible_guids.add(1001)
    monkeypatch.setattr(runtime_module, "iter_in_world_sessions", lambda **kwargs: [alice, bob], raising=False)
    monkeypatch.setattr(runtime_module, "_visible_guid_set", lambda session: session.visible_guids, raising=False)
    monkeypatch.setattr(
        runtime_module,
        "dispatch_responses_to_sessions",
        lambda targets, responses: [target.send_response(responses) for target in targets],
        raising=False,
    )

    responses = chat_handlers.build_display_id_responses(alice, 28213)

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"map=1|guid=1001|fields=[(69, 28213)]"),
    ]
    assert bob.send_response_log == [[
        ("SMSG_UPDATE_OBJECT", b"map=1|guid=1001|fields=[(69, 28213)]"),
    ]]


def test_build_display_id_responses_uses_char_guid_for_self_when_world_guid_exists(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "build_multi_u32_update_object_payload",
        lambda *, map_id, guid, field_updates: (
            f"map={int(map_id)}|guid={int(guid)}|fields={field_updates}".encode()
        ),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.world_guid = 0x3000100000002

    responses = chat_handlers.build_display_id_responses(alice, 28213)

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"map=1|guid=1001|fields=[(69, 28213)]"),
    ]


def test_apply_player_state_change_mount_updates_fields_and_resyncs_movement(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        chat_handlers,
        "_build_field_update_responses",
        lambda session, field_updates: (
            captured.setdefault("field_updates", dict(field_updates)),
            [("SMSG_UPDATE_OBJECT", b"values")],
        )[1],
    )
    monkeypatch.setattr(
        chat_handlers,
        "_build_movement_resync_responses",
        lambda session: [("SMSG_PLAYER_MOVE", b"move")],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = chat_handlers.apply_player_state_change(alice, mount_display_id=2404)

    assert alice.mount_display_id == 2404
    assert alice.unit_flags & 0x08000000
    assert captured["field_updates"][0x60] & 0x08000000
    assert captured["field_updates"][0x6A] == 2404
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"values"),
        ("SMSG_PLAYER_MOVE", b"move"),
    ]


def test_apply_player_state_change_same_map_position_queues_near_teleport(monkeypatch):
    movement_module = _install_movement_stub(monkeypatch)
    monkeypatch.setattr(
        movement_module,
        "_movement_state",
        lambda session: SimpleNamespace(x=0.0, y=0.0, z=0.0, orientation=0.0, flags=1, flags2=2),
        raising=False,
    )
    monkeypatch.setattr(movement_module, "_capture_persist_position_from_session", lambda session: None, raising=False)
    monkeypatch.setattr(movement_module, "_mark_position_dirty", lambda session: None, raising=False)
    monkeypatch.setattr(movement_module, "build_same_map_teleport_payload", lambda session: b"teleport", raising=False)
    monkeypatch.setattr(
        chat_handlers,
        "_build_field_update_responses",
        lambda session, field_updates: [("SMSG_UPDATE_OBJECT", b"pre-resync")],
    )
    monkeypatch.setattr(
        chat_handlers,
        "_build_movement_resync_responses",
        lambda session: [("SMSG_PLAYER_MOVE", b"move")],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.map_id = 1
    alice.zone = 12

    responses = chat_handlers.apply_player_state_change(
        alice,
        position=(10.0, 20.0, 30.0, 1.5),
        map_id=1,
    )

    assert alice.x == 10.0
    assert alice.y == 20.0
    assert alice.z == 30.0
    assert alice.orientation == 1.5
    assert alice.near_teleport_pending is True
    assert alice.teleport_pending is False
    assert len(responses) == 2
    assert responses[0][0] == "SMSG_MOVE_TELEPORT"
    assert responses[1] == ("SMSG_PLAYER_MOVE", b"move")


def test_apply_player_state_change_cross_map_position_returns_transfer_packets(monkeypatch):
    movement_module = _install_movement_stub(monkeypatch)
    monkeypatch.setattr(
        movement_module,
        "_movement_state",
        lambda session: SimpleNamespace(x=0.0, y=0.0, z=0.0, orientation=0.0, flags=1, flags2=2),
        raising=False,
    )
    monkeypatch.setattr(movement_module, "_capture_persist_position_from_session", lambda session: None, raising=False)
    monkeypatch.setattr(movement_module, "_mark_position_dirty", lambda session: None, raising=False)
    monkeypatch.setattr(chat_handlers, "_build_field_update_responses", lambda session, field_updates: [])
    monkeypatch.setattr(
        chat_handlers,
        "build_login_packet",
        lambda opcode_name, ctx: f"{opcode_name}|{getattr(ctx, 'map_id', 0)}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.map_id = 1
    alice.zone = 12

    responses = chat_handlers.apply_player_state_change(
        alice,
        position=(10.0, 20.0, 30.0, 1.5),
        map_id=0,
    )

    assert alice.map_id == 0
    assert alice.teleport_pending is True
    assert alice.near_teleport_pending is False
    assert responses == [
        ("SMSG_TRANSFER_PENDING", b"SMSG_TRANSFER_PENDING|0"),
        ("SMSG_NEW_WORLD", b"SMSG_NEW_WORLD|0"),
    ]


def test_morph_unknown_name_returns_feedback(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = chat_handlers._handle_chat_command(alice, ".morph unknown")

    assert responses == [
        ("SMSG_MESSAGECHAT", b"system|Morph target not found"),
    ]


def test_forced_inventory_slot_resend_uses_minimal_player_values_update(monkeypatch):
    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.inventory_state = SimpleNamespace(
        get=lambda bag, slot: SimpleNamespace(item_guid=2000) if (bag, slot) == (0, 23) else None
    )
    captured = {}

    def fake_build_multi_u32_update_object_payload(**fields):
        captured.update(fields)
        return b"slot-resend"

    monkeypatch.setattr(
        chat_handlers,
        "build_multi_u32_update_object_payload",
        fake_build_multi_u32_update_object_payload,
    )

    responses = chat_handlers._build_forced_inventory_slot_resend_responses(alice)

    assert len(responses) == 1
    opcode, payload = responses[0]
    assert opcode == "SMSG_UPDATE_OBJECT"
    field_index = chat_handlers._inventory_slot_field_index(0, 23)
    item_guid = chat_handlers._make_item_world_guid(2000)
    assert payload == b"slot-resend"
    assert captured["map_id"] == 1
    assert captured["guid"] == 1001
    assert captured["field_updates"] == [
        (field_index, int(item_guid & 0xFFFFFFFF)),
        (field_index + 1, int((item_guid >> 32) & 0xFFFFFFFF)),
    ]


def test_fixplayer_default_returns_values_then_speed_then_movement(monkeypatch):
    bootstrap_module = sys.modules["server.modules.handlers.world.bootstrap.replay"]
    monkeypatch.setattr(
        bootstrap_module,
        "_build_dynamic_active_mover_packet",
        lambda session: ("SMSG_MOVE_SET_ACTIVE_MOVER", b"active-mover"),
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers,
        "build_login_packet",
        lambda opcode_name, ctx: f"{opcode_name}|pkt".encode(),
    )
    monkeypatch.setattr(
        chat_handlers,
        "build_login_inventory_sync_responses",
        lambda session: [("SMSG_UPDATE_OBJECT", b"inv")],
    )
    monkeypatch.setattr(
        chat_handlers.login_handlers,
        "_build_world_login_context",
        lambda session: SimpleNamespace(),
    )
    runtime_module = sys.modules["server.modules.handlers.world.state.runtime"]
    monkeypatch.setattr(
        runtime_module,
        "_build_player_create_update_response",
        lambda session: ("SMSG_UPDATE_OBJECT", b"create"),
        raising=False,
    )
    monkeypatch.setattr(
        runtime_module,
        "_build_player_value_update_responses",
        lambda session: [
            ("SMSG_UPDATE_OBJECT", b"values-1"),
            ("SMSG_UPDATE_OBJECT", b"values-2"),
        ],
        raising=False,
    )
    monkeypatch.setattr(
        runtime_module,
        "_build_player_move_response",
        lambda session: ("SMSG_PLAYER_MOVE", b"player-move"),
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers,
        "build_move_set_speed_payload",
        lambda session, opcode_name, value: f"{opcode_name}|{float(value):.2f}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.walk_speed = 2.5
    alice.run_speed = 7.0
    alice.swim_speed = 4.7
    alice.fly_speed = 7.0
    alice.x = 1.0
    alice.y = 2.0
    alice.z = 3.0

    responses = chat_handlers._handle_chat_command(alice, ".fixplayer")

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"values-1"),
        ("SMSG_UPDATE_OBJECT", b"values-2"),
        ("SMSG_MOVE_SET_WALK_SPEED", b"SMSG_MOVE_SET_WALK_SPEED|2.50"),
        ("SMSG_MOVE_SET_RUN_SPEED", b"SMSG_MOVE_SET_RUN_SPEED|7.00"),
        ("SMSG_MOVE_SET_SWIM_SPEED", b"SMSG_MOVE_SET_SWIM_SPEED|4.70"),
        ("SMSG_MOVE_SET_FLIGHT_SPEED", b"SMSG_MOVE_SET_FLIGHT_SPEED|7.00"),
        ("SMSG_PLAYER_MOVE", b"player-move"),
        ("SMSG_MESSAGECHAT", b"system|[FixPlayer] mode=0 resync sent"),
    ]


def test_fixplayer_teleport_returns_bootstrap_like_sequence(monkeypatch):
    bootstrap_module = sys.modules["server.modules.handlers.world.bootstrap.replay"]
    monkeypatch.setattr(
        bootstrap_module,
        "_build_dynamic_active_mover_packet",
        lambda session: ("SMSG_MOVE_SET_ACTIVE_MOVER", b"active-mover"),
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers,
        "build_login_packet",
        lambda opcode_name, ctx: f"{opcode_name}|pkt".encode(),
    )
    monkeypatch.setattr(
        chat_handlers,
        "build_login_inventory_sync_responses",
        lambda session: [("SMSG_UPDATE_OBJECT", b"inv")],
    )
    monkeypatch.setattr(
        chat_handlers.login_handlers,
        "_build_world_login_context",
        lambda session: SimpleNamespace(),
    )
    runtime_module = sys.modules["server.modules.handlers.world.state.runtime"]
    monkeypatch.setattr(
        runtime_module,
        "_build_player_create_update_response",
        lambda session: ("SMSG_UPDATE_OBJECT", b"create"),
        raising=False,
    )
    monkeypatch.setattr(
        runtime_module,
        "_build_player_value_update_responses",
        lambda session: [
            ("SMSG_UPDATE_OBJECT", b"values-1"),
            ("SMSG_UPDATE_OBJECT", b"values-2"),
        ],
        raising=False,
    )
    monkeypatch.setattr(
        runtime_module,
        "_build_player_move_response",
        lambda session: ("SMSG_PLAYER_MOVE", b"player-move"),
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers,
        "build_move_set_speed_payload",
        lambda session, opcode_name, value: f"{opcode_name}|{float(value):.2f}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers,
        "find_teleport",
        lambda name: {
            "name": "orgrimmar",
            "map": 1,
            "x": 123.0,
            "y": 456.0,
            "z": 78.0,
            "o": 1.5,
        }
        if name == "orgrimmar"
        else None,
    )
    monkeypatch.setattr(
        chat_handlers,
        "resolve_zone_from_position",
        lambda map_id, x, y: 1637,
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.walk_speed = 2.5
    alice.run_speed = 7.0
    alice.swim_speed = 4.7
    alice.fly_speed = 7.0

    responses = chat_handlers._handle_chat_command(alice, ".fixplayer orgrimmar")

    assert responses == [
        ("SMSG_LOGIN_VERIFY_WORLD", b"SMSG_LOGIN_VERIFY_WORLD|pkt"),
        ("SMSG_LOGIN_SET_TIME_SPEED", b"SMSG_LOGIN_SET_TIME_SPEED|pkt"),
        ("SMSG_BIND_POINT_UPDATE", b"SMSG_BIND_POINT_UPDATE|pkt"),
        ("SMSG_MOVE_SET_ACTIVE_MOVER", b"active-mover"),
        ("SMSG_UPDATE_OBJECT", b"create"),
        ("SMSG_UPDATE_OBJECT", b"values-1"),
        ("SMSG_UPDATE_OBJECT", b"values-2"),
        ("SMSG_UPDATE_OBJECT", b"inv"),
        ("SMSG_TIME_SYNC_REQUEST", b"SMSG_TIME_SYNC_REQUEST|pkt"),
        ("SMSG_PHASE_SHIFT_CHANGE", b"SMSG_PHASE_SHIFT_CHANGE|pkt"),
        ("SMSG_INIT_WORLD_STATES", b"SMSG_INIT_WORLD_STATES|pkt"),
        ("SMSG_WEATHER", b"SMSG_WEATHER|pkt"),
        ("SMSG_QUERY_TIME_RESPONSE", b"SMSG_QUERY_TIME_RESPONSE|pkt"),
        ("SMSG_MOVE_SET_WALK_SPEED", b"SMSG_MOVE_SET_WALK_SPEED|2.50"),
        ("SMSG_MOVE_SET_RUN_SPEED", b"SMSG_MOVE_SET_RUN_SPEED|7.00"),
        ("SMSG_MOVE_SET_SWIM_SPEED", b"SMSG_MOVE_SET_SWIM_SPEED|4.70"),
        ("SMSG_MOVE_SET_FLIGHT_SPEED", b"SMSG_MOVE_SET_FLIGHT_SPEED|7.00"),
        ("SMSG_PLAYER_MOVE", b"player-move"),
        ("SMSG_MESSAGECHAT", b"system|[FixPlayer] destination=orgrimmar"),
    ]
    assert alice.map_id == 1
    assert alice.x == 123.0
    assert alice.y == 456.0
    assert alice.z == 78.0
    assert alice.orientation == 1.5
    assert alice.zone == 1637
    assert alice.instance_id == 0
    assert alice.teleport_destination == "orgrimmar"


def test_fixplayer_unknown_teleport_returns_feedback(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "find_teleport",
        lambda name: None,
    )
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = chat_handlers._handle_chat_command(alice, ".fixplayer nowhere")

    assert responses == [
        ("SMSG_MESSAGECHAT", b"system|Teleport not found"),
    ]


def test_fixspeed_queues_same_map_teleport_resync(monkeypatch):
    movement_module = _install_movement_stub(monkeypatch)
    monkeypatch.setattr(
        movement_module,
        "build_same_map_teleport_payload",
        lambda session: b"teleport-payload",
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: message.encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.x = 1.0
    alice.y = 2.0
    alice.z = 3.0
    alice.orientation = 4.0
    alice.run_speed = 7.0

    responses = chat_handlers._handle_chat_command(alice, ".fixspeed")

    assert alice.near_teleport_pending is True
    assert alice.fixspeed_pending is True
    assert responses == [
        ("SMSG_MESSAGECHAT", b"[FixSpeed] queued same-map resync"),
        ("SMSG_MOVE_TELEPORT", b"teleport-payload"),
    ]


def test_gps_returns_feedback_and_logs_telxyz():
    monkeypatch = __import__("pytest").MonkeyPatch()
    logged_messages = []

    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: message.encode(),
    )
    monkeypatch.setattr(
        chat_handlers.Logger,
        "info",
        lambda message, *args: logged_messages.append(
            message % args if args else message
        ),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.map_id = 1
    alice.x = 12.5
    alice.y = 34.5
    alice.z = 56.5
    alice.orientation = 1.25

    responses = chat_handlers._handle_chat_command(alice, ".gps")

    assert responses == [
        (
            "SMSG_MESSAGECHAT",
            b"[GPS] map=1 x=12.50 y=34.50 z=56.50 o=1.25",
        )
    ]
    assert "[GPS] map=1 x=12.50 y=34.50 z=56.50 o=1.25" in logged_messages
    assert ".telxyz 1 12.50 34.50 56.50 1.25" in logged_messages
    monkeypatch.undo()


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
