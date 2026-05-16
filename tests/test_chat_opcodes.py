import importlib
import struct
import sys
import time
import types
from types import SimpleNamespace
from pathlib import Path

from DSL.modules.EncoderHandler import EncoderHandler
from DSL.modules.bitsHandler import BitInterPreter, BitWriter
from server.modules.interpretation.utils import dsl_decode
from server.modules.handlers.world.state.global_state import GlobalState
from server.session.world_session import WorldSession


def _test_pack_update_mask(field_indices: list[int]) -> bytes:
    block_count = max(3, ((max(field_indices, default=-1) // 32) + 1))
    mask = bytearray(block_count * 4)
    for field_index in sorted({int(index) for index in field_indices if int(index) >= 0}):
        mask[field_index // 8] |= 1 << (field_index % 8)
    return bytes(mask)


def _test_build_values_update(session, guid: int, changed_fields: list[tuple[int, int]]) -> bytes:
    normalized_fields = sorted((int(index), int(value) & 0xFFFFFFFF) for index, value in changed_fields)
    mask = _test_pack_update_mask([index for index, _value in normalized_fields])
    fields = b"".join(int(value).to_bytes(4, "little") for _index, value in normalized_fields)
    return EncoderHandler.encode_packet(
        "SMSG_UPDATE_OBJECT",
        {
            "map_id": int(getattr(session, "map_id", 0) or 0) & 0xFFFF,
            "update_count": 1,
            "updates": [
                {
                    "update_type": 0,
                    "guid": int(guid),
                    "mask_blocks": len(mask) // 4,
                    "mask": mask,
                    "fields": fields,
                    "dynamic_mask_blocks": 0,
                }
            ],
        },
    )


def _test_inventory_slot_field_index(bag: int, slot: int) -> int | None:
    if int(bag) != 0:
        return None
    if 0 <= int(slot) < 23:
        return ((0x8 + 0x98) + 0x325) + (int(slot) * 2)
    if 23 <= int(slot) < 39:
        return ((0x8 + 0x98) + 0x353) + ((int(slot) - 23) * 2)
    return None


def _test_make_item_world_guid(item_low_guid: int) -> int:
    return (int(item_low_guid) & 0xFFFFFFFF) | (0x400 << 52)


def _import_chat_handlers():
    stub_modules = {
        "server.modules.handlers.world.bootstrap.replay": {
            "load_sniff_payload": lambda path: b"",
            "build_multi_u32_update_object_payload": lambda **fields: b"",
            "build_single_u32_update_object_payload": lambda **fields: b"",
            "send_raw_packet": lambda *args, **kwargs: ("SMSG_MESSAGECHAT", b""),
            "_build_gameobject_update_payload": lambda **kwargs: b"go-payload",
            "build_database_creature_responses": lambda session, loaded_guids=None: [],
            "make_update_object_response": lambda payload, **kwargs: ("SMSG_UPDATE_OBJECT", payload),
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
        "server.modules.handlers.world.login.packets": {
            "build_login_packet": lambda *args, **kwargs: b"",
            "_resolve_player_display_id": lambda race, gender, fallback=15475: int(fallback),
        },
        "server.modules.handlers.world.opcodes.entities": {
            "build_query_player_name_response": lambda session, guid: b"",
        },
        "server.modules.handlers.world.opcodes.spells": {
            "_DEFAULT_RUN_SPEED": 7.0,
            "_UNIT_FIELD_FLAGS": 0x60,
            "_UNIT_FIELD_MOUNTDISPLAYID": 0x6A,
            "_UNIT_FLAG_MOUNT": 0x08000000,
            "_restore_default_movement_speeds": lambda session: (
                setattr(session, "walk_speed", 2.5),
                setattr(session, "run_speed", 7.0),
                setattr(session, "swim_speed", 4.7),
                setattr(session, "fly_speed", 7.0),
            ),
            "_apply_mount_movement_speeds": lambda session: (
                setattr(session, "walk_speed", 2.5),
                setattr(session, "run_speed", 14.0),
                setattr(session, "swim_speed", 9.4),
                setattr(session, "fly_speed", 14.0),
            ),
            "set_custom_run_speed": lambda session, value: (
                setattr(session, "walk_speed", float(value) * (2.5 / 7.0)),
                setattr(session, "run_speed", float(value)),
                setattr(session, "swim_speed", float(value) * (4.7 / 7.0)),
                setattr(session, "fly_speed", float(value)),
            ),
            "handle_mount": lambda session, spell_id: [],
            "dismount": lambda session: [],
            "apply_fly_aura": lambda session: [("SMSG_AURA_UPDATE", b"fly-aura-on-1"), ("SMSG_AURA_UPDATE", b"fly-aura-on-2")],
            "remove_fly_aura": lambda session: [("SMSG_AURA_UPDATE", b"fly-aura-off-1"), ("SMSG_AURA_UPDATE", b"fly-aura-off-2")],
            "build_fly_state_responses": lambda session: [("SMSG_UPDATE_OBJECT", b"fly-state")],
            "is_mount_spell": lambda spell_id: int(spell_id) in {59535, 72286},
            "ensure_spell_known": lambda session, spell_id: (
                setattr(
                    session,
                    "known_spells",
                    sorted(
                        {int(value) for value in (getattr(session, "known_spells", []) or [])}
                        | {int(spell_id)}
                    ),
                ),
                setattr(
                    session,
                    "language",
                    7 if int(spell_id) == 668 else 1 if int(spell_id) == 669 else getattr(session, "language", 0),
                ),
                setattr(
                    session,
                    "known_languages_mask",
                    0xFFFFFFFF if int(spell_id) in {668, 669} else getattr(session, "known_languages_mask", 0),
                ),
            ),
            "build_known_spells_response": lambda session: ("SMSG_SEND_KNOWN_SPELLS", b"known-spells"),
        },
        "server.modules.handlers.world.opcodes.movement": {
            "build_move_set_speed_payload": (
                lambda session, opcode_name, value: f"{opcode_name}|{float(value):.2f}".encode()
            ),
            "build_move_set_run_speed_payload": lambda session: b"speed-packet",
            "_build_out_of_range_update_object_payload": lambda *, map_id, guid: b"",
            "resync_movement": lambda session: [("SMSG_PLAYER_MOVE", b"move-resync")],
            "_save_current_position_like_command": lambda *args, **kwargs: True,
            "_save_session_position": lambda *args, **kwargs: True,
        },
        "server.modules.handlers.world.inventory_sync": {
            "_inventory_slot_field_index": _test_inventory_slot_field_index,
            "_make_item_world_guid": _test_make_item_world_guid,
            "build_values_update": _test_build_values_update,
            "build_login_inventory_sync_responses": lambda session: [],
            "build_inventory_delta_responses": lambda session, result: [],
            "build_item_snapshot_responses": lambda session, item: [],
            "build_self_visible_item_update_responses": lambda session: [],
            "inventory_result_affects_equipment": lambda result: False,
            "trigger_inventory_activation": lambda session: [],
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
    module._build_gameobject_update_payload = lambda **kwargs: b"go-payload"
    module.make_update_object_response = lambda payload, **kwargs: ("SMSG_UPDATE_OBJECT", payload)
    sys.modules["server.modules.handlers.world.bootstrap.replay"] = module
    sys.modules.pop("server.modules.handlers.world.chat.codec", None)
    return importlib.import_module("server.modules.handlers.world.chat.codec")


chat_handlers = _import_chat_handlers()
chat_codec = _import_chat_codec()


def _install_worldserver_stub(monkeypatch, *, running=True, started_at=0.0, active_clients=None):
    class _Lock:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    module = types.ModuleType("server.worldserver")
    module.running = bool(running)
    module.STARTED_AT = float(started_at)
    module._ACTIVE_CLIENTS_LOCK = _Lock()
    module._ACTIVE_CLIENTS = dict(active_clients or {})
    module._shutdown_calls = []
    module._restart_calls = []

    def _shutdown_active_clients():
        module._shutdown_calls.append("shutdown")

    def request_restart():
        module._restart_calls.append("restart")
        module.running = False

    module._shutdown_active_clients = _shutdown_active_clients
    module.request_restart = request_restart
    monkeypatch.setitem(sys.modules, "server.worldserver", module)
    return module


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
    module.build_move_set_run_speed_payload = lambda session: b"run-speed-packet"
    module.build_move_set_flight_speed_payload = lambda session: b"flight-speed-packet"
    module.build_move_set_can_fly_payload = (
        lambda session, enabled: f"can-fly|{int(bool(enabled))}".encode()
    )
    module.resync_movement = lambda session: [("SMSG_PLAYER_MOVE", b"move-resync")]
    module.build_same_map_teleport_payload = lambda session: b"teleport-payload"
    module._save_current_position_like_command = lambda *args, **kwargs: True
    module._save_session_position = lambda *args, **kwargs: True
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
    opcodes_module = sys.modules.get("server.modules.handlers.world.opcodes")
    if opcodes_module is not None:
        monkeypatch.setattr(opcodes_module, "movement", module, raising=False)
    return module


def _read_who_xor_byte(payload: bytes, offset: int, raw: list[int], index: int) -> int:
    if raw[index]:
        raw[index] ^= payload[offset]
        return offset + 1
    return offset


def _decode_smsg_who_548(payload: bytes) -> list[dict[str, int | str]]:
    byte_pos = 0
    bit_pos = 0
    count, byte_pos, bit_pos = BitInterPreter.read_bits(payload, byte_pos, bit_pos, 6)

    account_ids: list[list[int]] = []
    player_guids: list[list[int]] = []
    guild_guids: list[list[int]] = []
    guild_name_lengths: list[int] = []
    player_name_lengths: list[int] = []
    extra_lengths: list[list[int]] = []

    for _ in range(count):
        account_id = [0] * 8
        player_guid = [0] * 8
        guild_guid = [0] * 8

        account_id[2], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        player_guid[2], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        account_id[7], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        guild_guid[5], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        guild_name_length, byte_pos, bit_pos = BitInterPreter.read_bits(payload, byte_pos, bit_pos, 7)
        account_id[1], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        account_id[5], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        guild_guid[7], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        player_guid[5], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        _, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        guild_guid[1], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        player_guid[6], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        guild_guid[2], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        player_guid[4], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        guild_guid[0], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        guild_guid[3], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        account_id[6], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        _, byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        player_guid[1], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        guild_guid[4], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        account_id[0], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)

        lengths: list[int] = []
        for _ in range(5):
            length, byte_pos, bit_pos = BitInterPreter.read_bits(payload, byte_pos, bit_pos, 7)
            lengths.append(length)

        player_guid[3], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        guild_guid[6], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        player_guid[0], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        account_id[4], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        account_id[3], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        player_guid[7], byte_pos, bit_pos = BitInterPreter.read_bit(payload, byte_pos, bit_pos)
        player_name_length, byte_pos, bit_pos = BitInterPreter.read_bits(payload, byte_pos, bit_pos, 6)

        account_ids.append(account_id)
        player_guids.append(player_guid)
        guild_guids.append(guild_guid)
        guild_name_lengths.append(guild_name_length)
        player_name_lengths.append(player_name_length)
        extra_lengths.append(lengths)

    if bit_pos:
        byte_pos += 1
        bit_pos = 0

    offset = byte_pos
    decoded: list[dict[str, int | str]] = []

    for index in range(count):
        player_guid = player_guids[index]
        guild_guid = guild_guids[index]
        account_id = account_ids[index]

        offset = _read_who_xor_byte(payload, offset, player_guid, 1)
        realm_id_a = struct.unpack_from("<i", payload, offset)[0]
        offset += 4
        offset = _read_who_xor_byte(payload, offset, player_guid, 7)
        offset = _read_who_xor_byte(payload, offset, player_guid, 4)
        name = payload[offset : offset + player_name_lengths[index]].decode()
        offset += player_name_lengths[index]
        offset = _read_who_xor_byte(payload, offset, guild_guid, 1)
        offset = _read_who_xor_byte(payload, offset, player_guid, 0)
        offset = _read_who_xor_byte(payload, offset, guild_guid, 2)
        offset = _read_who_xor_byte(payload, offset, guild_guid, 0)
        offset = _read_who_xor_byte(payload, offset, guild_guid, 4)
        offset = _read_who_xor_byte(payload, offset, player_guid, 3)
        offset = _read_who_xor_byte(payload, offset, guild_guid, 6)
        unk1 = struct.unpack_from("<i", payload, offset)[0]
        offset += 4
        guild_name = payload[offset : offset + guild_name_lengths[index]].decode()
        offset += guild_name_lengths[index]
        offset = _read_who_xor_byte(payload, offset, guild_guid, 3)
        offset = _read_who_xor_byte(payload, offset, account_id, 4)
        class_id = payload[offset]
        offset += 1
        offset = _read_who_xor_byte(payload, offset, account_id, 7)
        offset = _read_who_xor_byte(payload, offset, player_guid, 6)
        offset = _read_who_xor_byte(payload, offset, player_guid, 2)

        extra_strings: list[str] = []
        for length in extra_lengths[index]:
            extra_strings.append(payload[offset : offset + length].decode())
            offset += length

        offset = _read_who_xor_byte(payload, offset, account_id, 2)
        offset = _read_who_xor_byte(payload, offset, account_id, 3)
        race = payload[offset]
        offset += 1
        offset = _read_who_xor_byte(payload, offset, guild_guid, 7)
        offset = _read_who_xor_byte(payload, offset, account_id, 1)
        offset = _read_who_xor_byte(payload, offset, account_id, 5)
        offset = _read_who_xor_byte(payload, offset, account_id, 6)
        offset = _read_who_xor_byte(payload, offset, player_guid, 5)
        offset = _read_who_xor_byte(payload, offset, account_id, 0)
        gender = payload[offset]
        offset += 1
        offset = _read_who_xor_byte(payload, offset, guild_guid, 5)
        level = payload[offset]
        offset += 1
        zone_id = struct.unpack_from("<i", payload, offset)[0]
        offset += 4
        realm_id_b = struct.unpack_from("<i", payload, offset)[0]
        offset += 4

        decoded.append(
            {
                "name": name,
                "guild_name": guild_name,
                "level": level,
                "class_id": class_id,
                "race": race,
                "gender": gender,
                "zone_id": zone_id,
                "realm_id_a": realm_id_a,
                "realm_id_b": realm_id_b,
                "unk1": unk1,
                "extra_strings": extra_strings,
            }
        )

    assert offset == len(payload)
    return decoded


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


def test_chat_uses_current_language_for_outgoing_messages(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "encode_messagechat_payload",
        lambda **fields: f"{fields['language']}|{fields['sender_name']}|{fields['message']}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    alice.language = 7
    alice.current_language = 1
    alice.known_languages_mask = (1 << 1) | (1 << 7)
    ctx = SimpleNamespace(
        name="CMSG_MESSAGECHAT_SAY",
        payload=b"",
        decoded={"msg": "zug zug", "language": 7},
    )

    code, responses = chat_handlers.handle_messagechat_say(alice, ctx)

    assert code == 0
    assert responses is None
    assert alice.send_response_log == [[("SMSG_MESSAGECHAT", b"1|Alice|zug zug")]]
    assert bob.send_response_log == [[("SMSG_MESSAGECHAT", b"1|Alice|zug zug")]]


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


def test_stand_state_change_broadcasts_visible_update(monkeypatch):
    monkeypatch.setattr(chat_handlers, "log_cmsg", lambda ctx: ctx.decoded)
    monkeypatch.setattr(
        chat_handlers,
        "build_single_u32_update_object_payload",
        lambda **fields: f"update|{fields['guid']}|{fields['field_index']}|{fields['value']}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    ctx = SimpleNamespace(
        name="CMSG_STANDSTATECHANGE",
        payload=b"",
        decoded={"stand_state": 1},
    )

    code, responses = chat_handlers.handle_stand_state_change(alice, ctx)

    assert code == 0
    assert responses is None
    assert alice.player_stand_state == 1
    expected = [("SMSG_UPDATE_OBJECT", b"update|1001|76|1")]
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


def test_fly_command_is_removed(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = chat_handlers._handle_chat_command(alice, ".fly on")

    assert responses == [
        ("SMSG_MESSAGECHAT", b"system|Unknown command: .fly on"),
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


def test_handle_who_lists_all_online_players(monkeypatch):
    monkeypatch.setattr(chat_handlers, "resolve_zone_from_position", lambda map_id, x, y: 0)
    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    clara = _make_session(state, "Clara", 1003)

    alice.level = 12
    alice.zone = 1
    alice.class_id = 8
    alice.race = 2
    alice.gender = 1

    bob.level = 34
    bob.zone = 12
    bob.class_id = 1
    bob.race = 1
    bob.gender = 0

    clara.level = 60
    clara.zone = 85
    clara.class_id = 5
    clara.race = 10
    clara.gender = 1

    code, responses = chat_handlers.handle_who(alice, None)

    assert code == 0
    assert len(responses) == 1
    opcode, payload = responses[0]
    assert opcode == "SMSG_WHO"

    decoded = _decode_smsg_who_548(payload)

    assert decoded == [
        {
            "name": "Alice",
            "guild_name": "",
            "level": 12,
            "class_id": 8,
            "race": 2,
            "gender": 1,
            "zone_id": 1,
            "realm_id_a": 0,
            "realm_id_b": 0,
            "unk1": 0,
            "extra_strings": ["", "", "", "", ""],
        },
        {
            "name": "Bob",
            "guild_name": "",
            "level": 34,
            "class_id": 1,
            "race": 1,
            "gender": 0,
            "zone_id": 12,
            "realm_id_a": 0,
            "realm_id_b": 0,
            "unk1": 0,
            "extra_strings": ["", "", "", "", ""],
        },
        {
            "name": "Clara",
            "guild_name": "",
            "level": 60,
            "class_id": 5,
            "race": 10,
            "gender": 1,
            "zone_id": 85,
            "realm_id_a": 0,
            "realm_id_b": 0,
            "unk1": 0,
            "extra_strings": ["", "", "", "", ""],
        },
    ]


def test_online_who_players_uses_resolved_zone_over_stale_session_zone(monkeypatch):
    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.level = 20
    alice.class_id = 8
    alice.race = 2
    alice.gender = 1
    alice.map_id = 1
    alice.x = 123.0
    alice.y = 456.0
    alice.zone = 12
    alice.persist_zone = 12

    monkeypatch.setattr(chat_handlers, "resolve_zone_from_position", lambda map_id, x, y: 14)

    players = chat_handlers._online_who_players(alice)

    assert players == [
        {
            "name": "Alice",
            "guid": 1001,
            "level": 20,
            "class_id": 8,
            "race": 2,
            "gender": 1,
            "zone_id": 14,
            "realm_id": 0,
        }
    ]


def test_online_who_players_falls_back_to_character_row_for_missing_live_fields(monkeypatch):
    state = GlobalState()
    alice = _make_session(state, "", 1001)
    alice.level = 0
    alice.class_id = 0
    alice.race = 0
    alice.gender = 0
    alice.zone = 0
    alice.persist_zone = 0
    alice.map_id = 1
    alice.x = 0.0
    alice.y = 0.0
    alice._character_row = SimpleNamespace(
        name="Alice",
        level=42,
        class_=5,
        race=10,
        gender=1,
        zone=85,
        map=1,
        position_x=1.5,
        position_y=2.5,
    )

    monkeypatch.setattr(chat_handlers, "resolve_zone_from_position", lambda map_id, x, y: 0)

    players = chat_handlers._online_who_players(alice)

    assert players == [
        {
            "name": "Alice",
            "guid": 1001,
            "level": 42,
            "class_id": 5,
            "race": 10,
            "gender": 1,
            "zone_id": 85,
            "realm_id": 0,
        }
    ]


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


def test_invfix_command_is_removed(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = chat_handlers._handle_chat_command(alice, ".invfix")

    assert responses == [
        ("SMSG_MESSAGECHAT", b"system|Unknown command: .invfix"),
    ]


def test_mount_command_updates_visuals_and_speed_without_movement_resync(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_helper",
        lambda name: {"chat_mount_spell_id": 59535}[name],
    )
    monkeypatch.setattr(
        chat_handlers.spells_handlers,
        "handle_mount",
        lambda session, spell_id: (
            setattr(session, "mount_spell", int(spell_id)),
            setattr(session, "is_mounted", True),
            setattr(session, "run_speed", 14.0),
            [("SMSG_UPDATE_OBJECT", f"mount-spell|{int(spell_id)}".encode())],
        )[3],
    )
    _install_movement_stub(monkeypatch, resync_movement=lambda session: [("SMSG_PLAYER_MOVE", b"move-resync")])

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = chat_handlers._handle_chat_command(alice, ".mount")

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"mount-spell|59535"),
        ("SMSG_MESSAGECHAT", b"system|[Mount] mount requested"),
    ]
    assert alice.is_mounted is True
    assert alice.mount_spell == 59535
    assert alice.run_speed == 14.0


def test_dismount_command_clears_mount_display_without_movement_resync(monkeypatch):
    monkeypatch.setattr(
        chat_handlers,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
    )
    monkeypatch.setattr(
        chat_handlers.spells_handlers,
        "dismount",
        lambda session: (
            setattr(session, "mount_display_id", 0),
            setattr(session, "mount_spell", None),
            setattr(session, "is_mounted", False),
            setattr(session, "run_speed", 7.0),
            [("SMSG_UPDATE_OBJECT", b"dismount-spell")],
        )[4],
    )
    _install_movement_stub(monkeypatch, resync_movement=lambda session: [("SMSG_PLAYER_MOVE", b"move-resync")])

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.is_mounted = True
    alice.mount_spell = 123
    alice.unit_flags = 0x08000000
    alice.mount_display_id = 2404
    alice.run_speed = 14.0

    responses = chat_handlers._handle_chat_command(alice, ".dismount")

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"dismount-spell"),
        ("SMSG_MESSAGECHAT", b"system|[Mount] dismount requested"),
    ]
    assert alice.is_mounted is False
    assert alice.mount_spell is None
    assert alice.mount_display_id == 0
    assert alice.run_speed == 7.0


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


def test_learnspell_adds_runtime_spell_and_returns_known_spells_sync(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.known_spells = [133, 116]
    alice.language = 0

    responses = chat_handlers._handle_chat_command(alice, ".learnspell 668")

    assert alice.known_spells == [116, 133, 668]
    assert alice.language == 7
    assert responses == [
        ("SMSG_SEND_KNOWN_SPELLS", b"known-spells"),
        ("SMSG_MESSAGECHAT", b"system|Learned spell 668"),
    ]


def test_castspell_mount_uses_mount_handler_without_movement_resync(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands.spells_handlers,
        "handle_mount",
        lambda session, spell_id: captured.update({"spell_id": int(spell_id)}) or [("SMSG_UPDATE_OBJECT", b"mount")],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = chat_handlers._handle_chat_command(alice, ".castspell 59535")

    assert captured == {"spell_id": 59535}
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"mount"),
        ("SMSG_MESSAGECHAT", b"system|Casted spell 59535"),
    ]


def test_castspell_rejects_unknown_runtime_spell(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = chat_handlers._handle_chat_command(alice, ".castspell 12345")

    assert responses == [("SMSG_MESSAGECHAT", b"system|Spell 12345 has no runtime cast handler")]


def test_spawngo_loads_nearby_gameobjects_and_tracks_loaded_guids(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )
    monkeypatch.setattr(
        chat_handlers.DatabaseConnection,
        "get_gameobjects_near",
        lambda map_id, x, y, radius=120.0, limit=200: [
            {
                "guid": 4,
                "entry": 175354,
                "x": 1569.97,
                "y": -4397.41,
                "z": 16.05,
                "orientation": 0.0,
                "rotation0": 0.0,
                "rotation1": 0.0,
                "rotation2": 0.0,
                "rotation3": 1.0,
                "display_id": 3015,
                "flags": 40,
                "size": 1.0,
                "type": 15,
                "state": 1,
                "animprogress": 255,
                "faction": 0,
            }
        ],
        raising=False,
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.realm_id = 1
    alice.x = 1569.97
    alice.y = -4397.41
    alice.z = 16.05

    responses = chat_handlers.chat_commands.cmd_spawngo(alice, [])

    assert responses[0][0] == "SMSG_UPDATE_OBJECT"
    assert responses[1] == ("SMSG_MESSAGECHAT", b"system|[SpawnGO] loaded 1 gameobjects")
    assert len(alice.loaded_gameobjects) == 1


def test_addmoney_updates_player_coinage_fields(monkeypatch):
    captured = {}
    replay_module = sys.modules["server.modules.handlers.world.bootstrap.replay"]

    def _fake_build_multi_u32_update_object_payload(*, map_id, guid, field_updates):
        captured["map_id"] = int(map_id)
        captured["guid"] = int(guid)
        captured["field_updates"] = list(field_updates)
        return b"money-update"

    monkeypatch.setattr(
        replay_module,
        "build_multi_u32_update_object_payload",
        _fake_build_multi_u32_update_object_payload,
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands.DatabaseConnection,
        "update_character_money",
        lambda guid, realm_id, money: True,
        raising=False,
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.realm_id = 1
    alice.world_guid = 0x30001000003E9
    alice.money = 10

    responses = chat_handlers.chat_commands.cmd_addmoney(alice, ["1g2s3c"])

    assert alice.money == 10213
    assert responses[1] == ("SMSG_UPDATE_OBJECT", b"money-update")
    assert captured["map_id"] == 1
    assert captured["guid"] == alice.world_guid
    assert captured["field_updates"] == [
        (chat_handlers.chat_commands._PLAYER_FIELD_COINAGE, 10213),
        (chat_handlers.chat_commands._PLAYER_FIELD_COINAGE + 1, 0),
    ]


def test_world_go_status_reports_visibility_and_cache(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands.ConfigLoader,
        "load_config",
        staticmethod(lambda: {"worldserver": {"preload_gameobjects": True}}),
    )
    monkeypatch.setattr(chat_handlers.DatabaseConnection, "_cache_gameobjects_loaded", True, raising=False)
    monkeypatch.setattr(chat_handlers.DatabaseConnection, "_cache_gameobjects_by_map", {1: [{}, {}], 0: [{}]}, raising=False)

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.gameobjects_visible = True
    alice.loaded_gameobjects = {11, 12}

    responses = chat_handlers.chat_commands.cmd_world(alice, ["go", "status"])

    assert responses == [
        (
            "SMSG_MESSAGECHAT",
            b"system|[WorldGO] visible=1 loaded_now=2 cache_loaded=1 preload=1 cached_total=3 maps=2",
        )
    ]


def test_world_go_hide_clears_loaded_gameobjects(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )

    movement_module = sys.modules["server.modules.handlers.world.opcodes.movement"]
    monkeypatch.setattr(
        movement_module,
        "_build_out_of_range_update_object_payload",
        lambda *, map_id, guid: f"oor|map={map_id}|guid={guid}".encode(),
        raising=False,
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.gameobjects_visible = True
    alice.loaded_gameobjects = {21, 22}

    responses = chat_handlers.chat_commands.cmd_world(alice, ["go", "hide"])

    assert alice.gameobjects_visible is False
    assert alice.loaded_gameobjects == set()
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"oor|map=1|guid=21"),
        ("SMSG_UPDATE_OBJECT", b"oor|map=1|guid=22"),
        ("SMSG_MESSAGECHAT", b"system|[WorldGO] hidden"),
    ]


def test_world_go_show_spawns_nearby_gameobjects(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )

    replay_module = sys.modules["server.modules.handlers.world.bootstrap.replay"]
    monkeypatch.setattr(
        replay_module,
        "build_database_gameobject_responses",
        lambda session, loaded_guids=None: [("SMSG_UPDATE_OBJECT", b"go-1"), ("SMSG_UPDATE_OBJECT", b"go-2")],
        raising=False,
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.gameobjects_visible = False
    alice.last_gameobject_stream_at = 123.0

    responses = chat_handlers.chat_commands.cmd_world(alice, ["go", "show"])

    assert alice.gameobjects_visible is True
    assert alice.last_gameobject_stream_at == 0.0
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"go-1"),
        ("SMSG_UPDATE_OBJECT", b"go-2"),
        ("SMSG_MESSAGECHAT", b"system|[WorldGO] shown 2 updates"),
    ]


def test_world_npc_status_reports_visibility_and_cache(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands.ConfigLoader,
        "load_config",
        staticmethod(lambda: {"worldserver": {"preload_npcs": False}}),
    )
    monkeypatch.setattr(chat_handlers.DatabaseConnection, "_cache_creatures_loaded", False, raising=False)
    monkeypatch.setattr(chat_handlers.DatabaseConnection, "_cache_creatures_by_map", {}, raising=False)
    monkeypatch.setattr(chat_handlers.DatabaseConnection, "_cache_creature_templates", {}, raising=False)

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.npcs_visible = False
    alice.loaded_npcs = set()

    responses = chat_handlers.chat_commands.cmd_world(alice, ["npc", "status"])

    assert responses == [
        (
            "SMSG_MESSAGECHAT",
            b"system|[WorldNPC] visible=0 auto=0 loaded_now=0 cache_loaded=0 preload=0 cached_total=0 templates=0 maps=0",
        )
    ]


def test_world_npc_show_enables_visibility(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )
    replay_module = sys.modules["server.modules.handlers.world.bootstrap.replay"]
    monkeypatch.setattr(
        replay_module,
        "build_database_creature_responses",
        lambda session, loaded_guids=None: [("SMSG_UPDATE_OBJECT", b"npc-1"), ("SMSG_UPDATE_OBJECT", b"npc-2")],
        raising=False,
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.npcs_visible = False
    alice.last_npc_stream_at = 55.0

    responses = chat_handlers.chat_commands.cmd_world(alice, ["npc", "show"])

    assert alice.npcs_visible is True
    assert alice.last_npc_stream_at == 0.0
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"npc-1"),
        ("SMSG_UPDATE_OBJECT", b"npc-2"),
        ("SMSG_MESSAGECHAT", b"system|[WorldNPC] shown 2 updates"),
    ]


def test_world_npc_show_refreshes_stale_loaded_npcs(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )
    movement_module = sys.modules["server.modules.handlers.world.opcodes.movement"]
    monkeypatch.setattr(
        movement_module,
        "_build_out_of_range_update_object_payload",
        lambda *, map_id, guid: f"oor|map={map_id}|guid={guid}".encode(),
        raising=False,
    )
    replay_module = sys.modules["server.modules.handlers.world.bootstrap.replay"]

    def _fake_build_database_creature_responses(session, loaded_guids=None):
        assert loaded_guids == set()
        loaded_guids.add(303)
        return [("SMSG_UPDATE_OBJECT", b"npc-303")]

    monkeypatch.setattr(
        replay_module,
        "build_database_creature_responses",
        _fake_build_database_creature_responses,
        raising=False,
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.loaded_npcs = {101, 102}

    responses = chat_handlers.chat_commands.cmd_world(alice, ["npc", "show"])

    assert alice.loaded_npcs == {303}
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"oor|map=1|guid=101"),
        ("SMSG_UPDATE_OBJECT", b"oor|map=1|guid=102"),
        ("SMSG_UPDATE_OBJECT", b"npc-303"),
        ("SMSG_MESSAGECHAT", b"system|[WorldNPC] shown 1 updates"),
    ]


def test_world_npc_hide_disables_visibility_and_clears_loaded(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )
    movement_module = sys.modules["server.modules.handlers.world.opcodes.movement"]
    monkeypatch.setattr(
        movement_module,
        "_build_out_of_range_update_object_payload",
        lambda *, map_id, guid: f"oor|map={map_id}|guid={guid}".encode(),
        raising=False,
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.npcs_visible = True
    alice.loaded_npcs = {101, 102}

    responses = chat_handlers.chat_commands.cmd_world(alice, ["npc", "hide"])

    assert alice.npcs_visible is False
    assert alice.npc_auto_stream is False
    assert alice.loaded_npcs == set()
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"oor|map=1|guid=101"),
        ("SMSG_UPDATE_OBJECT", b"oor|map=1|guid=102"),
        ("SMSG_MESSAGECHAT", b"system|[WorldNPC] hidden"),
    ]


def test_world_npc_on_enables_auto_streaming(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )
    replay_module = sys.modules["server.modules.handlers.world.bootstrap.replay"]
    monkeypatch.setattr(
        replay_module,
        "build_database_creature_responses",
        lambda session, loaded_guids=None: [("SMSG_UPDATE_OBJECT", b"npc-1")],
        raising=False,
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.npcs_visible = False
    alice.npc_auto_stream = False
    alice.last_npc_stream_at = 55.0

    responses = chat_handlers.chat_commands.cmd_world(alice, ["npc", "on"])

    assert alice.npcs_visible is True
    assert alice.npc_auto_stream is True
    assert alice.last_npc_stream_at == 0.0
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"npc-1"),
        ("SMSG_MESSAGECHAT", b"system|[WorldNPC] auto on 1 updates"),
    ]


def test_world_npc_off_disables_auto_without_hiding(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.npcs_visible = True
    alice.npc_auto_stream = True
    alice.loaded_npcs = {101}

    responses = chat_handlers.chat_commands.cmd_world(alice, ["npc", "off"])

    assert alice.npc_auto_stream is False
    assert alice.npcs_visible is True
    assert alice.loaded_npcs == {101}
    assert responses == [("SMSG_MESSAGECHAT", b"system|[WorldNPC] auto off")]


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
    saved = {}
    monkeypatch.setattr(
        movement_module,
        "_movement_state",
        lambda session: SimpleNamespace(x=0.0, y=0.0, z=0.0, orientation=0.0, flags=1, flags2=2),
        raising=False,
    )
    monkeypatch.setattr(movement_module, "_capture_persist_position_from_session", lambda session: None, raising=False)
    monkeypatch.setattr(movement_module, "_mark_position_dirty", lambda session: None, raising=False)
    monkeypatch.setattr(
        movement_module,
        "_save_session_position",
        lambda session, **kwargs: saved.update({"kwargs": dict(kwargs)}) or True,
        raising=False,
    )
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
    assert saved["kwargs"] == {
        "reason": "near-teleport-start",
        "online": 1,
        "force": True,
    }
    assert len(responses) == 2
    assert responses[0][0] == "SMSG_MOVE_TELEPORT"
    assert responses[1] == ("SMSG_PLAYER_MOVE", b"move")


def test_apply_player_state_change_clears_loaded_world_objects_before_teleport(monkeypatch):
    movement_module = _install_movement_stub(
        monkeypatch,
        _build_out_of_range_update_object_payload=lambda *, map_id, guid: f"clear|{map_id}|{guid}".encode(),
    )
    monkeypatch.setattr(movement_module, "build_same_map_teleport_payload", lambda session: b"teleport", raising=False)
    monkeypatch.setattr(
        chat_handlers,
        "_build_movement_resync_responses",
        lambda session: [("SMSG_PLAYER_MOVE", b"move")],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.map_id = 1
    alice.loaded_gameobjects = {11}
    alice.loaded_npcs = {22}
    alice.last_gameobject_stream_at = 123.0
    alice.last_npc_stream_at = 456.0

    responses = chat_handlers.apply_player_state_change(
        alice,
        position=(10.0, 20.0, 30.0, 1.5),
        map_id=1,
    )

    assert ("SMSG_UPDATE_OBJECT", b"clear|1|11") in responses
    assert ("SMSG_UPDATE_OBJECT", b"clear|1|22") in responses
    assert alice.loaded_gameobjects == set()
    assert alice.loaded_npcs == set()
    assert alice.last_gameobject_stream_at == 0.0
    assert alice.last_npc_stream_at == 0.0


def test_apply_player_state_change_dismounts_before_teleport(monkeypatch):
    movement_module = _install_movement_stub(monkeypatch)
    spells_module = sys.modules["server.modules.handlers.world.opcodes.spells"]

    def fake_dismount(session):
        session.is_mounted = False
        session.mount_spell = None
        session.mount_display_id = 0
        session.run_speed = 7.0
        session.fly_speed = 7.0
        return [
            ("SMSG_DISMOUNT", b"off"),
            ("SMSG_MOVE_SET_RUN_SPEED", b"run-normal"),
        ]

    monkeypatch.setattr(spells_module, "dismount", fake_dismount, raising=False)
    monkeypatch.setattr(
        movement_module,
        "_movement_state",
        lambda session: SimpleNamespace(x=0.0, y=0.0, z=0.0, orientation=0.0, flags=1, flags2=2),
        raising=False,
    )
    monkeypatch.setattr(movement_module, "_capture_persist_position_from_session", lambda session: None, raising=False)
    monkeypatch.setattr(movement_module, "_mark_position_dirty", lambda session: None, raising=False)
    monkeypatch.setattr(movement_module, "_save_session_position", lambda *args, **kwargs: True, raising=False)
    monkeypatch.setattr(movement_module, "build_same_map_teleport_payload", lambda session: b"teleport", raising=False)
    monkeypatch.setattr(
        chat_handlers,
        "_build_field_update_responses",
        lambda session, field_updates: [],
    )
    monkeypatch.setattr(
        chat_handlers,
        "_build_movement_resync_responses",
        lambda session: [("SMSG_PLAYER_MOVE", b"move")],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.map_id = 1
    alice.is_mounted = True
    alice.mount_spell = 59535
    alice.mount_display_id = 2404
    alice.run_speed = 14.0

    responses = chat_handlers.apply_player_state_change(
        alice,
        position=(10.0, 20.0, 30.0, 1.5),
        map_id=1,
    )

    assert alice.is_mounted is False
    assert alice.mount_spell is None
    assert alice.mount_display_id == 0
    assert alice.run_speed == 7.0
    assert responses == [
        ("SMSG_DISMOUNT", b"off"),
        ("SMSG_MOVE_SET_RUN_SPEED", b"run-normal"),
        ("SMSG_MOVE_TELEPORT", b"teleport"),
        ("SMSG_PLAYER_MOVE", b"move"),
    ]


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


def test_forced_inventory_slot_resend_uses_dsl_player_values_update():
    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.inventory_state = SimpleNamespace(
        get=lambda bag, slot: SimpleNamespace(item_guid=2000) if (bag, slot) == (0, 23) else None
    )

    responses = chat_handlers._build_forced_inventory_slot_resend_responses(alice)

    assert len(responses) == 1
    opcode, payload = responses[0]
    assert opcode == "SMSG_UPDATE_OBJECT"
    field_index = chat_handlers._inventory_slot_field_index(0, 23)
    item_guid = chat_handlers._make_item_world_guid(2000)
    decoded = dsl_decode("SMSG_UPDATE_OBJECT", payload, silent=True)
    update = decoded["updates"][0]
    assert decoded["map_id"] == 1
    assert update["guid"] == 1001
    assert update["mask"]["set_bits"] == [field_index, field_index + 1]
    assert update["fields"]["u32"] == [
        int(item_guid & 0xFFFFFFFF),
        int((item_guid >> 32) & 0xFFFFFFFF),
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


def test_server_info_and_status_use_runtime_state(monkeypatch):
    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.login_state = "IN_WORLD"
    bob = _make_session(state, "Bob", 1002)
    bob.login_state = "IN_WORLD"
    chat_handlers.chat_commands._set_runtime_motd(alice, "Runtime MOTD")

    worldserver = _install_worldserver_stub(
        monkeypatch,
        running=True,
        started_at=time.time() - 65.0,
        active_clients={1: object(), 2: object()},
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "encode_skyfire_messagechat_system_payload",
        lambda message: message.encode(),
    )

    info_responses = chat_handlers.chat_commands.cmd_server(alice, ["info"])
    status_responses = chat_handlers.chat_commands.cmd_server(alice, ["status"])

    info_text = info_responses[0][1].decode()
    status_text = status_responses[0][1].decode()

    assert "PyPandariaEmu" in info_text
    assert "clients=2" in info_text
    assert "online=2" in info_text
    assert "motd=Runtime MOTD" in info_text
    assert "running" in status_text
    assert "clients=2" in status_text
    assert "in_world=2" in status_text
    assert worldserver._shutdown_calls == []


def test_server_motd_set_updates_runtime_sessions():
    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    bob = _make_session(state, "Bob", 1002)
    monkeypatch = __import__("pytest").MonkeyPatch()
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "encode_skyfire_messagechat_system_payload",
        lambda message: message.encode(),
    )

    responses = chat_handlers.chat_commands.cmd_server(alice, ["motd", "set", "Hello", "World"])
    message = responses[0][1].decode()

    assert message == "MOTD updated"
    assert alice.motd == "Hello World"
    assert bob.motd == "Hello World"
    monkeypatch.undo()


def test_server_motd_set_persists_to_default_yaml(tmp_path):
    config_module = importlib.import_module("shared.ConfigLoader")
    config_path = tmp_path / "default.yaml"
    config_path.write_text("worldserver:\n  motd: Original\n", encoding="utf-8")

    monkeypatch = __import__("pytest").MonkeyPatch()
    monkeypatch.setattr(chat_handlers.chat_commands, "_DEFAULT_CONFIG_MOTD_PATH", Path(config_path))
    monkeypatch.setattr(config_module, "_DEFAULT_CONFIG_PATH", Path(config_path))
    monkeypatch.setattr(config_module, "_CONFIG_DIR", tmp_path)
    config_module._config = None
    config_module._runtime_config = None

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    chat_handlers.chat_commands._set_runtime_motd(alice, "Persisted MOTD")

    saved = config_path.read_text(encoding="utf-8")
    assert 'motd: Persisted MOTD' in saved
    monkeypatch.undo()


def test_world_login_context_ignores_config_motd_when_database_missing(tmp_path):
    login_context = importlib.import_module("server.modules.handlers.world.login.context")
    session = WorldSession()
    session.account_data_times = {}
    session.account_data_mask = 0
    session.addons = []
    session.banned_addons = []
    session.known_spells = []
    session.action_buttons = []
    session.weather = {}

    ctx = login_context.WorldLoginContext.from_session(session)

    assert ctx.motd == "Welcome to PyPandaria"


def test_world_login_context_reloads_motd_for_each_login(monkeypatch):
    login_context = importlib.import_module("server.modules.handlers.world.login.context")
    values = iter(("Database MOTD 1", "Database MOTD 2"))
    monkeypatch.setattr(login_context, "_load_motd_from_database", lambda: next(values))

    session = WorldSession()
    session.account_data_times = {}
    session.account_data_mask = 0
    session.addons = []
    session.banned_addons = []
    session.known_spells = []
    session.action_buttons = []
    session.weather = {}
    session.motd = "Cached Runtime MOTD"

    first = login_context.WorldLoginContext.from_session(session)
    second = login_context.WorldLoginContext.from_session(session)

    assert first.motd == "Database MOTD 1"
    assert second.motd == "Database MOTD 2"


def test_world_login_context_preserves_mount_runtime_fields():
    login_context = importlib.import_module("server.modules.handlers.world.login.context")
    session = WorldSession()
    session.account_data_times = {}
    session.account_data_mask = 0
    session.addons = []
    session.banned_addons = []
    session.known_spells = []
    session.action_buttons = []
    session.weather = {}
    session.unit_flags = 0x08000020
    session.mount_display_id = 2404

    ctx = login_context.WorldLoginContext.from_session(session)

    assert ctx.unit_flags == 0x08000020
    assert ctx.mount_display_id == 2404


def test_server_restart_schedules_worldserver_shutdown(monkeypatch):
    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    worldserver = _install_worldserver_stub(monkeypatch, running=True, started_at=time.time())
    broadcasts = []
    logs = []

    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "broadcast_system_message",
        lambda message, scope="world": broadcasts.append((message, scope)),
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "encode_skyfire_messagechat_system_payload",
        lambda message: message.encode(),
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands.Logger,
        "info",
        lambda message, *args: logs.append(message % args if args else message),
    )

    responses = chat_handlers.chat_commands.cmd_server(alice, ["restart"])
    message = responses[0][1].decode()

    assert message == "Restart scheduled"
    assert broadcasts == [("[Server] restart requested", "world")]
    assert worldserver._restart_calls == ["restart"]
    assert worldserver.running is False
    assert worldserver._shutdown_calls == []


def test_server_msg_broadcasts_world_system_message(monkeypatch):
    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    broadcasts = []
    logs = []

    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "broadcast_system_message",
        lambda message, scope="world": broadcasts.append((message, scope)),
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "encode_skyfire_messagechat_system_payload",
        lambda message: message.encode(),
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands.Logger,
        "info",
        lambda message, *args: logs.append(message % args if args else message),
    )

    responses = chat_handlers.chat_commands.cmd_server(alice, ["msg", "Hello", "world"])

    assert responses == [("SMSG_MESSAGECHAT", b"[Server] sent: Hello world")]
    assert broadcasts == [("Hello world", "world")]
