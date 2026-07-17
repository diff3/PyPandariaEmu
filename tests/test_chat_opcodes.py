import importlib
import math
import struct
import sys
import time
import types
from types import SimpleNamespace
from pathlib import Path

import pytest

from DSL.modules.EncoderHandler import EncoderHandler
from DSL.modules.bitsHandler import BitInterPreter, BitWriter
from server.modules.interpretation.utils import dsl_decode
from server.modules.handlers.world.state.global_state import GlobalState
from server.modules.handlers.world.runtime import Player, get_player_runtime_store
from server.modules.protocol.packet_batch import PacketBatch
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
            "send_raw_packet": lambda *args, **kwargs: ("SMSG_MESSAGECHAT", b""),
        },
        "server.modules.handlers.world.bootstrap.creatures": {
            "build_database_creature_responses": lambda session, loaded_guids=None: [],
        },
        "server.modules.handlers.world.bootstrap.playerobjects": {
            "build_multi_u32_update_object_payload": lambda **fields: b"",
            "build_single_u32_update_object_payload": lambda **fields: b"",
            "make_update_object_response": lambda payload, **kwargs: ("SMSG_UPDATE_OBJECT", payload),
        },
        "server.modules.handlers.world.bootstrap.gameobjects": {
            "_build_gameobject_update_payload": lambda **kwargs: b"go-payload",
            "_build_gameobject_values_update_payload": lambda **kwargs: b"go-values",
            "build_database_gameobject_responses": (
                lambda session, loaded_guids=None: []
            ),
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


def test_gm_obsolete_top_level_commands_are_not_registered():
    obsolete = {
        "additem", "addmoney", "addhearthstone", "learnspell", "castspell",
        "taxi", "mapcheat", "time", "weather", "system", "roll", "mount",
        "dismount", "testbuff",
        "gocollision",
    }
    assert obsolete.isdisjoint(chat_handlers.chat_commands.COMMANDS)


def test_gm_hierarchical_roots_are_in_live_registry():
    registry = chat_handlers.chat_commands.PRIMARY_COMMANDS
    assert registry["add"].usage == ".add <item | money | hearthstone | bags> ..."
    assert registry["learn"].usage == ".learn spell <spell_id>"
    assert registry["spell"].usage == ".spell <cast | aura> ..."
    assert registry["cheat"].usage.startswith(".cheat <fly | taxi | map")
    assert "time | weather | message" in registry["server"].usage
    assert "world" not in registry


def test_every_live_command_declares_a_gm_level():
    commands = chat_handlers.chat_commands

    assert commands.GMLevel.PLAYER == 0
    assert commands.GMLevel.GAME_MASTER == 1
    assert commands.GMLevel.ADMINISTRATOR == 3
    assert all(
        isinstance(command.required_level, commands.GMLevel)
        for command in commands.PRIMARY_COMMANDS.values()
    )


def test_dispatcher_rejects_insufficient_gm_level_without_calling_handler(monkeypatch):
    commands = chat_handlers.chat_commands
    calls = []
    command = commands.Command(
        handler=lambda session, args: calls.append((session, args)) or [],
        usage=".restricted",
        required_level=commands.GMLevel.ADMINISTRATOR,
        allow_args=False,
    )
    monkeypatch.setitem(commands.COMMANDS, "restricted", command)
    monkeypatch.setattr(commands, "_session_gm_level", lambda _session: 1)

    responses = commands.handle_command(SimpleNamespace(), ".restricted")

    assert calls == []
    assert b"Insufficient permissions" in responses[0][1]
    assert b"Administrator" in responses[0][1]


def test_dispatcher_allows_matching_gm_level(monkeypatch):
    commands = chat_handlers.chat_commands
    calls = []
    command = commands.Command(
        handler=lambda session, args: calls.append((session, args)) or [("TEST", b"ok")],
        usage=".restricted",
        required_level=commands.GMLevel.GAME_MASTER,
    )
    monkeypatch.setitem(commands.COMMANDS, "restricted", command)
    monkeypatch.setattr(commands, "_session_gm_level", lambda _session: 1)
    session = SimpleNamespace()

    responses = commands.handle_command(session, ".restricted value")

    assert calls == [(session, ["value"])]
    assert responses == [("TEST", b"ok")]


def test_player_level_command_does_not_require_gm_access(monkeypatch):
    commands = chat_handlers.chat_commands
    monkeypatch.setattr(commands, "_session_gm_level", lambda _session: 0)

    responses = commands.handle_command(SimpleNamespace(), ".help gps")

    assert b"[Help] gps" in responses[0][1]


def test_help_without_argument_keeps_full_command_list():
    responses = chat_handlers.chat_commands.cmd_help(SimpleNamespace(), [])

    payloads = [payload for _opcode, payload in responses]
    assert b"[Help] commands:" in payloads[0]
    assert any(b".gps" in payload for payload in payloads)
    assert len(responses) == len(chat_handlers.chat_commands.PRIMARY_COMMANDS) + 1


def test_help_for_command_returns_usage_and_short_description():
    responses = chat_handlers.chat_commands.cmd_help(SimpleNamespace(), ["gps"])

    payloads = [payload for _opcode, payload in responses]
    assert b"[Help] gps" in payloads[0]
    assert any(b"Usage: .gps" in payload for payload in payloads)
    assert any(b"current map, position, and orientation" in payload for payload in payloads)


def test_help_for_unknown_command_is_harmless():
    responses = chat_handlers.chat_commands.cmd_help(SimpleNamespace(), ["does-not-exist"])

    assert len(responses) == 1
    assert b"unknown command: does-not-exist" in responses[0][1]


def test_gm_add_namespace_routes_without_legacy_lookup(monkeypatch):
    commands = chat_handlers.chat_commands
    calls = []
    monkeypatch.setattr(commands, "cmd_additem", lambda session, args: calls.append(("item", args)) or [])
    monkeypatch.setattr(commands, "cmd_addmoney", lambda session, args: calls.append(("money", args)) or [])
    monkeypatch.setattr(commands, "cmd_addhearthstone", lambda session, args: calls.append(("hearthstone", args)) or [])
    monkeypatch.setattr(commands, "cmd_addbags", lambda session, args: calls.append(("bags", args)) or [])

    commands.cmd_add(SimpleNamespace(), ["item", "6948", "2"])
    commands.cmd_add(SimpleNamespace(), ["money", "1g"])
    commands.cmd_add(SimpleNamespace(), ["hearthstone"])
    commands.cmd_add(SimpleNamespace(), ["bags"])

    assert calls == [("item", ["6948", "2"]), ("money", ["1g"]), ("hearthstone", []), ("bags", [])]


def test_gm_learn_and_spell_namespaces_route_subcommands(monkeypatch):
    commands = chat_handlers.chat_commands
    calls = []
    monkeypatch.setattr(commands, "cmd_learnspell", lambda session, args: calls.append(("learn", args)) or [])
    monkeypatch.setattr(commands, "cmd_castspell", lambda session, args: calls.append(("cast", args)) or [])
    monkeypatch.setattr(commands, "cmd_testbuff", lambda session, args: calls.append(("aura", args)) or [])

    commands.cmd_learn(SimpleNamespace(), ["spell", "123"])
    commands.cmd_spell(SimpleNamespace(), ["cast", "456"])
    commands.cmd_spell(SimpleNamespace(), ["aura", "789"])

    assert calls == [("learn", ["123"]), ("cast", ["456"]), ("aura", ["789"])]


def test_gm_cheat_namespace_routes_subcommands(monkeypatch):
    commands = chat_handlers.chat_commands
    calls = []
    monkeypatch.setattr(commands, "_cheat_fly", lambda session, args: calls.append(("fly", args)) or [])
    monkeypatch.setattr(commands, "cmd_taxi", lambda session, args: calls.append(("taxi", args)) or [])
    monkeypatch.setattr(commands, "cmd_mapcheat", lambda session, args: calls.append(("map", args)) or [])

    commands.cmd_cheat(SimpleNamespace(), ["fly", "on"])
    commands.cmd_cheat(SimpleNamespace(), ["taxi", "on"])
    commands.cmd_cheat(SimpleNamespace(), ["map", "on"])

    assert calls == [("fly", ["on"]), ("taxi", ["on"]), ("map", ["on"])]


def test_gm_server_namespace_routes_utility_subcommands(monkeypatch):
    commands = chat_handlers.chat_commands
    calls = []
    monkeypatch.setattr(commands, "cmd_time", lambda session, args: calls.append(("time", args)) or [])
    monkeypatch.setattr(commands, "cmd_weather", lambda session, args: calls.append(("weather", args)) or [])
    monkeypatch.setattr(commands, "server_msg", lambda session, args: calls.append(("message", args)) or [])

    commands.cmd_server(SimpleNamespace(), ["time", "noon"])
    commands.cmd_server(SimpleNamespace(), ["weather", "rain", "0.5"])
    commands.cmd_server(SimpleNamespace(), ["message", "hello", "world"])

    assert calls == [
        ("time", ["noon"]),
        ("weather", ["rain", "0.5"]),
        ("message", ["hello", "world"]),
    ]


def test_achievement_remove_uses_canonical_removal_service(monkeypatch):
    commands = chat_handlers.chat_commands
    achievement = SimpleNamespace(achievement_id=42, name="Explore Test")
    monkeypatch.setattr(commands, "find_achievement_by_name", lambda query, limit=8: [achievement])
    monkeypatch.setattr(
        commands,
        "remove_achievement_by_id",
        lambda session, achievement_id: (True, [("SMSG_ACHIEVEMENT_DELETED", b"removed")]),
    )

    responses = commands.cmd_achievement(SimpleNamespace(), ["remove", "Explore Test"])

    assert responses[0] == ("SMSG_ACHIEVEMENT_DELETED", b"removed")
    assert b"removed: 42 Explore Test" in responses[-1][1]
chat_codec = _import_chat_codec()


def test_testbuff_command_applies_default_visible_aura(monkeypatch):
    calls = []
    monkeypatch.setattr(chat_handlers.chat_commands.spells_handlers, "find_by_spell", lambda *_args: None, raising=False)
    monkeypatch.setattr(
        chat_handlers.chat_commands.spells_handlers,
        "apply_active_aura",
        lambda session, spell_id, **kwargs: calls.append((spell_id, kwargs)) or [("SMSG_AURA_UPDATE", b"buff")],
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands.spells_handlers,
        "replay_active_auras",
        lambda session: [("SMSG_AURA_UPDATE", b"full-buff-replay")],
        raising=False,
    )

    responses = chat_handlers.chat_commands.cmd_testbuff(SimpleNamespace(), [])

    assert calls == [(21562, {"positive": True, "cancelable": True, "duration_ms": -1, "applied_effects": ("test_buff",)})]
    assert responses[0] == ("SMSG_AURA_UPDATE", b"full-buff-replay")


def test_addhearthstone_uses_normal_inventory_delta(monkeypatch):
    result = SimpleNamespace(ok=True, message="item added")
    calls = []
    monkeypatch.setattr(chat_handlers.chat_commands, "add_item_to_character", lambda session, entry, count: calls.append((entry, count)) or result)
    monkeypatch.setattr(chat_handlers.chat_commands, "build_inventory_delta_responses", lambda session, value: [("SMSG_UPDATE_OBJECT", b"item")])

    responses = chat_handlers.chat_commands.cmd_addhearthstone(SimpleNamespace(inventory_dirty=False), [])

    assert calls == [(6948, 1)]
    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"item")
    assert chat_handlers.chat_commands.COMMANDS["add"].handler is chat_handlers.chat_commands.cmd_add
    assert "addheartstone" not in chat_handlers.chat_commands.COMMANDS


def test_addbags_adds_four_royal_satchels_through_inventory_delta(monkeypatch):
    result = SimpleNamespace(ok=True, message="items added")
    calls = []
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "add_item_to_character",
        lambda session, entry, count: calls.append((entry, count)) or result,
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "build_inventory_delta_responses",
        lambda session, value: [("SMSG_UPDATE_OBJECT", b"bags")],
    )

    responses = chat_handlers.chat_commands.cmd_addbags(SimpleNamespace(inventory_dirty=False), [])

    assert calls == [(82446, 4)]
    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"bags")


def test_additem_parses_count_and_comma_separated_entries():
    parse = chat_handlers.chat_commands._parse_add_item_requests

    assert parse(["82446", "count", "4,", "828,", "82342", "count", "2"]) == [
        (82446, 4),
        (828, 1),
        (82342, 2),
    ]
    assert parse(["82446", "4"]) is None
    assert parse(["82446", "ant", "4"]) is None


def test_additem_executes_each_validated_list_entry(monkeypatch):
    calls = []

    def add_item(_session, entry, count):
        calls.append((entry, count))
        return SimpleNamespace(ok=True, message=f"added {count}x item {entry}")

    monkeypatch.setattr(chat_handlers.chat_commands, "add_item_to_character", add_item)
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "build_inventory_delta_responses",
        lambda _session, result: [("SMSG_UPDATE_OBJECT", result.message.encode())],
    )

    responses = chat_handlers.chat_commands.cmd_additem(
        SimpleNamespace(inventory_dirty=False),
        ["82446", "count", "4,", "828,", "82342", "count", "2"],
    )

    assert calls == [(82446, 4), (828, 1), (82342, 2)]
    assert [opcode for opcode, _payload in responses].count("SMSG_UPDATE_OBJECT") == 3


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
    session.account_id = int(guid)
    session._cached_gm_level_account_id = int(guid)
    session._cached_gm_level = 3
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
    module.stream_world_objects_after_teleport = lambda session, *, context: []
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


def test_roll_command_is_removed(monkeypatch):
    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    responses = chat_handlers._handle_chat_command(alice, ".roll")

    assert responses[0][1].endswith(b"Unknown command: .roll")


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


def test_mapcheat_on_reveals_all_explored_zones_without_saving(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.map_cheat_enabled",
        lambda: True,
    )

    monkeypatch.setattr(
        chat_handlers,
        "build_explored_zones_update_response",
        lambda session: captured.update(
            {
                "explored_zones_raw": session.explored_zones_raw,
                "map_cheat_enabled": bool(getattr(session, "map_cheat_enabled", False)),
            }
        )
        or ("SMSG_UPDATE_OBJECT", b"map-update"),
    )
    monkeypatch.setattr(
        chat_handlers.DatabaseConnection,
        "save_character_explored_zones",
        staticmethod(lambda *_args: captured.update({"saved": True}) or True),
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
    alice.explored_zones_raw = "7 0 0"

    responses = chat_handlers._handle_chat_command(alice, ".cheat map on")

    assert captured["map_cheat_enabled"] is True
    assert captured["explored_zones_raw"] == "7 0 0"
    assert "saved" not in captured
    assert alice.map_cheat_enabled is True
    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"map-update")
    assert responses[-1] == (
        "SMSG_MESSAGECHAT",
        b"system|[MapCheat] all areas temporarily visible",
    )
    assert ("SMSG_TITLE_EARNED", struct.pack("<I", 47)) not in responses


def test_mapcheat_zero_restores_real_explored_zones_without_saving(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        "server.modules.handlers.world.feature_config.map_cheat_enabled",
        lambda: True,
    )

    monkeypatch.setattr(
        chat_handlers,
        "build_explored_zones_update_response",
        lambda session: captured.update(
            {
                "explored_zones_raw": session.explored_zones_raw,
                "map_cheat_enabled": bool(getattr(session, "map_cheat_enabled", False)),
            }
        )
        or ("SMSG_UPDATE_OBJECT", b"map-update"),
    )
    monkeypatch.setattr(
        chat_handlers.DatabaseConnection,
        "save_character_explored_zones",
        staticmethod(lambda *_args: captured.update({"saved": True}) or True),
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
    alice.explored_zones_raw = "7 0 0"
    alice.map_cheat_enabled = True

    responses = chat_handlers._handle_chat_command(alice, ".cheat map 0")

    assert captured["map_cheat_enabled"] is False
    assert captured["explored_zones_raw"] == "7 0 0"
    assert "saved" not in captured
    assert alice.map_cheat_enabled is False
    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"map-update"),
        ("SMSG_MESSAGECHAT", b"system|[MapCheat] real exploration restored"),
    ]


def test_mapcheat_effective_mask_does_not_overwrite_real_mask():
    runtime_module = importlib.import_module("server.modules.handlers.world.state.runtime")
    session = SimpleNamespace(
        explored_zones_raw="7 0 0",
        map_cheat_enabled=False,
    )

    real_values = runtime_module.effective_explored_zones_for_client(session)
    session.map_cheat_enabled = True
    cheat_values = runtime_module.effective_explored_zones_for_client(session)
    session.map_cheat_enabled = False
    restored_values = runtime_module.effective_explored_zones_for_client(session)

    assert real_values[:3] == [7, 0, 0]
    assert cheat_values == [0xFFFFFFFF] * 200
    assert restored_values[:3] == [7, 0, 0]
    assert session.explored_zones_raw == "7 0 0"


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


def test_mount_command_is_removed(monkeypatch):
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

    assert responses == [("SMSG_MESSAGECHAT", b"system|Unknown command: .mount")]
    assert alice.is_mounted is False
    assert alice.mount_spell is None


def test_dismount_command_is_removed(monkeypatch):
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

    assert responses == [("SMSG_MESSAGECHAT", b"system|Unknown command: .dismount")]
    assert alice.is_mounted is True
    assert alice.mount_spell == 123
    assert alice.mount_display_id == 2404
    assert alice.run_speed == 14.0


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

    responses = chat_handlers._handle_chat_command(alice, ".learn spell 668")

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

    responses = chat_handlers._handle_chat_command(alice, ".spell cast 59535")

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

    responses = chat_handlers._handle_chat_command(alice, ".spell cast 12345")

    assert [opcode for opcode, _payload in responses] == ["SMSG_CAST_FAILED", "SMSG_MESSAGECHAT"]
    assert responses[-1] == ("SMSG_MESSAGECHAT", b"system|Spell 12345 has no runtime cast handler")


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
    playerobjects_module = sys.modules["server.modules.handlers.world.bootstrap.playerobjects"]

    def _fake_build_multi_u32_update_object_payload(*, map_id, guid, field_updates):
        captured["map_id"] = int(map_id)
        captured["guid"] = int(guid)
        captured["field_updates"] = list(field_updates)
        return b"money-update"

    monkeypatch.setattr(
        playerobjects_module,
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
    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"money-update")
    assert responses[1][0] == "SMSG_MESSAGECHAT"
    assert captured["map_id"] == 1
    assert captured["guid"] == alice.char_guid
    assert captured["field_updates"] == [
        (chat_handlers.chat_commands._PLAYER_FIELD_COINAGE, 10213),
        (chat_handlers.chat_commands._PLAYER_FIELD_COINAGE + 1, 0),
    ]


def test_addmoney_supports_negative_copper_and_updates_coinage(monkeypatch):
    captured = []
    playerobjects_module = sys.modules["server.modules.handlers.world.bootstrap.playerobjects"]

    def _fake_build_multi_u32_update_object_payload(*, map_id, guid, field_updates):
        captured.append((int(map_id), int(guid), list(field_updates)))
        return b"money-update"

    monkeypatch.setattr(
        playerobjects_module,
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
    alice.money = 20000

    responses = chat_handlers.chat_commands.cmd_addmoney(alice, ["-100"])

    assert alice.money == 19900
    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"money-update")
    assert captured[-1][2] == [
        (chat_handlers.chat_commands._PLAYER_FIELD_COINAGE, 19900),
        (chat_handlers.chat_commands._PLAYER_FIELD_COINAGE + 1, 0),
    ]

    chat_handlers.chat_commands.cmd_addmoney(alice, ["-999999"])

    assert alice.money == 0
    assert captured[-1][2] == [
        (chat_handlers.chat_commands._PLAYER_FIELD_COINAGE, 0),
        (chat_handlers.chat_commands._PLAYER_FIELD_COINAGE + 1, 0),
    ]


def test_addmoney_parses_signed_denomination_values(monkeypatch):
    playerobjects_module = sys.modules["server.modules.handlers.world.bootstrap.playerobjects"]
    saved = []

    monkeypatch.setattr(
        playerobjects_module,
        "build_multi_u32_update_object_payload",
        lambda *, map_id, guid, field_updates: b"money-update",
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands.DatabaseConnection,
        "update_character_money",
        lambda guid, realm_id, money: saved.append(int(money)) or True,
        raising=False,
    )

    cases = (
        ("10g10s10c", 101010),
        ("-10g10s10c", -101010),
        ("5g", 50000),
        ("-5g", -50000),
        ("25s", 2500),
        ("-25s", -2500),
        ("50c", 50),
        ("-50c", -50),
        ("100000", 100000),
        ("-100000", -100000),
    )

    for raw, expected_delta in cases:
        state = GlobalState()
        alice = _make_session(state, "Alice", 1001)
        alice.realm_id = 1
        alice.money = 200000

        responses = chat_handlers.chat_commands.cmd_addmoney(alice, [raw])

        assert alice.money == 200000 + expected_delta
        assert saved[-1] == alice.money
        assert responses[0] == ("SMSG_UPDATE_OBJECT", b"money-update")


def test_addmoney_uses_self_object_guid_when_world_guid_exists(monkeypatch):
    captured = {}
    playerobjects_module = sys.modules["server.modules.handlers.world.bootstrap.playerobjects"]

    def _fake_build_multi_u32_update_object_payload(*, map_id, guid, field_updates):
        captured["guid"] = int(guid)
        captured["field_updates"] = list(field_updates)
        return b"money-update"

    monkeypatch.setattr(
        playerobjects_module,
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

    responses = chat_handlers.chat_commands.cmd_addmoney(alice, ["100"])

    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"money-update")
    assert captured["guid"] == alice.char_guid
    assert captured["field_updates"] == [
        (chat_handlers.chat_commands._PLAYER_FIELD_COINAGE, 110),
        (chat_handlers.chat_commands._PLAYER_FIELD_COINAGE + 1, 0),
    ]


def test_title_command_grants_and_activates_title_bit(monkeypatch):
    import server.modules.handlers.world.title_service as title_service

    captured = {}
    playerobjects_module = sys.modules["server.modules.handlers.world.bootstrap.playerobjects"]

    def _fake_build_multi_u32_update_object_payload(*, map_id, guid, field_updates):
        captured["map_id"] = int(map_id)
        captured["guid"] = int(guid)
        captured["field_updates"] = list(field_updates)
        return b"title-update"

    monkeypatch.setattr(
        playerobjects_module,
        "build_multi_u32_update_object_payload",
        _fake_build_multi_u32_update_object_payload,
        raising=False,
    )
    monkeypatch.setattr(
        title_service.DatabaseConnection,
        "update_character_title_state",
        lambda guid, realm_id, chosen_title, known_titles: True,
        raising=False,
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.realm_id = 1
    alice.world_guid = 0x30001000003E9
    alice.known_titles_raw = "0 0 0 0 0 0 0 0 0 0"
    alice.chosen_title = 0

    responses = chat_handlers.chat_commands.cmd_title(alice, ["explorer"])

    assert alice.chosen_title == 47
    assert title_service.title_is_known(alice.known_titles_raw, 47)
    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"title-update")
    assert ("SMSG_TITLE_EARNED", struct.pack("<I", 47)) in responses[1:]
    assert captured["map_id"] == 1
    assert captured["guid"] == alice.world_guid
    assert captured["field_updates"][0] == (title_service.PLAYER_FIELD_PLAYER_TITLE, 47)
    assert captured["field_updates"][1 + (47 // 32)] == (
        title_service.PLAYER_FIELD_KNOWN_TITLES + (47 // 32),
        1 << (47 % 32),
    )


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

    gameobjects_module = sys.modules["server.modules.handlers.world.bootstrap.gameobjects"]
    monkeypatch.setattr(
        gameobjects_module,
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




def test_worldporttest_requires_transport_debug_messages(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )
    monkeypatch.setattr(chat_handlers.chat_commands, "_session_gm_level", lambda session: 3)
    monkeypatch.setattr(chat_handlers.chat_commands, "transport_debug_messages_enabled", lambda: False)

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)

    responses = chat_handlers.chat_commands.cmd_worldporttest(alice, ["0", "1", "2", "3", "4"])

    assert responses == [
        ("SMSG_MESSAGECHAT", b"system|Worldport test requires Transport.DebugMessages=true.")
    ]


def test_worldporttest_selects_single_bootstrap_variant(monkeypatch):
    alice = SimpleNamespace(is_gm=True, char_guid=1, map_id=1)
    monkeypatch.setattr(chat_handlers.chat_commands, "transport_debug_messages_enabled", lambda: True)
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", message.encode())],
    )

    responses = chat_handlers.chat_commands.cmd_worldporttest(alice, ["variant", "B"])

    assert alice._worldport_bootstrap_variant == "B"
    assert responses == [("SMSG_MESSAGECHAT", b"[WorldportTest] bootstrap variant=B")]


def test_worldporttest_coordinate_uses_apply_map_transfer(monkeypatch):
    from server.modules.handlers.world.teleport import map_transfer

    calls = []
    monkeypatch.setattr(chat_handlers.chat_commands, "_session_gm_level", lambda session: 3)
    monkeypatch.setattr(chat_handlers.chat_commands, "transport_debug_messages_enabled", lambda: True)

    def fake_apply(session, destination, **kwargs):
        calls.append((session, destination, kwargs))
        return [("SMSG_TRANSFER_PENDING", b"pending"), ("SMSG_NEW_WORLD", b"new-world")]

    monkeypatch.setattr(map_transfer, "apply_map_transfer", fake_apply)

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.map_id = 1

    responses = chat_handlers.chat_commands.cmd_worldporttest(
        alice,
        ["0", "10.5", "20.5", "30.5", "1.25"],
    )

    assert responses == [("SMSG_TRANSFER_PENDING", b"pending"), ("SMSG_NEW_WORLD", b"new-world")]
    assert len(calls) == 1
    _session, destination, kwargs = calls[0]
    assert destination.map_id == 0
    assert destination.x == pytest.approx(10.5)
    assert destination.y == pytest.approx(20.5)
    assert destination.z == pytest.approx(30.5)
    assert destination.orientation == pytest.approx(1.25)
    assert kwargs["reason"] == "worldporttest"
    assert kwargs["keep_transport"] is False
    assert getattr(alice, "_worldporttest_active") is True


def test_worldporttest_transport_uses_runtime_transform_and_keep_transport(monkeypatch):
    from server.modules.handlers.world.teleport import map_transfer
    from server.modules.handlers.world import transport_runtime

    calls = []
    guid = 0x1FC0000000000007
    runtime_state = SimpleNamespace(
        guid=guid,
        entry=20808,
        map_id=0,
        x=100.0,
        y=200.0,
        z=10.0,
        orientation=math.pi / 2.0,
        path_progress_ms=12345,
    )
    attachment = SimpleNamespace(
        local_x=2.0,
        local_y=3.0,
        local_z=4.0,
        local_o=0.5,
    )
    monkeypatch.setattr(chat_handlers.chat_commands, "_session_gm_level", lambda session: 3)
    monkeypatch.setattr(chat_handlers.chat_commands, "transport_debug_messages_enabled", lambda: True)
    monkeypatch.setattr(
        transport_runtime,
        "current_runtime_transport_state_for_guid",
        lambda value: runtime_state if int(value) == guid else None,
    )
    monkeypatch.setattr(
        transport_runtime,
        "transport_passenger_attachment",
        lambda value, passenger: attachment if int(value) == guid and int(passenger) == 1001 else None,
    )

    def fake_apply(session, destination, **kwargs):
        calls.append((session, destination, kwargs))
        return [("SMSG_TRANSFER_PENDING", b"pending"), ("SMSG_NEW_WORLD", b"new-world")]

    monkeypatch.setattr(map_transfer, "apply_map_transfer", fake_apply)

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.map_id = 1
    alice.movement_state = SimpleNamespace()

    responses = chat_handlers.chat_commands.cmd_worldporttest(
        alice,
        ["transport", hex(guid)],
    )

    assert responses == [("SMSG_TRANSFER_PENDING", b"pending"), ("SMSG_NEW_WORLD", b"new-world")]
    assert len(calls) == 1
    _session, destination, kwargs = calls[0]
    assert destination.map_id == 0
    assert destination.x == pytest.approx(97.0)
    assert destination.y == pytest.approx(202.0)
    assert destination.z == pytest.approx(14.0)
    assert destination.orientation == pytest.approx((math.pi / 2.0) + 0.5)
    assert kwargs["reason"] == "worldporttest"
    assert kwargs["keep_transport"] is True
    assert kwargs["source_map_id"] == 1
    assert kwargs["transport_entry"] == 20808
    assert alice.movement_state.has_transport_data is True
    assert alice.movement_state.transport_guid == guid
    assert alice.movement_state.transport_x == pytest.approx(2.0)
    assert alice.movement_state.transport_y == pytest.approx(3.0)
    assert alice.movement_state.transport_z == pytest.approx(4.0)
    assert alice.movement_state.transport_orientation == pytest.approx(0.5)
    assert alice.movement_state.transport_time == 12345


def test_world_lift_on_keeps_already_streamed_elevator(monkeypatch):
    monkeypatch.setattr(
        chat_handlers.chat_commands,
        "_notification_response",
        lambda message: [("SMSG_MESSAGECHAT", f"system|{message}".encode())],
    )
    monkeypatch.setattr(
        chat_handlers.chat_commands.DatabaseConnection,
        "get_gameobjects_near",
        lambda map_id, x, y, radius, limit: [
            {
                "guid": 873,
                "entry": 11899,
                "map_id": int(map_id),
                "x": float(x) + 1.0,
                "y": float(y) + 2.0,
                "z": 321.0,
                "orientation": 0.0,
                "rotation0": 0.0,
                "rotation1": 0.0,
                "rotation2": 0.0,
                "rotation3": 1.0,
                "animprogress": 0,
                "state": 1,
                "type": 11,
                "display_id": 360,
                "name": "Mesa Elevator",
                "faction": 0,
                "flags": 40,
                "size": 1.0,
                "data0": 0,
                "data1": 0,
            },
        ],
        raising=False,
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.realm_id = 1
    alice.map_id = 1
    alice.x = -1300.0
    alice.y = 180.0
    from server.modules.game.guid import MoTransportGuid

    streamed_guid = int(MoTransportGuid.from_spawn_guid(873))
    alice.loaded_gameobjects = {streamed_guid}

    responses = chat_handlers.chat_commands.cmd_world(alice, ["lift", "on"])

    assert responses == [
        (
            "SMSG_MESSAGECHAT",
            b"system|[TransportElevator] legacy lift controls removed; use WorldTransportManager",
        )
    ]
    assert alice.loaded_gameobjects == {streamed_guid}
    assert not hasattr(alice, "loaded_lift_entries")


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
    creatures_module = sys.modules["server.modules.handlers.world.bootstrap.creatures"]
    monkeypatch.setattr(
        creatures_module,
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
    creatures_module = sys.modules["server.modules.handlers.world.bootstrap.creatures"]

    def _fake_build_database_creature_responses(session, loaded_guids=None):
        assert loaded_guids == set()
        loaded_guids.add(303)
        return [("SMSG_UPDATE_OBJECT", b"npc-303")]

    monkeypatch.setattr(
        creatures_module,
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
    creatures_module = sys.modules["server.modules.handlers.world.bootstrap.creatures"]
    monkeypatch.setattr(
        creatures_module,
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
    alice.instance_id = 77
    alice.zone = 12
    player_store = get_player_runtime_store()
    player_store.clear()
    player = player_store.add(Player.from_session(alice))
    from server.modules.handlers.world import transport_runtime

    alice.movement_state.has_transport_data = True
    alice.movement_state.transport_guid = 9
    alice.movement_state.transport_x = 90.0
    alice.movement_state.transport_y = 91.0
    alice.movement_state.transport_z = 92.0
    original_clear_transport = transport_runtime.clear_player_transport_state
    transport_reset_calls = []

    def capture_transport_reset(session, *, reason, opcode_name):
        transport_reset_calls.append(
            (
                session.x,
                session.y,
                session.z,
                session.movement_state.transport_guid,
            )
        )
        original_clear_transport(
            session,
            reason=reason,
            opcode_name=opcode_name,
        )

    monkeypatch.setattr(
        transport_runtime,
        "clear_player_transport_state",
        capture_transport_reset,
    )
    visibility_positions = []
    movement_module.stream_world_objects_after_teleport = (
        lambda session, *, context: visibility_positions.append(
            (
                context,
                player.map_id,
                player.instance_id,
                player.world_position,
                player.orientation,
            )
        )
        or []
    )

    responses = chat_handlers.apply_player_state_change(
        alice,
        position=(10.0, 20.0, 30.0, 1.5),
        map_id=1,
    )

    assert alice.x == 10.0
    assert alice.y == 20.0
    assert alice.z == 30.0
    assert alice.orientation == 1.5
    assert player.map_id == alice.map_id
    assert player.instance_id == alice.instance_id == 0
    assert player.world_position == (alice.x, alice.y, alice.z)
    assert player.orientation == alice.orientation
    assert transport_reset_calls == [(0.0, 0.0, 0.0, 9)]
    assert alice.movement_state.has_transport_data is False
    assert alice.movement_state.transport_guid == 0
    assert alice.movement_state.transport_x == 0.0
    assert alice.movement_state.transport_y == 0.0
    assert alice.movement_state.transport_z == 0.0
    assert visibility_positions == [
        ("near-teleport-start", 1, 0, (10.0, 20.0, 30.0), 1.5)
    ]
    assert alice.near_teleport_pending is True
    assert alice.teleport_pending is False
    assert saved == {}
    assert len(responses) == 2
    assert responses[0][0] == "SMSG_MOVE_TELEPORT"
    assert responses[1] == ("SMSG_PLAYER_MOVE", b"move")
    player_store.clear()


def test_same_map_teleport_streams_world_objects_in_transfer_batch(monkeypatch):
    calls: list[str] = []
    movement_module = _install_movement_stub(
        monkeypatch,
        stream_world_objects_after_teleport=lambda session, *, context: calls.append(context)
        or session.loaded_gameobjects.add(11)
        or session.loaded_transport_entries.update({11: {"entry": 20808}})
        or [("SMSG_UPDATE_OBJECT", b"transport-create")],
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
    alice.loaded_gameobjects = set()
    alice.loaded_transport_entries = {}

    responses = chat_handlers.apply_player_state_change(
        alice,
        position=(10.0, 20.0, 30.0, 1.5),
        map_id=1,
    )

    assert calls == ["near-teleport-start"]
    assert ("SMSG_UPDATE_OBJECT", b"transport-create") in responses
    assert 11 in alice.loaded_gameobjects
    assert 11 in alice.loaded_transport_entries
    assert alice.near_teleport_pending is True


def test_same_map_teleport_does_not_duplicate_initial_stream_at_ack(monkeypatch):
    transport_guid = 11
    create_count = 0

    def fake_stream(session, *, context):
        nonlocal create_count
        if transport_guid in getattr(session, "loaded_gameobjects", set()):
            return []
        session.loaded_gameobjects.add(transport_guid)
        session.loaded_transport_entries[transport_guid] = {"entry": 20808}
        create_count += 1
        return [("SMSG_UPDATE_OBJECT", f"transport-create:{context}".encode())]

    movement_module = _install_movement_stub(
        monkeypatch,
        stream_world_objects_after_teleport=fake_stream,
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
    alice.loaded_gameobjects = set()
    alice.loaded_transport_entries = {}

    responses = chat_handlers.apply_player_state_change(
        alice,
        position=(10.0, 20.0, 30.0, 1.5),
        map_id=1,
    )
    ack_responses = movement_module.stream_world_objects_after_teleport(
        alice,
        context="near-teleport-ack",
    )

    assert ("SMSG_UPDATE_OBJECT", b"transport-create:near-teleport-start") in responses
    assert ack_responses == []
    assert create_count == 1
    assert alice.loaded_gameobjects == {transport_guid}
    assert alice.loaded_transport_entries == {transport_guid: {"entry": 20808}}


def test_same_map_teleport_preserves_loaded_objects_until_ack_refresh(monkeypatch):
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
    alice.loaded_transport_entries = {11: {"entry": 20808}, 33: {"entry": 176495}}
    alice.loaded_npcs = {22}
    alice.last_gameobject_stream_at = 123.0
    alice.last_npc_stream_at = 456.0

    responses = chat_handlers.apply_player_state_change(
        alice,
        position=(10.0, 20.0, 30.0, 1.5),
        map_id=1,
    )

    assert not any(payload.startswith(b"clear|") for _opcode, payload in responses)
    assert alice.loaded_gameobjects == {11}
    assert alice.loaded_transport_entries == {
        11: {"entry": 20808},
        33: {"entry": 176495},
    }
    assert alice.loaded_npcs == {22}
    assert alice.last_gameobject_stream_at == 123.0
    assert alice.last_npc_stream_at == 456.0


def test_cross_map_teleport_clears_tracking_without_source_despawn_packets(monkeypatch):
    movement_module = _install_movement_stub(
        monkeypatch,
        _build_out_of_range_update_object_payload=lambda *, map_id, guid: (
            f"clear|{map_id}|{guid}".encode()
        ),
    )
    monkeypatch.setattr(
        movement_module,
        "_movement_state",
        lambda session: SimpleNamespace(flags=1, flags2=2),
        raising=False,
    )
    monkeypatch.setattr(
        movement_module,
        "_capture_persist_position_from_session",
        lambda session: None,
        raising=False,
    )
    monkeypatch.setattr(
        movement_module,
        "_mark_position_dirty",
        lambda session: None,
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers,
        "build_login_packet",
        lambda opcode_name, ctx: f"{opcode_name}|{getattr(ctx, 'map_id', 0)}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.map_id = 1
    alice.loaded_gameobjects = {11}
    alice.loaded_transport_entries = {11: {"entry": 20808}}
    alice.loaded_npcs = {22}

    responses = chat_handlers.apply_player_state_change(
        alice,
        position=(10.0, 20.0, 30.0, 1.5),
        map_id=0,
    )

    assert not any(payload.startswith(b"clear|") for _opcode, payload in responses)
    assert responses == [
        ("SMSG_TRANSFER_PENDING", b"SMSG_TRANSFER_PENDING|0"),
        ("SMSG_NEW_WORLD", b"SMSG_NEW_WORLD|0"),
    ]
    assert alice.loaded_gameobjects == set()
    assert alice.loaded_transport_entries == {}
    assert alice.loaded_npcs == set()


def test_ordinary_teleport_cancels_taxi_before_destination_commit(monkeypatch):
    movement_module = _install_movement_stub(monkeypatch)
    monkeypatch.setattr(
        movement_module,
        "build_same_map_teleport_payload",
        lambda session: b"teleport",
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers,
        "_build_movement_resync_responses",
        lambda session: [],
    )
    from server.modules.handlers.world import taxi_runtime

    cancellation_positions = []

    def cancel_taxi(session, reason, *, send_updates=True):
        cancellation_positions.append(
            (session.x, session.y, session.z, reason, send_updates)
        )
        session.taxi_state = None
        session._taxi_generation += 1

    monkeypatch.setattr(taxi_runtime, "cancel_taxi_flight", cancel_taxi)

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.map_id = 1
    alice.taxi_state = object()
    alice._taxi_generation = 7
    alice.pending_taxi_transfer = {"destination_map": 530}

    chat_handlers.apply_player_state_change(
        alice,
        position=(10.0, 20.0, 30.0, 1.5),
        map_id=1,
    )

    assert cancellation_positions == [
        (0.0, 0.0, 0.0, "ordinary_teleport", False),
    ]
    assert alice.taxi_state is None
    assert alice.pending_taxi_transfer is None
    assert alice._taxi_generation == 8
    assert (alice.x, alice.y, alice.z, alice.orientation) == (
        10.0,
        20.0,
        30.0,
        1.5,
    )


def test_manual_teleport_supersedes_incomplete_transport_worldport(monkeypatch):
    movement_module = _install_movement_stub(monkeypatch)
    monkeypatch.setattr(
        chat_handlers,
        "build_login_packet",
        lambda opcode_name, ctx: f"{opcode_name}|{getattr(ctx, 'map_id', 0)}".encode(),
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.map_id = 0
    alice.instance_id = 44
    alice.teleport_pending = True
    alice.worldport_ack_pending = True
    # Command handlers replace the destination label before entering the shared
    # teleport boundary; the active lifecycle flags still belong to transport.
    alice.teleport_destination = "manual:530:10:20:30:1.5"
    alice.loading_screen_visible = True
    alice.loading_screen_done = True
    alice.post_loading_sent = True
    alice.transport_transfer_pending = True
    alice.pending_transport_transfer = {
        "transfer_id": "old-transport-worldport",
        "source_guid": 77,
        "destination_guid": 88,
    }
    alice.post_bootstrap_transport_reattach_request = {
        "transfer_id": "old-transport-worldport",
        "destination_guid": 88,
    }
    player_store = get_player_runtime_store()
    player_store.clear()
    player = player_store.add(Player.from_session(alice))

    responses = chat_handlers.apply_player_state_change(
        alice,
        position=(10.0, 20.0, 30.0, 1.5),
        map_id=530,
    )

    assert responses == [
        ("SMSG_TRANSFER_PENDING", b"SMSG_TRANSFER_PENDING|530"),
        ("SMSG_NEW_WORLD", b"SMSG_NEW_WORLD|530"),
    ]
    assert isinstance(responses, PacketBatch)
    assert responses.transition_bound is True
    assert responses.transition_generation == 1
    assert responses.transition_owner == "ordinary_teleport"
    assert alice.world_transition_generation == 1
    assert alice.world_transition_owner == "ordinary_teleport"
    assert alice.world_transition_ignore_worldport_ack is True
    assert alice.world_transition_loading_generation == 1
    assert alice.teleport_destination == "manual:530:10:20:30:1.5"
    assert alice.teleport_pending is True
    assert alice.worldport_ack_pending is True
    assert alice.loading_screen_visible is True
    assert alice.loading_screen_done is False
    assert alice.post_loading_sent is False
    assert alice.transport_transfer_pending is False
    assert alice.pending_transport_transfer is None
    assert alice.post_bootstrap_transport_reattach_request is None
    assert (alice.map_id, alice.instance_id) == (530, 0)
    assert (alice.x, alice.y, alice.z, alice.orientation) == (10.0, 20.0, 30.0, 1.5)
    assert (player.map_id, player.instance_id) == (530, 0)
    assert player.world_position == (10.0, 20.0, 30.0)
    assert player.orientation == 1.5
    player_store.clear()


def test_same_map_teleport_defers_transport_tracking_reset_until_refresh(monkeypatch):
    transport_guid = 11
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

    gameobjects_module = sys.modules["server.modules.handlers.world.bootstrap.gameobjects"]

    def fake_visibility_rebuild(session, loaded_guids=None):
        loaded_guids = loaded_guids if isinstance(loaded_guids, set) else set()
        loaded_transports = getattr(session, "loaded_transport_entries", {})
        if transport_guid in loaded_guids or transport_guid in loaded_transports:
            return []
        loaded_guids.add(transport_guid)
        loaded_transports[transport_guid] = {"entry": 20808}
        session.loaded_transport_entries = loaded_transports
        return [("SMSG_UPDATE_OBJECT", b"transport-create")]

    monkeypatch.setattr(
        gameobjects_module,
        "build_database_gameobject_responses",
        fake_visibility_rebuild,
        raising=False,
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.map_id = 1
    alice.loaded_gameobjects = {transport_guid}
    alice.loaded_transport_entries = {transport_guid: {"entry": 20808}}
    alice.loaded_npcs = set()

    responses = chat_handlers.apply_player_state_change(
        alice,
        position=(10.0, 20.0, 30.0, 1.5),
        map_id=1,
    )

    assert not any(payload.startswith(b"clear|") for _opcode, payload in responses)
    assert transport_guid in alice.loaded_gameobjects
    assert transport_guid in alice.loaded_transport_entries

    from server.modules.handlers.world.world_refresh import get_world_refresh_service

    get_world_refresh_service()._reset_world_object_tracking(alice)

    rebuild_responses = gameobjects_module.build_database_gameobject_responses(
        alice,
        loaded_guids=alice.loaded_gameobjects,
    )

    assert rebuild_responses == [("SMSG_UPDATE_OBJECT", b"transport-create")]
    assert transport_guid in alice.loaded_gameobjects
    assert transport_guid in alice.loaded_transport_entries


def test_teleport_to_dock_recreates_metadata_only_transport_before_values(monkeypatch):
    transport_guid = 11
    packets = []

    def stream_transport(session, *, context):
        assert context == "near-teleport-ack"
        if transport_guid in session.loaded_gameobjects:
            packets.append("values")
            return [("SMSG_UPDATE_OBJECT", b"transport-values")]
        assert transport_guid not in session.loaded_transport_entries
        session.loaded_gameobjects.add(transport_guid)
        session.loaded_transport_entries[transport_guid] = {"entry": 20808}
        packets.append("create")
        return [("SMSG_UPDATE_OBJECT", b"transport-create")]

    movement_module = _install_movement_stub(
        monkeypatch,
        stream_world_objects_after_teleport=stream_transport,
    )
    monkeypatch.setattr(
        movement_module,
        "build_same_map_teleport_payload",
        lambda session: b"teleport",
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers,
        "_build_movement_resync_responses",
        lambda session: [],
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.map_id = 1
    alice.loaded_gameobjects = set()
    alice.loaded_transport_entries = {
        transport_guid: {"entry": 20808},
    }

    responses = chat_handlers.apply_player_state_change(
        alice,
        position=(10.0, 20.0, 30.0, 1.5),
        map_id=1,
    )

    assert packets == []
    assert ("SMSG_UPDATE_OBJECT", b"transport-create") not in responses
    assert transport_guid not in alice.loaded_gameobjects
    assert transport_guid in alice.loaded_transport_entries
    from server.modules.handlers.world.world_refresh import get_world_refresh_service

    get_world_refresh_service()._reset_world_object_tracking(alice)
    ack_updates = stream_transport(
        alice,
        context="near-teleport-ack",
    )
    assert packets == ["create"]
    assert ack_updates == [("SMSG_UPDATE_OBJECT", b"transport-create")]
    later_updates = stream_transport(alice, context="near-teleport-ack")
    assert packets == ["create", "values"]
    assert later_updates == [("SMSG_UPDATE_OBJECT", b"transport-values")]


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
    alice.instance_id = 55
    alice.zone = 12
    player_store = get_player_runtime_store()
    player_store.clear()
    player = player_store.add(Player.from_session(alice))

    responses = chat_handlers.apply_player_state_change(
        alice,
        position=(10.0, 20.0, 30.0, 1.5),
        map_id=0,
    )

    assert alice.map_id == 0
    assert player.map_id == alice.map_id
    assert player.instance_id == alice.instance_id == 0
    assert player.world_position == (alice.x, alice.y, alice.z)
    assert player.orientation == alice.orientation
    assert alice.teleport_pending is True
    assert alice.near_teleport_pending is False
    assert responses == [
        ("SMSG_TRANSFER_PENDING", b"SMSG_TRANSFER_PENDING|0"),
        ("SMSG_NEW_WORLD", b"SMSG_NEW_WORLD|0"),
    ]
    player_store.clear()


def test_gm_coordinate_teleport_updates_runtime_player(monkeypatch):
    movement_module = _install_movement_stub(monkeypatch)
    monkeypatch.setattr(
        movement_module,
        "_movement_state",
        lambda session: SimpleNamespace(
            x=0.0,
            y=0.0,
            z=0.0,
            orientation=0.0,
            flags=1,
            flags2=2,
        ),
        raising=False,
    )
    monkeypatch.setattr(
        chat_handlers,
        "build_login_packet",
        lambda opcode_name, ctx: opcode_name.encode(),
    )
    monkeypatch.setitem(
        chat_handlers.chat_commands.HELPERS,
        "apply_player_state_change",
        chat_handlers.apply_player_state_change,
    )

    state = GlobalState()
    alice = _make_session(state, "Alice", 1001)
    alice.map_id = 1
    alice.instance_id = 33
    player_store = get_player_runtime_store()
    player_store.clear()
    player = player_store.add(Player.from_session(alice))

    responses = chat_handlers.chat_commands._telxyz(
        alice,
        ["530", "10", "20", "30", "1.5"],
    )

    assert player.map_id == alice.map_id == 530
    assert player.instance_id == alice.instance_id == 0
    assert player.world_position == (alice.x, alice.y, alice.z)
    assert player.orientation == alice.orientation == 1.5
    assert [opcode for opcode, _payload in responses[:2]] == [
        "SMSG_TRANSFER_PENDING",
        "SMSG_NEW_WORLD",
    ]
    player_store.clear()


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

    responses = chat_handlers._build_fixplayer_responses(alice, mode=0)

    assert responses == [
        ("SMSG_UPDATE_OBJECT", b"values-1"),
        ("SMSG_UPDATE_OBJECT", b"values-2"),
        ("SMSG_MOVE_SET_WALK_SPEED", b"SMSG_MOVE_SET_WALK_SPEED|2.50"),
        ("SMSG_MOVE_SET_RUN_SPEED", b"SMSG_MOVE_SET_RUN_SPEED|7.00"),
        ("SMSG_MOVE_SET_SWIM_SPEED", b"SMSG_MOVE_SET_SWIM_SPEED|4.70"),
        ("SMSG_MOVE_SET_FLIGHT_SPEED", b"SMSG_MOVE_SET_FLIGHT_SPEED|7.00"),
        ("SMSG_PLAYER_MOVE", b"player-move"),
    ]


def test_fixplayer_teleport_returns_bootstrap_like_sequence(monkeypatch):
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

    assert chat_handlers._apply_fixplayer_destination(alice, "orgrimmar") == "orgrimmar"
    responses = chat_handlers._build_fixplayer_responses(alice, mode=2)

    assert responses == [
        ("SMSG_LOGIN_VERIFY_WORLD", b"SMSG_LOGIN_VERIFY_WORLD|pkt"),
        ("SMSG_LOGIN_SET_TIME_SPEED", b"SMSG_LOGIN_SET_TIME_SPEED|pkt"),
        ("SMSG_BIND_POINT_UPDATE", b"SMSG_BIND_POINT_UPDATE|pkt"),
        ("SMSG_MOVE_SET_ACTIVE_MOVER", b"SMSG_MOVE_SET_ACTIVE_MOVER|pkt"),
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

    assert chat_handlers._apply_fixplayer_destination(alice, "nowhere") is None


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
