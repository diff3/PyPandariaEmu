import sys
import types
from types import SimpleNamespace


def _install_misc_test_stubs():
    login_packets = types.ModuleType("server.modules.handlers.world.login.packets")
    login_packets.handle_CMSG_REQUEST_HOTFIX = lambda *args, **kwargs: None
    login_packets.build_login_packet = lambda opcode_name, ctx: f"{opcode_name}|{getattr(ctx, 'weather_type', 0)}|{getattr(ctx, 'density', 0.0):.2f}".encode()
    sys.modules["server.modules.handlers.world.login.packets"] = login_packets

    account_data = types.ModuleType("server.modules.handlers.world.account_data")
    account_data.DB_ACCOUNT_DATA_137_TYPES = ()
    account_data.GLOBAL_ACCOUNT_DATA_STORAGE_TYPES = ()
    account_data.GLOBAL_ACCOUNT_DATA_TYPES = ()
    account_data.SEND_ACCOUNT_DATA_TO_CLIENT = False
    account_data.USE_DB_ACCOUNT_DATA_137 = False
    account_data.account_data_mask_for_types = lambda *args, **kwargs: 0
    account_data.account_data_text_for_type = lambda *args, **kwargs: ""
    account_data.account_data_times_list_for_types = lambda *args, **kwargs: []
    account_data.build_minimal_post_timesync_account_packets = lambda *args, **kwargs: []
    account_data.build_update_account_data_payload = lambda *args, **kwargs: b""
    account_data.decode_account_data_request_type = lambda *args, **kwargs: 0
    account_data.decode_account_data_update_payload = lambda *args, **kwargs: {}
    account_data.flush_account_data_types_to_db = lambda *args, **kwargs: None
    account_data.is_global_account_data_type = lambda *args, **kwargs: False
    account_data.load_character_account_data = lambda *args, **kwargs: None
    account_data.load_global_account_data = lambda *args, **kwargs: None
    account_data.normalize_account_data_text = lambda value: value
    account_data.persist_account_data_entry = lambda *args, **kwargs: None
    sys.modules["server.modules.handlers.world.account_data"] = account_data

    database_module = types.ModuleType("server.modules.database.DatabaseConnection")
    database_module.DatabaseConnection = type("DatabaseConnection", (), {})
    sys.modules["server.modules.database.DatabaseConnection"] = database_module

    inventory_module = types.ModuleType("server.modules.game.inventory")
    inventory_module.persist_session_inventory = lambda *args, **kwargs: None
    sys.modules["server.modules.game.inventory"] = inventory_module

    login_opcode_module = types.ModuleType("server.modules.handlers.world.opcodes.login")
    sys.modules["server.modules.handlers.world.opcodes.login"] = login_opcode_module

    movement_module = types.ModuleType("server.modules.handlers.world.opcodes.movement")
    movement_module._save_current_position_like_command = lambda *args, **kwargs: None
    sys.modules["server.modules.handlers.world.opcodes.movement"] = movement_module

    logging_module = types.ModuleType("server.modules.handlers.world.packet_logging")
    logging_module.log_cmsg = lambda *args, **kwargs: None
    sys.modules["server.modules.handlers.world.packet_logging"] = logging_module

    dispatcher_module = types.ModuleType("server.modules.handlers.world.dispatcher")
    dispatcher_module.register = lambda name: (lambda fn: fn)
    sys.modules["server.modules.handlers.world.dispatcher"] = dispatcher_module

    runtime_module = types.ModuleType("server.modules.handlers.world.state.runtime")
    runtime_module.advance_global_time = lambda delta=1: None
    runtime_module.broadcast_player_remove = lambda *args, **kwargs: None
    runtime_module.refresh_region_weather = lambda session: False
    sys.modules["server.modules.handlers.world.state.runtime"] = runtime_module


def test_time_sync_response_sends_weather_when_auto_weather_changes(monkeypatch):
    _install_misc_test_stubs()
    sys.modules.pop("server.modules.handlers.world.opcodes.misc", None)
    from server.modules.handlers.world.opcodes import misc

    session = SimpleNamespace(
        last_time_sync_seq=0,
        time_sync_ok=False,
        char_guid=10,
        map_id=1,
        zone=1637,
        skyfire_login_stage=0,
        weather={"weather_type": 0, "density": 0.0, "abrupt": 0},
    )

    monkeypatch.setattr(misc, "advance_global_time", lambda delta=1: None)
    monkeypatch.setattr(
        misc,
        "refresh_region_weather",
        lambda target: (
            setattr(target, "weather", {"weather_type": 5, "density": 0.75, "abrupt": 0}) or True
        ),
    )

    status, responses = misc.handle_time_sync_response(
        session,
        SimpleNamespace(decoded={"sequence_id": 7, "client_ticks": 12345}),
    )

    assert status == 0
    assert session.last_time_sync_seq == 7
    assert session.time_sync_ok is True
    assert responses == [("SMSG_WEATHER", b"SMSG_WEATHER|5|0.75")]
