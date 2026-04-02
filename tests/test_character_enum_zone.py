import importlib
import sys
import types
from types import SimpleNamespace


def _import_login_packets():
    stub_modules = {
        "server.modules.handlers.world.addons": {
            "addon_public_key_bytes": lambda: b"",
        },
        "server.modules.database.DatabaseConnection": {
            "DatabaseConnection": type("DatabaseConnection", (), {}),
        },
    }

    for module_name, attrs in stub_modules.items():
        module = types.ModuleType(module_name)
        for attr_name, value in attrs.items():
            setattr(module, attr_name, value)
        sys.modules[module_name] = module

    sys.modules.pop("server.modules.handlers.world.login.packets", None)
    return importlib.import_module("server.modules.handlers.world.login.packets")


def test_enum_characters_uses_zone_resolved_from_position(monkeypatch):
    login_packets = _import_login_packets()

    row = SimpleNamespace(
        guid=7,
        name="Tester",
        at_login=0,
        playerBytes=0,
        playerBytes2=0,
        equipmentCache="",
        slot=0,
        position_x=123.4,
        position_y=567.8,
        position_z=90.1,
        class_=1,
        map=1,
        race=1,
        level=10,
        gender=0,
        playerFlags=0,
        zone=12,
    )

    captured = {}

    monkeypatch.setattr(
        login_packets.DatabaseConnection,
        "get_characters_for_account",
        lambda account_id, realm_id: [row],
        raising=False,
    )
    monkeypatch.setattr(
        login_packets,
        "_decode_player_bytes",
        lambda *args, **kwargs: {
            "hair_style": 0,
            "face": 0,
            "skin": 0,
            "hair_color": 0,
            "facial_hair": 0,
        },
    )
    monkeypatch.setattr(
        login_packets,
        "_parse_equipment_cache",
        lambda *args, **kwargs: [{"enchant": 0, "int_type": 0, "display_id": 0} for _ in range(23)],
    )
    monkeypatch.setattr(login_packets, "resolve_zone_from_position", lambda map_id, x, y: 876)
    monkeypatch.setattr(
        login_packets.EncoderHandler,
        "encode_packet",
        lambda name, fields: captured.setdefault("fields", fields) or b"payload",
    )

    login_packets.build_ENUM_CHARACTERS_RESULT(account_id=1, realm_id=1)

    assert captured["fields"]["chars"][0]["zone"] == 876


def test_world_map_area_resolver_finds_orgrimmar_zone():
    from server.modules.handlers.world.position.area_service import resolve_zone_from_position

    assert resolve_zone_from_position(1, 1572.95, -4395.64) == 1637
