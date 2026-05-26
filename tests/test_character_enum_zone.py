import importlib
import struct
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
    from server.modules.handlers.world.position.area_service import (
        resolve_area_from_position,
        resolve_zone_from_position,
    )

    assert resolve_zone_from_position(0, -8833.38, 628.628) == 1519
    assert resolve_zone_from_position(1, 1572.95, -4395.64) == 1637
    assert resolve_area_from_position(1, 1572.95, -4395.64) > 0


def test_area_assignment_resolver_finds_smaller_area_inside_parent_zone():
    from server.modules.handlers.world.position.area_service import (
        resolve_area_from_position,
        resolve_zone_from_position,
    )

    assert resolve_area_from_position(1, 1572.95, -4395.64) == 5170
    assert resolve_zone_from_position(1, 1572.95, -4395.64) == 1637


def test_world_map_area_resolver_finds_gm_island_zone():
    from server.modules.handlers.world.position.area_service import (
        resolve_area_from_position,
        resolve_zone_from_position,
    )

    assert resolve_zone_from_position(1, 16226.2, 16257.0) == 876
    assert resolve_area_from_position(1, 16226.2, 16257.0) == 876


def test_world_map_area_resolver_keeps_area_separate_from_parent_zone(monkeypatch):
    from server.modules.handlers.world.position import area_service

    monkeypatch.setattr(
        area_service,
        "_WORLD_MAP_AREAS",
        [
            (1, 10, 0.0, 100.0, 0.0, 100.0, 1),
            (1, 20, 25.0, 75.0, 25.0, 75.0, 1),
        ],
        raising=False,
    )
    monkeypatch.setattr(area_service, "_AREA_ASSIGNMENTS", {}, raising=False)
    monkeypatch.setattr(area_service, "_AREA_PARENTS", {20: 10}, raising=False)
    monkeypatch.setattr(area_service, "_MAP_AREA_CACHE", {}, raising=False)
    monkeypatch.setattr(area_service, "_resolve_map_file_area", lambda map_id, x, y: 0)

    assert area_service.resolve_area_from_position(1, 50.0, 50.0) == 20
    assert area_service.resolve_zone_from_position(1, 50.0, 50.0) == 10


def test_map_file_area_resolver_uses_16x16_area_grid(monkeypatch, tmp_path):
    from server.modules.handlers.world.position import area_service

    map_id = 0
    grid_x = 51
    grid_y = 34
    area_map = [10] * (16 * 16)
    area_map[15 * 16 + 4] = 42
    area_payload = struct.pack("<4sHH", b"AREA", 0, 0) + struct.pack("<256H", *area_map)
    header = struct.pack(
        "<4s4s4sIIIIIIII",
        b"MAPS",
        b"v1.8",
        b"test",
        44,
        len(area_payload),
        0,
        0,
        0,
        0,
        0,
        0,
    )
    (tmp_path / f"{map_id:04d}_{grid_x:02d}_{grid_y:02d}.map").write_bytes(header + area_payload)

    monkeypatch.setattr(area_service, "get_maps_root", lambda: tmp_path)
    monkeypatch.setattr(area_service, "_MAP_AREA_CACHE", {}, raising=False)

    assert area_service.resolve_area_from_position(map_id, -10665.58, -1219.04) == 42
