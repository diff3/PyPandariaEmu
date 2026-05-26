from types import SimpleNamespace

from server.modules.handlers.world import achievement_service as achievements


def _reset_runtime(monkeypatch):
    monkeypatch.setattr(achievements, "_ACHIEVEMENTS", {}, raising=False)
    monkeypatch.setattr(achievements, "_CRITERIA_BY_ID", {}, raising=False)
    monkeypatch.setattr(achievements, "_CRITERIA_BY_ACHIEVEMENT", {}, raising=False)
    monkeypatch.setattr(achievements, "_EXPLORE_CRITERIA_BY_AREA", {}, raising=False)
    monkeypatch.setattr(achievements, "_COMPLETE_ACHIEVEMENT_CRITERIA_BY_ACHIEVEMENT", {}, raising=False)
    monkeypatch.setattr(achievements, "_LEVEL_CRITERIA", [], raising=False)
    monkeypatch.setattr(achievements, "_AREA_META_BY_ID", {}, raising=False)
    monkeypatch.setattr(achievements, "_WORLD_MAP_OVERLAY_AREAS", {}, raising=False)


def test_login_sync_completes_reached_level_achievements(monkeypatch):
    _reset_runtime(monkeypatch)
    level_10 = achievements.CriteriaMeta(
        criteria_id=34,
        achievement_id=6,
        criteria_type=achievements.ACHIEVEMENT_CRITERIA_TYPE_REACH_LEVEL,
        asset=0,
        quantity=10,
        description="each level 10",
    )
    monkeypatch.setattr(achievements, "_LEVEL_CRITERIA", [level_10], raising=False)
    monkeypatch.setattr(achievements, "_CRITERIA_BY_ACHIEVEMENT", {6: [level_10]}, raising=False)
    monkeypatch.setattr(achievements, "_load_achievements", lambda: {}, raising=False)
    monkeypatch.setattr(achievements, "_load_criteria", lambda: {}, raising=False)
    monkeypatch.setattr(achievements, "_load_area_meta", lambda: {}, raising=False)
    monkeypatch.setattr(achievements.DatabaseConnection, "load_character_exploration", lambda *_: {}, raising=False)
    monkeypatch.setattr(achievements.DatabaseConnection, "load_character_criteria_progress", lambda *_: {}, raising=False)
    monkeypatch.setattr(achievements.DatabaseConnection, "load_character_achievement_progress", lambda *_: {}, raising=False)
    monkeypatch.setattr(achievements.DatabaseConnection, "save_character_criteria_progress", lambda *_: True, raising=False)
    monkeypatch.setattr(achievements.DatabaseConnection, "save_character_achievement_progress", lambda *_: True, raising=False)

    session = SimpleNamespace(
        char_guid=1,
        realm_id=1,
        world_guid=0x0003000100000001,
        player_name="Tester",
        level=90,
        zone=0,
    )

    responses = achievements.initialize_session_achievements(session)

    assert 34 in session.achievement_criteria_progress
    assert 6 in session.achievement_completed
    assert [name for name, _payload in responses] == [
        "SMSG_CRITERIA_UPDATE",
        "SMSG_ACHIEVEMENT_EARNED",
    ]


def test_discover_area_updates_explored_zone_bitmask(monkeypatch):
    _reset_runtime(monkeypatch)
    monkeypatch.setattr(
        achievements,
        "_AREA_META_BY_ID",
        {1637: achievements.AreaMeta(area_id=1637, map_id=1, parent_area_id=0, explore_flag=707, name="Orgrimmar")},
        raising=False,
    )
    monkeypatch.setattr(achievements.DatabaseConnection, "save_character_exploration", lambda *_: True, raising=False)
    monkeypatch.setattr(achievements.DatabaseConnection, "save_character_explored_zones", lambda *_: True, raising=False)
    monkeypatch.setattr(achievements, "build_explored_zones_update_response", lambda _session: ("SMSG_UPDATE_OBJECT", b"map"), raising=False)
    monkeypatch.setattr(
        achievements,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
        raising=False,
    )

    session = SimpleNamespace(
        char_guid=1,
        realm_id=1,
        world_guid=0x0003000100000001,
        player_name="Tester",
        zone=1637,
        explored_zones_raw="",
    )

    responses = achievements.discover_area(session, 1637)
    values = [int(value) for value in session.explored_zones_raw.split()]

    assert session.discovered_areas[1637] > 0
    assert values[707 // 32] & (1 << (707 % 32))
    assert responses[:2] == [
        ("SMSG_UPDATE_OBJECT", b"map"),
        ("SMSG_MESSAGECHAT", b"system|You have discovered Orgrimmar"),
    ]


def test_discover_area_updates_real_mask_while_mapcheat_active(monkeypatch):
    _reset_runtime(monkeypatch)
    monkeypatch.setattr(
        achievements,
        "_AREA_META_BY_ID",
        {1637: achievements.AreaMeta(area_id=1637, map_id=1, parent_area_id=0, explore_flag=707, name="Orgrimmar")},
        raising=False,
    )
    saved = {}
    monkeypatch.setattr(achievements.DatabaseConnection, "save_character_exploration", lambda *_: True, raising=False)
    monkeypatch.setattr(
        achievements.DatabaseConnection,
        "save_character_explored_zones",
        lambda _guid, _realm, raw: saved.update({"raw": raw}) or True,
        raising=False,
    )
    monkeypatch.setattr(achievements, "build_explored_zones_update_response", lambda _session: ("SMSG_UPDATE_OBJECT", b"map"), raising=False)
    monkeypatch.setattr(
        achievements,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
        raising=False,
    )

    session = SimpleNamespace(
        char_guid=1,
        realm_id=1,
        world_guid=0x0003000100000001,
        player_name="Tester",
        zone=1637,
        explored_zones_raw="",
        map_cheat_enabled=True,
    )

    responses = achievements.discover_area(session, 1637)
    values = [int(value) for value in session.explored_zones_raw.split()]

    assert session.discovered_areas[1637] > 0
    assert values[707 // 32] & (1 << (707 % 32))
    assert saved["raw"] == session.explored_zones_raw
    assert responses[:2] == [
        ("SMSG_UPDATE_OBJECT", b"map"),
        ("SMSG_MESSAGECHAT", b"system|You have discovered Orgrimmar"),
    ]


def test_discovery_message_without_area_name_is_generic(monkeypatch):
    monkeypatch.setattr(
        achievements,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
        raising=False,
    )

    response = achievements.build_exploration_discovered_message(
        achievements.AreaMeta(area_id=3487, map_id=530, parent_area_id=0, explore_flag=1111)
    )

    assert response == ("SMSG_MESSAGECHAT", b"system|Exploration updated")


def test_explore_criteria_map_world_overlay_areas(monkeypatch):
    _reset_runtime(monkeypatch)
    monkeypatch.setattr(achievements, "_CRITERIA_BY_ID", None, raising=False)
    monkeypatch.setattr(achievements, "_CRITERIA_BY_ACHIEVEMENT", None, raising=False)
    monkeypatch.setattr(achievements, "_EXPLORE_CRITERIA_BY_AREA", None, raising=False)
    monkeypatch.setattr(achievements, "_WORLD_MAP_OVERLAY_AREAS", {777: (100, 101)}, raising=False)
    monkeypatch.setattr(
        achievements,
        "read_dbc",
        lambda _path, _fmt: [[1, 2, achievements.ACHIEVEMENT_CRITERIA_TYPE_EXPLORE_AREA, 777, 1, 0, 0, 0, 0, 0, ""]],
        raising=False,
    )

    criteria_by_area = achievements._explore_criteria_by_area()

    assert criteria_by_area[100][0].criteria_id == 1
    assert criteria_by_area[101][0].criteria_id == 1


def test_earned_exploration_achievement_updates_continent_criteria(monkeypatch):
    _reset_runtime(monkeypatch)
    duskwood_area = achievements.CriteriaMeta(
        criteria_id=1161,
        achievement_id=778,
        criteria_type=achievements.ACHIEVEMENT_CRITERIA_TYPE_EXPLORE_AREA,
        asset=1097,
        quantity=1,
        description="",
    )
    eastern_kingdoms_duskwood = achievements.CriteriaMeta(
        criteria_id=1284,
        achievement_id=42,
        criteria_type=achievements.ACHIEVEMENT_CRITERIA_TYPE_COMPLETE_ACHIEVEMENT,
        asset=778,
        quantity=1,
        description="",
    )
    monkeypatch.setattr(achievements, "_AREA_META_BY_ID", {
        1097: achievements.AreaMeta(area_id=1097, map_id=0, parent_area_id=10, explore_flag=351, name="The Hushed Bank"),
    }, raising=False)
    monkeypatch.setattr(achievements, "_EXPLORE_CRITERIA_BY_AREA", {1097: [duskwood_area]}, raising=False)
    monkeypatch.setattr(achievements, "_CRITERIA_BY_ACHIEVEMENT", {
        778: [duskwood_area],
        42: [eastern_kingdoms_duskwood],
    }, raising=False)
    monkeypatch.setattr(
        achievements,
        "_COMPLETE_ACHIEVEMENT_CRITERIA_BY_ACHIEVEMENT",
        {778: [eastern_kingdoms_duskwood]},
        raising=False,
    )
    monkeypatch.setattr(achievements.DatabaseConnection, "save_character_exploration", lambda *_: True, raising=False)
    monkeypatch.setattr(achievements.DatabaseConnection, "save_character_explored_zones", lambda *_: True, raising=False)
    monkeypatch.setattr(achievements.DatabaseConnection, "save_character_criteria_progress", lambda *_: True, raising=False)
    monkeypatch.setattr(achievements.DatabaseConnection, "save_character_achievement_progress", lambda *_: True, raising=False)
    monkeypatch.setattr(achievements, "build_explored_zones_update_response", lambda _session: None, raising=False)
    monkeypatch.setattr(
        achievements,
        "encode_skyfire_messagechat_system_payload",
        lambda message: f"system|{message}".encode(),
        raising=False,
    )

    session = SimpleNamespace(
        char_guid=1,
        realm_id=1,
        world_guid=0x0003000100000001,
        player_name="Tester",
        zone=10,
        explored_zones_raw="",
    )

    responses = achievements.discover_area(session, 1097)

    assert 778 in session.achievement_completed
    assert 1284 in session.achievement_criteria_progress
    assert [name for name, _payload in responses].count("SMSG_CRITERIA_UPDATE") == 2
    assert [name for name, _payload in responses].count("SMSG_ACHIEVEMENT_EARNED") == 1


def test_achievement_earned_payload_includes_realm_ids_for_mop_layout():
    session = SimpleNamespace(world_guid=0, char_guid=0, realm_id=7)

    payload = achievements.build_achievement_earned_payload(
        session,
        achievement_id=772,
        completion_time=0,
    )

    assert len(payload) == 19
    assert int.from_bytes(payload[11:15], "little") == 7
    assert int.from_bytes(payload[15:19], "little") == 7
