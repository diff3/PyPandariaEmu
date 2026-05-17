from types import SimpleNamespace

from server.modules.handlers.world import achievement_service as achievements


def _reset_runtime(monkeypatch):
    monkeypatch.setattr(achievements, "_ACHIEVEMENTS", {}, raising=False)
    monkeypatch.setattr(achievements, "_CRITERIA_BY_ID", {}, raising=False)
    monkeypatch.setattr(achievements, "_CRITERIA_BY_ACHIEVEMENT", {}, raising=False)
    monkeypatch.setattr(achievements, "_EXPLORE_CRITERIA_BY_AREA", {}, raising=False)
    monkeypatch.setattr(achievements, "_LEVEL_CRITERIA", [], raising=False)
    monkeypatch.setattr(achievements, "_AREA_META_BY_ID", {}, raising=False)


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
        {1637: achievements.AreaMeta(area_id=1637, map_id=1, parent_area_id=0, explore_flag=707)},
        raising=False,
    )
    monkeypatch.setattr(achievements.DatabaseConnection, "save_character_exploration", lambda *_: True, raising=False)
    monkeypatch.setattr(achievements.DatabaseConnection, "save_character_explored_zones", lambda *_: True, raising=False)
    monkeypatch.setattr(achievements, "build_explored_zones_update_response", lambda _session: ("SMSG_UPDATE_OBJECT", b"map"), raising=False)

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
    assert responses[0] == ("SMSG_UPDATE_OBJECT", b"map")
