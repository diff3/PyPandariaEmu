#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import sys
import types

from server.modules.handlers.world.state.weather_zone_registry import WeatherZoneEntry

if "pymysql" not in sys.modules:
    pymysql_stub = types.ModuleType("pymysql")
    pymysql_stub.connect = lambda *args, **kwargs: None
    pymysql_stub.cursors = types.SimpleNamespace(DictCursor=object)
    sys.modules["pymysql"] = pymysql_stub

from admin_panel.modules import world_state


def _weather_rows(monkeypatch, rows):
    monkeypatch.setattr(
        world_state,
        "canonical_weather_zone_registry",
        lambda _explicit: {
            148: WeatherZoneEntry(
                148,
                0,
                1,
                "Darkshore",
                "darkshore",
                ("Auberdine",),
                (465,),
            ),
            12: WeatherZoneEntry(
                12,
                0,
                0,
                "Elwynn Forest",
                "elwynn forest",
                ("Goldshire",),
                (87,),
            ),
            67: WeatherZoneEntry(
                67,
                0,
                571,
                "The Storm Peaks",
                "the storm peaks",
                (),
                (),
            ),
        },
    )
    monkeypatch.setattr(
        world_state,
        "map_name_lookup",
        lambda _map_ids: {
            0: "Eastern Kingdoms",
            1: "Kalimdor",
            571: "Northrend",
        },
    )
    return world_state._weather_rows({"weather": rows})


def test_admin_weather_rows_are_runtime_observer_only(monkeypatch):
    rows = _weather_rows(monkeypatch, [{
        "zone": 148,
        "weather_type": 5,
        "density": 0.8,
        "manual": True,
        "rain_chance": 80,
        "snow_chance": 10,
        "storm_chance": 20,
        "season": "spring",
    }])

    row = rows[0]

    assert row["zone_name"] == "Darkshore"
    assert row["current"] == "Heavy Rain"
    assert row["weather_icon"] == "🌧"
    assert row["weather_icon_key"] == "Heavy Rain"
    assert row["continent_name"] == "Kalimdor"
    assert row["teleport_name"] == "Darkshore"
    assert "manual" not in row
    assert "rain_chance" not in row
    assert "snow_chance" not in row
    assert "storm_chance" not in row
    assert "season" not in row


def test_admin_weather_search_supports_runtime_weather_and_continent_tokens(monkeypatch):
    rows = _weather_rows(monkeypatch, [
        {"zone": 148, "weather_type": 5, "density": 0.8},
        {"zone": 12, "weather_type": 0, "density": 0.0},
        {"zone": 67, "weather_type": 0, "density": 0.0},
    ])
    by_name = {row["zone_name"]: row for row in rows}

    darkshore_search = by_name["Darkshore"]["search_text"]
    elwynn_search = by_name["Elwynn Forest"]["search_text"]
    storm_peaks_search = by_name["The Storm Peaks"]["search_text"]

    assert all(token in darkshore_search for token in ("kalimdor", "rain", "heavy"))
    assert all(token in elwynn_search for token in ("eastern", "clear", "goldshire"))
    assert "storm" in storm_peaks_search
