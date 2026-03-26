#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class RegionState:
    def __init__(self, map_id):
        self.map_id = int(map_id)
        self.players = set()
        self.weather = {
            "weather_type": 0,
            "density": 0.0,
            "abrupt": 0,
        }
        self.weather_manual = False
        self.local_time_offset = 0
