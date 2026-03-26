#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class RegionState:
    def __init__(self, map_id):
        self.map_id = int(map_id)
        self.players = set()
        self.weather = "sunny"
        self.local_time_offset = 0

