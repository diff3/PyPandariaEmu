#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from server.modules.handlers.world.state.region_state import RegionState


class RegionManager:
    def __init__(self):
        self.regions = {}

    def get_region(self, map_id):
        normalized_map_id = int(map_id)
        if normalized_map_id not in self.regions:
            self.regions[normalized_map_id] = RegionState(normalized_map_id)
        return self.regions[normalized_map_id]


region_manager = RegionManager()
