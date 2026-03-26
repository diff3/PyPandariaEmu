#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class GlobalState:
    def __init__(self):
        self.time = 0
        self.time_offset = 0
        self.time_speed = 0.01666667
        self.weather_seed = 12345
        self.chat_channels = {}


global_state = GlobalState()
