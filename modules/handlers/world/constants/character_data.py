#!/usr/bin/env python3
# -*- coding: utf-8 -*-

INVTYPE_SLOT_MAP = {
    1: [0],
    2: [1],
    3: [2],
    4: [3],
    5: [4],
    20: [4],
    6: [5],
    7: [6],
    8: [7],
    9: [8],
    10: [9],
    11: [10, 11],
    12: [12, 13],
    16: [14],
    13: [15],
    17: [15],
    21: [15],
    22: [16],
    14: [16],
    23: [16],
    15: [17],
    25: [17],
    26: [17],
    28: [17],
    19: [18],
    18: [19, 20, 21, 22],
}

EQUIPMENT_SLOTS = 23

DBC_CHAR_START_OUTFIT_FMT = (
    "dbbbX"
    "iiiiiiiiiiiiiiiiiiiiiiii"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
)

PLAYER_FACTION_TEMPLATE_BY_RACE = {
    1: 1,
    2: 2,
    3: 3,
    4: 4,
    5: 5,
    6: 6,
    7: 115,
    8: 116,
    9: 2204,
    10: 1610,
    11: 1629,
    12: 1,
    13: 1,
    14: 1,
    15: 1,
    16: 1,
    17: 1,
    18: 1,
    19: 1,
    20: 1,
    21: 1,
    22: 2203,
    23: 1,
    24: 2395,
    25: 2401,
    26: 2402,
}

PLAYER_DISPLAY_POWER_BY_CLASS = {
    1: 1,
    2: 0,
    3: 2,
    4: 3,
    5: 0,
    6: 6,
    7: 0,
    8: 0,
    9: 0,
    10: 3,
    11: 0,
}

DEFAULT_MAX_PRIMARY_POWER_BY_DISPLAY = {
    0: 100,
    1: 100,
    2: 100,
    3: 100,
    6: 100,
}
