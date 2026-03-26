#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def _decode_player_bytes(player_bytes: int, player_bytes2: int) -> dict:
    return {
        "skin": player_bytes & 0xFF,
        "face": (player_bytes >> 8) & 0xFF,
        "hair_style": (player_bytes >> 16) & 0xFF,
        "hair_color": (player_bytes >> 24) & 0xFF,
        "facial_hair": player_bytes2 & 0xFF,
    }