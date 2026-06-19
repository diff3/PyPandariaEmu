#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PetBattleSession:
    battle_id: int
    player_guid: int
    started_at: float
    active: bool = True
