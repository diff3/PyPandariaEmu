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
    player_pet_guid: int = 0
    enemy_pet_guid: int = 0
    player_species_id: int = 0
    enemy_species_id: int = 0
    spawned_unit_guids: tuple[int, ...] = ()
    spawned_world_object_guids: tuple[int, ...] = ()
