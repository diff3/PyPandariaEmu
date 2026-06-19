#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from server.modules.handlers.world.features.pet_battles.runtime import (
    PetBattleManager,
)


_MANAGER = PetBattleManager()


def get_pet_battle_manager() -> PetBattleManager:
    return _MANAGER
