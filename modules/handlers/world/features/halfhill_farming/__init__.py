#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from server.modules.handlers.world.features.halfhill_farming.runtime import (
    HalfhillFarmManager,
)


_MANAGER = HalfhillFarmManager()


def get_halfhill_farm_manager() -> HalfhillFarmManager:
    return _MANAGER
