#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FarmPlotStage(str, Enum):
    EMPTY = "EMPTY"
    PLANTED = "PLANTED"
    GROWING = "GROWING"
    MATURE = "MATURE"


@dataclass
class PendingSeedSelection:
    seed_item: int
    bag: int
    slot: int


@dataclass
class FarmPlot:
    owner_guid: int
    plot_guid: int
    seed_item: int = 0
    planted_at: int = 0


@dataclass
class PlayerFarm:
    owner_guid: int
    plots: dict[int, FarmPlot]
