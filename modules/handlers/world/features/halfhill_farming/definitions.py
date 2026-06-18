#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass


HALFHILL_MAP_ID = 870
MANAGED_PLOT_GUIDS = (
    262125,
    262133,
    262134,
    262142,
)

PLOT_STAGE_PLANTED_SECONDS = 60
PLOT_STAGE_GROWING_SECONDS = 300


@dataclass(frozen=True)
class CropDefinition:
    key: str
    seed_item: int
    harvest_item: int
    seed_name: str
    harvest_name: str


GREEN_CABBAGE = CropDefinition(
    key="cabbage",
    seed_item=79102,
    harvest_item=74840,
    seed_name="Green Cabbage Seeds",
    harvest_name="Green Cabbage",
)

JUICYCRUNCH_CARROT = CropDefinition(
    key="carrot",
    seed_item=80590,
    harvest_item=74841,
    seed_name="Juicycrunch Carrot Seeds",
    harvest_name="Juicycrunch Carrot",
)

CROPS_BY_SEED_ITEM = {
    int(GREEN_CABBAGE.seed_item): GREEN_CABBAGE,
    int(JUICYCRUNCH_CARROT.seed_item): JUICYCRUNCH_CARROT,
}
