#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from shared.Logger import Logger
from server.modules.game.inventory import (
    add_item_to_character,
    persist_session_inventory,
)
from server.modules.handlers.world.features.halfhill_farming import persistence
from server.modules.handlers.world.features.halfhill_farming.definitions import (
    CROPS_BY_SEED_ITEM,
)
from server.modules.handlers.world.inventory_sync import build_inventory_delta_responses


def harvest_plot(session, plot) -> tuple[bool, list[tuple[str, bytes]], str]:
    crop = CROPS_BY_SEED_ITEM.get(int(getattr(plot, "seed_item", 0) or 0))
    if crop is None:
        return False, [], "[HalfhillFarm] Plot has no harvestable crop."

    result = add_item_to_character(session, int(crop.harvest_item), 1)
    if not result.ok:
        return False, [], f"[HalfhillFarm] Harvest failed: {result.message}"

    if not persistence.clear_plot(
        int(getattr(plot, "owner_guid", 0) or 0),
        int(getattr(plot, "plot_guid", 0) or 0),
    ):
        return False, [], "[HalfhillFarm] Failed to clear harvested plot."

    plot.seed_item = 0
    plot.planted_at = 0

    persist_session_inventory(session)
    responses = list(build_inventory_delta_responses(session, result) or [])
    Logger.info(
        "[HalfhillFarm] harvested player=%s plot=%s item=%s",
        int(getattr(plot, "owner_guid", 0) or 0),
        int(getattr(plot, "plot_guid", 0) or 0),
        int(crop.harvest_item),
    )
    return True, responses, f"[HalfhillFarm] Harvested {crop.harvest_name}."
