#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from shared.Logger import Logger
from server.modules.game.inventory import (
    destroy_character_item,
    persist_session_inventory,
)
from server.modules.handlers.world.features.halfhill_farming import persistence
from server.modules.handlers.world.features.halfhill_farming.definitions import (
    CROPS_BY_SEED_ITEM,
)
from server.modules.handlers.world.inventory_sync import build_inventory_delta_responses


def plant_plot(session, plot, pending_seed, *, planted_at: int) -> tuple[bool, list[tuple[str, bytes]], str]:
    crop = CROPS_BY_SEED_ITEM.get(int(getattr(pending_seed, "seed_item", 0) or 0))
    if crop is None:
        return False, [], "[HalfhillFarm] Unsupported seed."

    if not persistence.save_plot(
        int(getattr(plot, "owner_guid", 0) or 0),
        int(getattr(plot, "plot_guid", 0) or 0),
        seed_item=int(crop.seed_item),
        planted_at=int(planted_at),
    ):
        return False, [], "[HalfhillFarm] Failed to save planted plot."

    result = destroy_character_item(
        session,
        int(getattr(pending_seed, "bag", 0) or 0),
        int(getattr(pending_seed, "slot", 0) or 0),
        1,
    )
    if not result.ok:
        persistence.clear_plot(
            int(getattr(plot, "owner_guid", 0) or 0),
            int(getattr(plot, "plot_guid", 0) or 0),
        )
        return False, [], "[HalfhillFarm] Selected seed is no longer available."

    plot.seed_item = int(crop.seed_item)
    plot.planted_at = int(planted_at)

    persist_session_inventory(session)
    responses = list(build_inventory_delta_responses(session, result) or [])
    Logger.info(
        "[HalfhillFarm] planted player=%s plot=%s seed=%s planted_at=%s",
        int(getattr(plot, "owner_guid", 0) or 0),
        int(getattr(plot, "plot_guid", 0) or 0),
        int(crop.seed_item),
        int(planted_at),
    )
    return True, responses, f"[HalfhillFarm] Planted {crop.seed_name}."
