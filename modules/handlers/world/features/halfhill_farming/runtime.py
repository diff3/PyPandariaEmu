#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import time

from shared.Logger import Logger
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from server.modules.handlers.world.features.halfhill_farming import (
    harvesting,
    persistence,
    planting,
)
from server.modules.handlers.world.features.halfhill_farming.definitions import (
    CROPS_BY_SEED_ITEM,
    MANAGED_PLOT_GUIDS,
    PLOT_STAGE_GROWING_SECONDS,
    PLOT_STAGE_PLANTED_SECONDS,
)
from server.modules.handlers.world.features.halfhill_farming.state import (
    FarmPlot,
    FarmPlotStage,
    PendingSeedSelection,
    PlayerFarm,
)


class HalfhillFarmManager:
    def __init__(self) -> None:
        self._farms: dict[int, PlayerFarm] = {}

    def select_seed(self, session, *, item_entry: int, bag: int, slot: int) -> list[tuple[str, bytes]]:
        crop = CROPS_BY_SEED_ITEM.get(int(item_entry or 0))
        if crop is None:
            return []
        session.pending_farm_seed = PendingSeedSelection(
            seed_item=int(item_entry),
            bag=int(bag),
            slot=int(slot),
        )
        Logger.info(
            "[HalfhillFarm] seed selected player=%s seed=%s bag=%s slot=%s",
            int(getattr(session, "char_guid", 0) or 0),
            int(item_entry),
            int(bag),
            int(slot),
        )
        return [self._system_message(
            f"[HalfhillFarm] Selected {crop.seed_name}. Click an Undisturbed Soil plot."
        )]

    def clear_pending_seed(self, session) -> None:
        if hasattr(session, "pending_farm_seed"):
            session.pending_farm_seed = None

    def clear_for_logout(self, session) -> None:
        self.clear_pending_seed(session)
        try:
            from server.modules.handlers.world.features.halfhill_farming.farmer_yoon import (
                clear_farmer_yoon_state,
            )

            clear_farmer_yoon_state(session)
        except Exception:
            pass

    def clear_for_map_transfer(self, session) -> None:
        self.clear_pending_seed(session)
        try:
            from server.modules.handlers.world.features.halfhill_farming.farmer_yoon import (
                clear_farmer_yoon_state,
            )

            clear_farmer_yoon_state(session)
        except Exception:
            pass

    def handle_gameobject_use(self, session, entry: dict) -> list[tuple[str, bytes]] | None:
        plot_guid = int(entry.get("guid", 0) or 0)
        if plot_guid not in MANAGED_PLOT_GUIDS:
            return None

        farm = self._load_farm(session)
        plot = farm.plots[int(plot_guid)]
        pending_seed = getattr(session, "pending_farm_seed", None)
        now = int(time.time())

        if isinstance(pending_seed, PendingSeedSelection):
            stage = self.plot_stage(plot, now=now)
            if stage != FarmPlotStage.EMPTY:
                return [self._system_message(
                    f"[HalfhillFarm] Plot {int(plot_guid)} is {stage.value.lower()} and cannot be planted."
                )]
            ok, responses, message = planting.plant_plot(
                session,
                plot,
                pending_seed,
                planted_at=now,
            )
            if ok:
                self.clear_pending_seed(session)
            else:
                self.clear_pending_seed(session)
            responses.append(self._system_message(message))
            return responses

        stage = self.plot_stage(plot, now=now)
        if stage == FarmPlotStage.MATURE:
            ok, responses, message = harvesting.harvest_plot(session, plot)
            if not ok:
                return [self._system_message(message)]
            responses.append(self._system_message(message))
            return responses

        return [self._system_message(self.plot_status_message(plot, now=now))]

    def plot_stage(self, plot: FarmPlot, *, now: int | None = None) -> FarmPlotStage:
        seed_item = int(getattr(plot, "seed_item", 0) or 0)
        planted_at = int(getattr(plot, "planted_at", 0) or 0)
        if seed_item <= 0 or planted_at <= 0:
            return FarmPlotStage.EMPTY

        age = max(0, int((int(now) if now is not None else int(time.time())) - planted_at))
        if age < PLOT_STAGE_PLANTED_SECONDS:
            return FarmPlotStage.PLANTED
        if age < PLOT_STAGE_GROWING_SECONDS:
            return FarmPlotStage.GROWING
        return FarmPlotStage.MATURE

    def plot_status_message(self, plot: FarmPlot, *, now: int | None = None) -> str:
        stage = self.plot_stage(plot, now=now)
        if stage == FarmPlotStage.EMPTY:
            return f"[HalfhillFarm] Plot {int(plot.plot_guid)} is empty."
        crop = CROPS_BY_SEED_ITEM.get(int(plot.seed_item), None)
        crop_name = crop.harvest_name if crop is not None else f"seed {int(plot.seed_item)}"
        if stage == FarmPlotStage.PLANTED:
            return f"[HalfhillFarm] Plot {int(plot.plot_guid)} is planted with {crop_name}."
        if stage == FarmPlotStage.GROWING:
            return f"[HalfhillFarm] Plot {int(plot.plot_guid)} is growing {crop_name}."
        return f"[HalfhillFarm] Plot {int(plot.plot_guid)} is mature and ready to harvest."

    def _load_farm(self, session) -> PlayerFarm:
        owner_guid = int(getattr(session, "char_guid", 0) or 0)
        existing = self._farms.get(owner_guid)
        if existing is not None:
            return existing

        rows = persistence.load_player_plots(owner_guid)
        plots = {
            int(plot_guid): FarmPlot(
                owner_guid=owner_guid,
                plot_guid=int(plot_guid),
                seed_item=int((rows.get(int(plot_guid)) or {}).get("seed_item", 0) or 0),
                planted_at=int((rows.get(int(plot_guid)) or {}).get("planted_at", 0) or 0),
            )
            for plot_guid in MANAGED_PLOT_GUIDS
        }
        farm = PlayerFarm(owner_guid=owner_guid, plots=plots)
        self._farms[owner_guid] = farm
        return farm

    def get_or_load_farm(self, session) -> PlayerFarm:
        return self._load_farm(session)

    def reset_for_tests(self) -> None:
        self._farms.clear()

    def _system_message(self, message: str) -> tuple[str, bytes]:
        return "SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(str(message or ""))
