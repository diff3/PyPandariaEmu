#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import time

from shared.Logger import Logger
from server.modules.game.inventory import (
    add_item_to_character,
    persist_session_inventory,
)
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from server.modules.handlers.world.features.halfhill_farming import (
    get_halfhill_farm_manager,
)
from server.modules.handlers.world.features.halfhill_farming.definitions import (
    CROPS_BY_SEED_ITEM,
    GREEN_CABBAGE,
    JUICYCRUNCH_CARROT,
    MANAGED_PLOT_GUIDS,
)
from server.modules.handlers.world.features.halfhill_farming.persistence import (
    has_claimed_starter_seeds,
    mark_starter_seed_claimed,
)
from server.modules.handlers.world.inventory_sync import build_inventory_delta_responses


FARMER_YOON_ENTRY = 58646
_STARTER_CONFIRM_SECONDS = 15.0


def handle_farmer_yoon_interaction(session, guid: int) -> list[tuple[str, bytes]]:
    responses = build_farm_summary_messages(session)

    if _starter_confirmation_active(session):
        granted = grant_starter_seeds(session)
        _clear_starter_confirmation(session)
        return responses + granted

    if eligible_for_starter_seeds(session):
        _arm_starter_confirmation(session)
        responses.append(_message("[HalfhillFarm] Click Farmer Yoon again within 15 seconds to claim starter seeds."))
    else:
        _clear_starter_confirmation(session)
    return responses


def build_farm_summary_messages(session) -> list[tuple[str, bytes]]:
    manager = get_halfhill_farm_manager()
    farm = manager.get_or_load_farm(session)

    counts = {
        "EMPTY": 0,
        "PLANTED": 0,
        "GROWING": 0,
        "MATURE": 0,
    }
    plot_lines: list[str] = []

    for index, plot_guid in enumerate(MANAGED_PLOT_GUIDS, start=1):
        plot = farm.plots[int(plot_guid)]
        stage = manager.plot_stage(plot)
        counts[stage.value] += 1
        crop = CROPS_BY_SEED_ITEM.get(int(plot.seed_item))
        if stage.value == "EMPTY":
            plot_lines.append(f"Plot {index}: Empty")
        elif crop is None:
            plot_lines.append(f"Plot {index}: {stage.value.title()}")
        else:
            crop_label = "Carrot" if crop.key == "carrot" else "Cabbage"
            plot_lines.append(f"Plot {index}: {stage.value.title()} ({crop_label})")

    messages = [
        _message("Halfhill Farm Status"),
        _message(
            f"Plots: total={len(MANAGED_PLOT_GUIDS)} empty={counts['EMPTY']} planted={counts['PLANTED']} "
            f"growing={counts['GROWING']} mature={counts['MATURE']}"
        ),
    ]
    messages.extend(_message(line) for line in plot_lines)
    return messages


def eligible_for_starter_seeds(session) -> bool:
    if has_claimed_starter_seeds(int(getattr(session, "char_guid", 0) or 0)):
        return False
    return not player_has_supported_seeds(session)


def player_has_supported_seeds(session) -> bool:
    supported = {int(GREEN_CABBAGE.seed_item), int(JUICYCRUNCH_CARROT.seed_item)}
    state = getattr(session, "inventory_state", None)
    items_by_pos = getattr(state, "items_by_pos", {}) if state is not None else {}
    if isinstance(items_by_pos, dict):
        for item in items_by_pos.values():
            if int(getattr(item, "entry", 0) or 0) in supported:
                return True

    items_by_guid = getattr(session, "inventory_by_guid", None)
    if isinstance(items_by_guid, dict):
        for item in items_by_guid.values():
            if int(getattr(item, "entry", 0) or 0) in supported:
                return True
    return False


def grant_starter_seeds(session) -> list[tuple[str, bytes]]:
    char_guid = int(getattr(session, "char_guid", 0) or 0)
    if has_claimed_starter_seeds(char_guid):
        return [_message("[HalfhillFarm] Starter seeds have already been claimed.")]
    if player_has_supported_seeds(session):
        return [_message("[HalfhillFarm] You already have supported Halfhill seeds.")]

    cabbage = add_item_to_character(session, int(GREEN_CABBAGE.seed_item), 5)
    if not cabbage.ok:
        return [_message(f"[HalfhillFarm] Failed to grant starter seeds: {cabbage.message}")]
    carrot = add_item_to_character(session, int(JUICYCRUNCH_CARROT.seed_item), 5)
    if not carrot.ok:
        return [_message(f"[HalfhillFarm] Failed to grant starter seeds: {carrot.message}")]
    if not mark_starter_seed_claimed(char_guid, int(time.time())):
        return [_message("[HalfhillFarm] Failed to record starter seed claim.")]

    persist_session_inventory(session)
    responses = list(build_inventory_delta_responses(session, cabbage) or [])
    responses.extend(build_inventory_delta_responses(session, carrot) or [])
    responses.extend([
        _message("Starter seeds granted:"),
        _message("5x Green Cabbage Seeds"),
        _message("5x Juicycrunch Carrot Seeds"),
    ])
    Logger.info("[HalfhillFarm] starter seeds granted player=%s", char_guid)
    return responses


def clear_farmer_yoon_state(session) -> None:
    _clear_starter_confirmation(session)


def _starter_confirmation_active(session) -> bool:
    until = float(getattr(session, "farmer_yoon_starter_confirm_until", 0.0) or 0.0)
    if until <= 0.0:
        return False
    if until < time.monotonic():
        _clear_starter_confirmation(session)
        return False
    return True


def _arm_starter_confirmation(session) -> None:
    session.farmer_yoon_starter_confirm_until = float(time.monotonic() + _STARTER_CONFIRM_SECONDS)


def _clear_starter_confirmation(session) -> None:
    session.farmer_yoon_starter_confirm_until = 0.0


def _message(text: str) -> tuple[str, bytes]:
    return "SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(str(text or ""))
