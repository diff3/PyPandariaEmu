#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import random
from typing import Optional

from DSL.modules.EncoderHandler import EncoderHandler
from shared.Logger import Logger
from server.modules.handlers.world.characters.characters import preload_cache as preload_character_cache
from server.modules.game.inventory import persist_session_inventory
from server.session.runtime import session
from server.modules.handlers.world.opcodes import login as login_handlers
from server.modules.handlers.world.opcodes.movement import (
    _save_current_position_like_command as save_current_position_like_command,
)
from server.modules.handlers.world.state.global_state import global_state
from server.modules.handlers.world.state.runtime import broadcast_player_remove
from server.modules.handlers.world.runtime.player_store import (
    get_player_runtime_store,
)





def get_auth_challenge() -> Optional[tuple[str, bytes]]:
    fields = {
        "uint16_0": 0,
        "uint32_zeros": [random.getrandbits(32) for _ in range(8)],
        "uint8_value": 1,
        "seed": random.getrandbits(32),
    }
    payload = EncoderHandler.encode_packet("SMSG_AUTH_CHALLENGE", fields)
    if len(payload) != 39:
        raise ValueError(
            f"SMSG_AUTH_CHALLENGE payload size is {len(payload)}, expected 39"
        )
    return "SMSG_AUTH_CHALLENGE", payload


def reset_state() -> None:
    try:
        from server.modules.handlers.world.opcodes.entities import release_current_chair
        release_current_chair(session, reason="reset")
    except Exception as exc:
        Logger.debug("[CHAIR] release on reset failed: %s", exc)

    region = getattr(session, "region", None)
    if region is not None:
        region.players.discard(session)
    state = getattr(session, "global_state", None)
    if state is not None:
        state.chat_channels.setdefault("world", set()).discard(session)
        getattr(state, "sessions", set()).discard(session)
    session.region = None
    session.global_state = global_state
    session.account_id = None
    session.account_name = None
    session.realm_id = None
    session.player_guid = None
    session.world_guid = None
    session.char_guid = None
    session.selected_character = None
    session.time_sync_seq = 0
    session.last_position_save_at = 0.0
    session.position_dirty = False
    session.persist_map_id = 0
    session.persist_zone = 0
    session.persist_instance_id = 0
    session.persist_x = 0.0
    session.persist_y = 0.0
    session.persist_z = 0.0
    session.persist_orientation = 0.0
    session.last_saved_map_id = 0
    session.last_saved_zone = 0
    session.last_saved_instance_id = 0
    session.last_saved_x = 0.0
    session.last_saved_y = 0.0
    session.last_saved_z = 0.0
    session.last_saved_orientation = 0.0
    from server.modules.handlers.world.player_visibility import (
        get_player_visibility_service,
    )

    get_player_visibility_service().clear_player_links(
        session,
        list(getattr(global_state, "sessions", set()) or ()),
    )
    login_handlers._reset_login_flow_state(session)


def preload_cache() -> None:
    try:
        preload_character_cache()
    except Exception as exc:
        Logger.warning(f"[WorldHandlers] preload_cache failed: {exc}")


def handle_disconnect() -> None:
    handle_disconnect_session(session)


def handle_disconnect_session(target_session) -> None:
    if target_session is None or bool(getattr(target_session, "_disconnect_handled", False)):
        return

    target_session._disconnect_handled = True

    guid = int(getattr(target_session, "char_guid", 0) or 0)
    state = getattr(target_session, "global_state", None)

    Logger.info(f"[DISCONNECT] guid={guid} start")

    try:
        from server.modules.handlers.world.opcodes.entities import release_current_chair
        release_current_chair(target_session, reason="disconnect")
    except Exception as exc:
        Logger.debug("[CHAIR] release on disconnect failed: %s", exc)

    try:
        from server.modules.handlers.world.taxi_runtime import persist_taxi_for_disconnect
        if persist_taxi_for_disconnect(target_session):
            Logger.info(
                "[DISCONNECT] taxi paused guid=%s pos=(%.3f, %.3f, %.3f)",
                guid,
                float(getattr(target_session, "x", 0.0) or 0.0),
                float(getattr(target_session, "y", 0.0) or 0.0),
                float(getattr(target_session, "z", 0.0) or 0.0),
            )
    except Exception as exc:
        Logger.warning(f"[DISCONNECT] taxi pause failed: {exc}")

    try:
        from server.modules.handlers.world.features.plants_vs_ghouls import (
            get_plants_vs_ghouls_manager,
        )

        get_plants_vs_ghouls_manager().handle_disconnect(target_session)
    except Exception as exc:
        Logger.warning(f"[DISCONNECT] PvG cleanup failed: {exc}")

    try:
        from server.modules.handlers.world.features.halfhill_farming import (
            get_halfhill_farm_manager,
        )

        get_halfhill_farm_manager().clear_for_logout(target_session)
    except Exception as exc:
        Logger.warning(f"[DISCONNECT] HalfhillFarm cleanup failed: {exc}")
    try:
        from server.modules.handlers.world.features.pet_battles import (
            get_pet_battle_manager,
        )

        get_pet_battle_manager().handle_disconnect(target_session)
    except Exception as exc:
        Logger.warning(f"[DISCONNECT] PetBattle cleanup failed: {exc}")

    # --- Remove from world (broadcast) ---
    try:
        broadcast_player_remove(target_session)
    except Exception as exc:
        Logger.warning(f"[DISCONNECT] broadcast_player_remove failed: {exc}")

    # --- Persist position ---
    try:
        from server.modules.handlers.world.runtime.world_attachment import (
            persist_session_world_attachment,
        )

        persist_session_world_attachment(target_session)
    except Exception as exc:
        Logger.warning(f"[DISCONNECT] world attachment save failed: {exc}")

    try:
        save_current_position_like_command(
            target_session,
            reason="disconnect",
            online=0,
            force=True,
        )
    except Exception as exc:
        Logger.warning(f"[DISCONNECT] position save failed: {exc}")

    # --- Persist inventory/equipment cache ---
    try:
        persist_session_inventory(target_session)
    except Exception as exc:
        Logger.warning(f"[DISCONNECT] inventory save failed: {exc}")

    # --- Remove from region ---
    region = getattr(target_session, "region", None)
    if region is not None:
        try:
            region.players.discard(target_session)
        except Exception as exc:
            Logger.warning(f"[DISCONNECT] region cleanup failed: {exc}")

    # --- Remove from global state ---
    if state is not None:
        try:
            # chat channels
            if hasattr(state, "chat_channels"):
                state.chat_channels.setdefault("world", set()).discard(target_session)

            # sessions (IMPORTANT FIX)
            sessions = getattr(state, "sessions", None)
            if sessions is not None:
                before = len(sessions)
                sessions.discard(target_session)
                after = len(sessions)

                Logger.info(
                    f"[DISCONNECT] sessions {before} -> {after} (removed={guid})"
                )

        except Exception as exc:
            Logger.warning(f"[DISCONNECT] global_state cleanup failed: {exc}")

    get_player_runtime_store().remove(guid)
    target_session.selected_character = None

    # --- Clear references ---
    target_session.region = None
    target_session.send_response = None
    from server.modules.handlers.world.player_visibility import (
        get_player_visibility_service,
    )

    get_player_visibility_service().clear_player_links(target_session, ())
    target_session.near_teleport_pending = False
    target_session.worldport_ack_pending = False

    # --- Reset login state ---
    try:
        login_handlers._reset_login_flow_state(target_session)
    except Exception as exc:
        Logger.warning(f"[DISCONNECT] login reset failed: {exc}")

    Logger.info(f"[DISCONNECT] guid={guid} done")
