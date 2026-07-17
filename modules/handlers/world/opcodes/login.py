#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import math
import time
from typing import Any, Optional, Tuple

from shared.Logger import Logger
from server.modules.protocol.PacketContext import PacketContext
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.game.guid import GuidHelper, HighGuid
from server.modules.game.inventory import refresh_session_inventory
from server.modules.handlers.world.characters.characters import (
    handle_CMSG_CHAR_CREATE as handle_char_create_packet,
    handle_CMSG_CHAR_DELETE as handle_char_delete_packet,
    handle_CMSG_REORDER_CHARACTERS as handle_reorder_characters_packet,
)
from server.modules.handlers.world.login.context import WorldLoginContext
from server.modules.handlers.world.login.packets import (
    _resolve_player_display_id,
    build_ENUM_CHARACTERS_RESULT,
    build_login_packet,
)
from server.modules.handlers.world.login import (
    build_char_screen_packets,
    build_player_login_packets,
    build_pre_update_object_packets,
    build_post_update_object_packets,
    build_world_bootstrap_packets,
)
from server.modules.handlers.world.addons import prepare_session_addons
from server.session.world_session import LoginState
from server.modules.handlers.world.account_data import (
    PER_CHARACTER_ACCOUNT_DATA_TYPES,
    SEND_ACCOUNT_DATA_TO_CLIENT,
    account_data_mask_for_types,
    build_minimal_post_timesync_account_packets,
    load_character_account_data,
    load_global_account_data,
)
from server.modules.handlers.world.achievement_service import initialize_session_achievements
from server.modules.handlers.world.bootstrap.gameobjects import build_database_gameobject_responses
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from DSL.modules.EncoderHandler import EncoderHandler
from server.modules.handlers.world.constants.character_data import (
    DEFAULT_MAX_PRIMARY_POWER_BY_DISPLAY,
    PLAYER_DISPLAY_POWER_BY_CLASS,
    PLAYER_FACTION_TEMPLATE_BY_RACE,
)
from server.modules.handlers.world.dispatcher import register
from server.modules.handlers.world.inventory_sync import (
    build_login_inventory_sync_responses,
    trigger_inventory_activation,
)
from server.modules.handlers.world.opcodes import misc as misc_handlers
from server.modules.handlers.world.opcodes.movement import (
    _capture_persist_position_from_session as capture_persist_position_from_session,
    _remember_saved_position as remember_saved_position,
)
from server.modules.handlers.world.opcodes import spells as spells_handlers
from server.modules.handlers.world.packet_logging import log_cmsg
from server.modules.handlers.world.position.position_service import (
    Position,
    correct_z_if_invalid,
    format_position,
    normalize_position,
    position_from_row,
)
from server.modules.handlers.world.runtime.player import Player
from server.modules.handlers.world.runtime.player_store import (
    get_player_runtime_store,
    resolve_player_runtime,
)
from server.modules.handlers.world.transport_debug import (
    TransportDebugEvent,
    log_transport_event,
    log_transport_packet_snapshot,
)

_CINEMATIC_SEQUENCE_BY_RACE = {
    # ChrRaces.dbc cinematic sequence ids.
    1: 81,
    2: 21,
    3: 41,
    4: 61,
    5: 2,
    6: 141,
    7: 101,
    8: 121,
    9: 172,
    10: 162,
    11: 163,
    22: 170,
    24: 259,
    25: 259,
    26: 259,
}
_SANDBOX_RACE_REMAP = {
    24: 26,  # Neutral Pandaren -> Horde Pandaren until neutral faction choice exists.
}
_CINEMATIC_OFF = 0
_CINEMATIC_PLAYED = 1
_CINEMATIC_PENDING = 2
from server.modules.handlers.world.position.area_service import (
    resolve_area_from_position,
    resolve_zone_from_position,
)
from server.modules.handlers.world.state.runtime import (
    attach_session_to_world_state,
    build_explored_zones_update_response,
    pack_wow_game_time,
    refresh_region_weather,
    sync_all_players_on_map,
    sync_player_visibility,
)
from server.modules.handlers.world.feature_config import (
    gameobjects_enabled,
    npc_auto_stream_enabled,
    npcs_enabled,
    taxi_movement_debug_enabled,
)


def _taxi_xmap_debug(message: str, *args) -> None:
    if not taxi_movement_debug_enabled():
        return
    Logger.info(message, *args)


def _resolve_session_ids(session) -> Tuple[Optional[int], Optional[int]]:
    """Ensure session.account_id and session.realm_id are populated if possible."""
    if session.account_id is None and session.account_name:
        try:
            acc = DatabaseConnection.get_user_by_username(session.account_name)
            if not acc:
                acc = DatabaseConnection.get_user_by_username(session.account_name.upper())
            if acc:
                session.account_id = acc.id
        except Exception:
            pass

    if session.realm_id is None:
        try:
            realm = DatabaseConnection.get_realmlist()
            if realm:
                session.realm_id = int(realm.id)
        except Exception:
            pass

    return session.account_id, session.realm_id


def _decode_loading_screen_showing(decoded: dict[str, Any], payload: bytes) -> int:
    for key in ("showing", "is_loading", "show"):
        if key in decoded:
            return int(decoded.get(key) or 0)
    if len(payload) >= 4:
        packed = int.from_bytes(payload[:4], "little", signed=False)
        return (packed >> 31) & 0x01
    return 0


def _resolve_login_character_guid(
    login_guid: Optional[int],
    payload: bytes,
    account_id: Optional[int],
    realm_id: Optional[int],
    account_name: Optional[str] = None,
) -> Optional[int]:
    def _log_match(candidate: int, row: object) -> None:
        player_name = str(getattr(row, "name", "") or f"Player{candidate}")
        account_label = str(account_name or account_id or "?")
        Logger.info(
            f"[WorldHandlers] PLAYER_LOGIN selected player={player_name} "
            f"account={account_label} char_guid={candidate}"
        )

    def _decode_bitpacked_guid(
        body: bytes,
        *,
        mask_order: tuple[int, ...],
        byte_order: tuple[int, ...],
    ) -> Optional[int]:
        if len(body) < 5:
            return None

        offset = 4
        mask = body[offset]
        offset += 1

        raw = [0] * 8
        for bit_pos, byte_index in enumerate(mask_order):
            if mask & (1 << bit_pos):
                raw[byte_index] = 1

        for byte_index in byte_order:
            if not raw[byte_index]:
                continue
            if offset >= len(body):
                return None
            raw[byte_index] ^= body[offset]
            offset += 1

        if offset != len(body):
            return None

        return int.from_bytes(bytes(raw), "little", signed=False)

    candidates: list[int] = []

    if login_guid is not None:
        try:
            low_from_login, _realm_from_login, _high_from_login = GuidHelper.decode_login_guid(login_guid)
            candidates.append(int(low_from_login))
        except Exception:
            pass

    if payload and len(payload) >= 6:
        raw6 = payload[:6]
        candidates.extend(
            [
                int.from_bytes(raw6[:4], "little", signed=False),
                int.from_bytes(raw6[:4], "big", signed=False),
            ]
        )

    deduped: list[int] = []
    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        deduped.append(candidate)

    for candidate in deduped:
        try:
            row = DatabaseConnection.get_character(candidate, realm_id)
            if row and (account_id is None or int(row.account) == int(account_id)):
                _log_match(int(candidate), row)
                return int(candidate)
        except Exception:
            continue

    if account_id is not None and realm_id is not None:
        try:
            rows = DatabaseConnection.get_characters_for_account(account_id, realm_id)
        except Exception:
            rows = []

        if login_guid is None and rows:
            fallback = rows[0]
            Logger.warning(
                f"[WorldHandlers] PLAYER_LOGIN missing login guid; "
                f"falling back to first character guid={int(fallback.guid)} slot={int(fallback.slot or 0)}"
            )
            return int(fallback.guid)

        row_by_world_guid = {
            int(GuidHelper.make(HighGuid.PLAYER, int(realm_id), int(row.guid))): int(row.guid)
            for row in rows
        }
        row_by_login_guid = {
            int(GuidHelper.make_login_guid(int(row.guid), int(realm_id), HighGuid.PLAYER)): int(row.guid)
            for row in rows
        }

        if payload and len(payload) == 6:
            try:
                candidate_login_guid = int.from_bytes(payload, "little", signed=False)
            except Exception:
                candidate_login_guid = None
            if candidate_login_guid in row_by_login_guid:
                candidate = row_by_login_guid[candidate_login_guid]
                row = DatabaseConnection.get_character(candidate, realm_id)
                if row:
                    _log_match(candidate, row)
                return candidate

        packed_variants = (
            ((1, 4, 7, 3, 2, 6, 5, 0), (5, 1, 0, 6, 2, 4, 7, 3), "5.4.8"),
            ((7, 6, 0, 4, 5, 2, 3, 1), (5, 0, 1, 6, 7, 2, 3, 4), "5.4.7"),
        )
        for mask_order, byte_order, _label in packed_variants:
            candidate_world_guid = _decode_bitpacked_guid(
                payload,
                mask_order=mask_order,
                byte_order=byte_order,
            )
            if candidate_world_guid in row_by_world_guid:
                candidate = row_by_world_guid[candidate_world_guid]
                row = DatabaseConnection.get_character(candidate, realm_id)
                if row:
                    _log_match(candidate, row)
                return candidate

        if len(payload) == 7:
            compact = payload[4:]
            compact_candidates = []
            if len(compact) >= 2:
                compact_candidates.append(int(compact[1]))
                compact_candidates.append(int(compact[1]) ^ 0x01)

            seen_compact = set()
            for candidate in compact_candidates:
                if candidate in seen_compact:
                    continue
                seen_compact.add(candidate)
                if candidate <= 0:
                    continue
                row = DatabaseConnection.get_character(candidate, realm_id)
                if row and int(row.account) == int(account_id):
                    _log_match(candidate, row)
                    return candidate

    if account_id is not None and realm_id is not None:
        try:
            rows = DatabaseConnection.get_characters_for_account(account_id, realm_id)
            for row in rows:
                expected = GuidHelper.make_login_guid(
                    low=int(row.guid),
                    realm=int(realm_id),
                    high=HighGuid.PLAYER,
                )
                if int(expected) == int(login_guid):
                    _log_match(int(row.guid), row)
                    return int(row.guid)
        except Exception:
            pass

    Logger.warning(
        f"[WorldHandlers] PLAYER_LOGIN could not resolve login_guid="
        f"{'None' if login_guid is None else f'0x{int(login_guid):X}'}; "
        f"candidate lows={deduped}"
    )
    return None


def _resolve_primary_power_for_row(row, class_id: int) -> tuple[int, int, int]:
    display_power = int(PLAYER_DISPLAY_POWER_BY_CLASS.get(int(class_id) or 0, 0))
    power_field = {
        0: "power1",
        1: "power2",
        2: "power3",
        3: "power4",
        6: "power5",
    }.get(display_power, "power1")
    current = int(getattr(row, power_field, 0) or 0)
    default_max = int(DEFAULT_MAX_PRIMARY_POWER_BY_DISPLAY.get(display_power, 100))
    if current <= 0:
        current = default_max
    return display_power, current, max(current, default_max)


def _assert_player_object_sent(session) -> None:
    assert getattr(session, "player_object_sent", False) is True, (
        "player object must be sent before UI bootstrap packets"
    )


def _set_login_state(session, state: Optional[LoginState]) -> None:
    previous = getattr(session, "login_state", None)
    if previous == state:
        return
    session.login_state = state
    Logger.info(
        f"[LOGIN] state {previous.value if previous else 'None'} -> "
        f"{state.value if state else 'None'}"
    )


def _reset_login_flow_state(session, *, preserve_loading_screen_done: bool = False) -> None:
    _set_login_state(session, None)
    session.loading_screen_visible = False
    if not preserve_loading_screen_done:
        session.loading_screen_done = False
    session.chat_motd_sent = False
    session.post_loading_sent = False
    session.player_object_sent = False
    session.pending_account_data_requests = []
    session.account_data_times_sent = False
    session.account_data_captures_sent = False
    session.skyfire_login_stage = 0
    session.teleport_pending = False
    session.worldport_ack_pending = False
    session.teleport_destination = None
    session.near_teleport_pending = False
    session.near_teleport_generation = 0
    session.world_transition_generation = 0
    session.world_transition_loading_generation = 0
    from server.modules.handlers.world.teleport.transition import (
        reset_world_transition_bootstrap,
    )

    reset_world_transition_bootstrap(session)
    session.world_transition_owner = None
    session.world_transition_ignore_worldport_ack = False
    session.world_transition_status = "IDLE"
    session.world_transition_terminal_state = None
    session.world_transition_terminal_generation = 0
    session.world_transition_terminal_owner = None
    session.world_transition_failure_reason = None
    session._worldport_destination_visibility_refresh_pending = False
    try:
        from server.modules.handlers.world.transport_runtime import detach_session_transport_passenger

        detach_session_transport_passenger(
            session,
            reason="login_reset",
            opcode_name="login_reset",
        )
    except Exception as exc:
        Logger.warning("[TransportDetach] login reset detach failed error=%s", str(exc))
    session.post_bootstrap_transport_reattach_request = None
    session.pending_world_attachment_restore = None
    session.inventory_activated = False


def _reset_morph_state(session, race: int, gender: int) -> None:
    # Morph is session-only and must not survive relog.
    native_display_id = int(_resolve_player_display_id(race, gender, 15476) or 15476)
    session.display_id = native_display_id
    session.is_morphed = False
    session.morph_display_id = None
    session.original_display_id = None
    session.native_display_id = native_display_id


def _reset_loaded_world_object_state(session) -> None:
    """Drop client-visible world object bookkeeping for a fresh login."""
    session.loaded_gameobjects = set()
    session.loaded_gameobject_entries = {}
    session.loaded_transport_entries = {}
    session.loaded_npcs = set()
    session.npc_flags_by_guid = {}
    session.gameobjects_visible = bool(gameobjects_enabled())
    session.npcs_visible = bool(npcs_enabled())
    session.npc_auto_stream = bool(npc_auto_stream_enabled())
    session.last_gameobject_stream_at = 0.0
    session.last_npc_stream_at = 0.0


def _build_world_login_context(session) -> WorldLoginContext:
    ctx = WorldLoginContext.from_session(session)
    ctx.player_runtime = resolve_player_runtime(session)
    return ctx


def _worldport_bootstrap_variant(session) -> str:
    variant = str(
        getattr(session, "_worldport_bootstrap_variant", "A") or "A"
    ).strip().upper()
    return variant if variant in {"A", "B", "C", "D"} else "A"


def _resolve_opening_cinematic_id(race: int) -> int:
    return int(_CINEMATIC_SEQUENCE_BY_RACE.get(int(race), 0) or 0)


def _resolve_pending_cinematic_id(race: int, cinematic_state: int) -> int:
    if int(cinematic_state or 0) != _CINEMATIC_PENDING:
        return 0
    return _resolve_opening_cinematic_id(int(race))


def _build_pending_cinematic_response(session) -> list[tuple[str, bytes]]:
    cinematic_id = int(getattr(session, "pending_cinematic_id", 0) or 0)
    if cinematic_id <= 0:
        return []

    payload = EncoderHandler.encode_packet(
        "SMSG_TRIGGER_CINEMATIC",
        {"cinematic_id": int(cinematic_id)},
    )
    session.pending_cinematic_id = 0
    session.cinematic_played = _CINEMATIC_PLAYED
    DatabaseConnection.save_character_cinematic_state(
        int(getattr(session, "char_guid", 0) or 0),
        int(getattr(session, "realm_id", 0) or 0),
        _CINEMATIC_PLAYED,
    )
    Logger.info(
        "[CINEMATIC] trigger guid=%s race=%s cinematic=%s",
        int(getattr(session, "char_guid", 0) or 0),
        int(getattr(session, "race", 0) or 0),
        int(cinematic_id),
    )
    return [("SMSG_TRIGGER_CINEMATIC", payload)]


def _is_pre_player_login_state(state: Optional[LoginState]) -> bool:
    return state in {None, LoginState.AUTHED, LoginState.CHAR_SCREEN}


def build_player_bootstrap_packets(session) -> list[tuple[str, bytes]]:
    """Build the player's initial world object packets from live session state."""
    ctx = _build_world_login_context(session)
    player = resolve_player_runtime(session)
    ctx.player_runtime = player
    responses: list[tuple[str, bytes]] = []

    active_mover = build_login_packet("SMSG_MOVE_SET_ACTIVE_MOVER", ctx)
    if active_mover is not None:
        responses.append(("SMSG_MOVE_SET_ACTIVE_MOVER", active_mover))

    bootstrap_runtime = getattr(session, "_player_bootstrap_runtime_transport", None)
    transport_bootstrap = isinstance(bootstrap_runtime, dict)
    bootstrap_variant = _worldport_bootstrap_variant(session)
    pre_player_gameobject_responses: list[tuple[str, bytes]] = []
    if transport_bootstrap:
        pre_player_gameobject_responses = build_database_gameobject_responses(session)
        if bootstrap_variant != "B":
            responses.extend(pre_player_gameobject_responses)
        if bool(bootstrap_runtime.get("transport_create_transform_matched")):
            Logger.info(
                "[TransportBootstrap] transport_create_sent guid=0x%016X packets=%s",
                int(bootstrap_runtime["transport_guid"]) & 0xFFFFFFFFFFFFFFFF,
                len(pre_player_gameobject_responses),
            )
        else:
            Logger.warning(
                "[TransportBootstrap] transport_create_sent guid=0x%016X packets=%s "
                "matched=false",
                int(bootstrap_runtime["transport_guid"]) & 0xFFFFFFFFFFFFFFFF,
                len(pre_player_gameobject_responses),
            )
    if isinstance(bootstrap_runtime, dict):
        Logger.info(
            "[TransportTransfer] player_bootstrap_runtime "
            "transport_guid=0x%016X route_phase=%s "
            "runtime_transport_world=(%.3f %.3f %.3f) runtime_rotation=%.6f "
            "local_offset=(%.3f %.3f %.3f %.3f) "
            "rotated_offset=(%.3f %.3f %.3f) "
            "player_world=(%.3f %.3f %.3f %.3f) "
            "has_transport_data=%s fallback=false",
            int(bootstrap_runtime["transport_guid"]) & 0xFFFFFFFFFFFFFFFF,
            int(bootstrap_runtime["route_phase"]),
            float(bootstrap_runtime["x"]),
            float(bootstrap_runtime["y"]),
            float(bootstrap_runtime["z"]),
            float(bootstrap_runtime["orientation"]),
            float(bootstrap_runtime["local_x"]),
            float(bootstrap_runtime["local_y"]),
            float(bootstrap_runtime["local_z"]),
            float(bootstrap_runtime["local_o"]),
            float(bootstrap_runtime["rotated_x"]),
            float(bootstrap_runtime["rotated_y"]),
            float(bootstrap_runtime["rotated_z"]),
            float(ctx.x),
            float(ctx.y),
            float(ctx.z),
            float(ctx.orientation),
            "true" if bool(ctx.has_transport_data) else "false",
        )
        Logger.info(
            "[TransportBootstrap] player_create_transport has_transport_data=%s "
            "guid=0x%016X offset=(%.3f %.3f %.3f %.6f) transport_time=%s",
            "true" if bool(ctx.has_transport_data) else "false",
            int(getattr(ctx, "transport_guid", 0) or 0) & 0xFFFFFFFFFFFFFFFF,
            float(getattr(ctx, "transport_x", 0.0) or 0.0),
            float(getattr(ctx, "transport_y", 0.0) or 0.0),
            float(getattr(ctx, "transport_z", 0.0) or 0.0),
            float(getattr(ctx, "transport_orientation", 0.0) or 0.0),
            int(getattr(ctx, "transport_time", 0) or 0) & 0xFFFFFFFF,
        )
    player_create = build_login_packet("SMSG_UPDATE_OBJECT_1773613176_0002", ctx)
    if player_create is not None:
        responses.append(("SMSG_UPDATE_OBJECT", player_create))
        session.player_object_sent = True
        log_transport_packet_snapshot(
            session,
            opcode="SMSG_UPDATE_OBJECT",
            source_subsystem="player_bootstrap_create",
            batch_id=(
                f"{int(getattr(session, 'world_transition_generation', 0) or 0)}:"
                "world-bootstrap"
            ),
            map_id=int(getattr(ctx, "map_id", 0) or 0),
            position=(
                float(getattr(ctx, "x", 0.0) or 0.0),
                float(getattr(ctx, "y", 0.0) or 0.0),
                float(getattr(ctx, "z", 0.0) or 0.0),
                float(getattr(ctx, "orientation", 0.0) or 0.0),
            ),
            transport_guid=int(
                getattr(ctx, "transport_guid", 0) or 0
            ),
            transport_offsets=(
                float(getattr(ctx, "transport_x", 0.0) or 0.0),
                float(getattr(ctx, "transport_y", 0.0) or 0.0),
                float(getattr(ctx, "transport_z", 0.0) or 0.0),
                float(
                    getattr(ctx, "transport_orientation", 0.0) or 0.0
                ),
            ),
            movement_flags=int(
                getattr(ctx, "movement_flags", 0) or 0
            ),
            object_guid=int(getattr(ctx, "world_guid", 0) or 0),
            object_map_context=int(getattr(ctx, "map_id", 0) or 0),
        )

    if transport_bootstrap and bootstrap_variant == "B":
        responses.extend(pre_player_gameobject_responses)
    if transport_bootstrap and bootstrap_variant == "C" and active_mover is not None:
        responses.append(("SMSG_MOVE_SET_ACTIVE_MOVER", active_mover))

    if not transport_bootstrap:
        responses.extend(build_database_gameobject_responses(session))
    if (
        isinstance(bootstrap_runtime, dict)
        and not bool(bootstrap_runtime.get("transport_create_transform_matched"))
    ):
        Logger.warning(
            "[TransportTransfer] transport_bootstrap_runtime "
            "transport_guid=0x%016X matches_player_runtime=false "
            "reason=transport_create_not_built",
            int(bootstrap_runtime["transport_guid"]) & 0xFFFFFFFFFFFFFFFF,
        )
    return responses


def _sync_pending_transport_before_player_bootstrap(session) -> bool:
    """Place a pending boat passenger on the current destination transform."""
    session._player_bootstrap_runtime_transport = None
    pending = getattr(session, "pending_transport_transfer", None)
    if not isinstance(pending, dict):
        return False

    from server.modules.handlers.world.teleport.transition import (
        pending_transition_is_current,
    )

    if not pending_transition_is_current(session, pending):
        log_transport_event(
            TransportDebugEvent.STALE_GENERATION_IGNORED,
            transport_guid=int(pending.get("destination_guid", 0) or 0),
            player_guid=int(getattr(session, "char_guid", 0) or 0),
            transfer_id=str(pending.get("transfer_id", "") or ""),
            reason="pre_bootstrap_generation_mismatch",
        )
        Logger.info(
            "[TeleportTransition] ignoring superseded pre-bootstrap transport "
            "pending_generation=%s current_generation=%s",
            pending.get("world_transition_generation"),
            int(getattr(session, "world_transition_generation", 0) or 0),
        )
        session.pending_transport_transfer = None
        session.transport_transfer_pending = False
        return False

    destination_entry = pending.get("destination_entry")
    try:
        from server.modules.handlers.world.transport_runtime import (
            current_runtime_transport_state_for_guid,
            is_cross_map_boat_entry,
            is_cross_map_zeppelin_entry,
        )

        if not isinstance(destination_entry, dict) or not (
            is_cross_map_boat_entry(destination_entry)
            or is_cross_map_zeppelin_entry(destination_entry)
        ):
            return False

        destination_guid = int(pending.get("destination_guid", 0) or 0)
        runtime_state = current_runtime_transport_state_for_guid(destination_guid)
        destination_map = int(
            pending.get("destination_map", getattr(session, "map_id", 0)) or 0
        )
        if runtime_state is None or int(getattr(runtime_state, "map_id", -1)) != destination_map:
            Logger.info(
                "[TransportTransfer] player_bootstrap_runtime transfer_id=%s "
                "transport_guid=0x%016X fallback=true reason=transport_not_found",
                str(pending.get("transfer_id", "unknown") or "unknown"),
                destination_guid & 0xFFFFFFFFFFFFFFFF,
            )
            return False

        local_x = float(pending.get("local_x", 0.0) or 0.0)
        local_y = float(pending.get("local_y", 0.0) or 0.0)
        local_z = float(pending.get("local_z", 0.0) or 0.0)
        local_o = float(pending.get("local_o", 0.0) or 0.0)
        transport_x = float(getattr(runtime_state, "x", 0.0) or 0.0)
        transport_y = float(getattr(runtime_state, "y", 0.0) or 0.0)
        transport_z = float(getattr(runtime_state, "z", 0.0) or 0.0)
        transport_o = float(getattr(runtime_state, "orientation", 0.0) or 0.0)
        cos_o = math.cos(transport_o)
        sin_o = math.sin(transport_o)
        rotated_x = (cos_o * local_x) - (sin_o * local_y)
        rotated_y = (sin_o * local_x) + (cos_o * local_y)
        rotated_z = local_z
        player_x = transport_x + rotated_x
        player_y = transport_y + rotated_y
        player_z = transport_z + rotated_z
        player_o = transport_o + local_o
        state = getattr(session, "movement_state", None)
        if state is None:
            from server.session.world_session import MovementState

            state = MovementState()
            session.movement_state = state
        from server.modules.handlers.world.transport_runtime import (
            update_transport_passenger_offset,
        )

        if not update_transport_passenger_offset(
            session,
            destination_guid,
            local_x=local_x,
            local_y=local_y,
            local_z=local_z,
            local_o=local_o,
            transport_time=int(getattr(runtime_state, "path_progress_ms", 0) or 0),
            transport_time2=0,
            transport_time3=0,
            seat=-1,
        ):
            raise RuntimeError("destination passenger attachment missing during bootstrap")
        from server.modules.handlers.world.position.publication import (
            publish_absolute,
        )

        publish_absolute(
            session,
            map_id=destination_map,
            instance_id=int(getattr(session, "instance_id", 0) or 0),
            x=player_x,
            y=player_y,
            z=player_z,
            orientation=player_o,
        )
        region = getattr(session, "region", None)
        if (
            region is not None
            and int(getattr(region, "map_id", destination_map) or 0)
            != destination_map
        ):
            attach_session_to_world_state(session, map_id=destination_map)

        route_phase = int(getattr(runtime_state, "path_progress_ms", 0) or 0) & 0xFFFFFFFF
        session._player_bootstrap_runtime_transport = {
            "transport_guid": destination_guid,
            "map_id": destination_map,
            "x": transport_x,
            "y": transport_y,
            "z": transport_z,
            "orientation": transport_o,
            "route_phase": route_phase,
            "local_x": local_x,
            "local_y": local_y,
            "local_z": local_z,
            "local_o": local_o,
            "rotated_x": rotated_x,
            "rotated_y": rotated_y,
            "rotated_z": rotated_z,
        }
        Logger.info(
            "[TransportBootstrap] preserved_attachment "
            "transport_guid=0x%016X has_transport_data=true "
            "player_world=(%.3f %.3f %.3f %.3f)",
            destination_guid & 0xFFFFFFFFFFFFFFFF,
            float(getattr(session, "x", 0.0) or 0.0),
            float(getattr(session, "y", 0.0) or 0.0),
            float(getattr(session, "z", 0.0) or 0.0),
            float(getattr(session, "orientation", 0.0) or 0.0),
        )
        return True
    except Exception as exc:
        Logger.info(
            "[TransportTransfer] player_bootstrap_runtime transfer_id=%s "
            "fallback=true reason=transport_not_found error=%s",
            str(pending.get("transfer_id", "unknown") or "unknown"),
            str(exc),
        )
        return False


def _sync_bootstrap_context_from_session(
    session,
    ctx: WorldLoginContext,
) -> None:
    """Publish committed passenger geometry into the existing bootstrap context."""
    state = getattr(session, "movement_state", None)
    ctx.map_id = int(getattr(session, "map_id", 0) or 0)
    ctx.instance_id = int(getattr(session, "instance_id", 0) or 0)
    ctx.x = float(getattr(session, "x", 0.0) or 0.0)
    ctx.y = float(getattr(session, "y", 0.0) or 0.0)
    ctx.z = float(getattr(session, "z", 0.0) or 0.0)
    ctx.orientation = float(getattr(session, "orientation", 0.0) or 0.0)
    ctx.player_runtime = resolve_player_runtime(session)
    ctx.has_transport_data = bool(
        state is not None
        and getattr(state, "has_transport_data", False)
        and int(getattr(state, "transport_guid", 0) or 0) > 0
    )
    ctx.transport_guid = int(getattr(state, "transport_guid", 0) or 0)
    ctx.transport_x = float(getattr(state, "transport_x", 0.0) or 0.0)
    ctx.transport_y = float(getattr(state, "transport_y", 0.0) or 0.0)
    ctx.transport_z = float(getattr(state, "transport_z", 0.0) or 0.0)
    ctx.transport_orientation = float(
        getattr(state, "transport_orientation", 0.0) or 0.0
    )
    ctx.transport_time = int(getattr(state, "transport_time", 0) or 0)
    ctx.transport_time2 = int(getattr(state, "transport_time2", 0) or 0)
    ctx.transport_time3 = int(getattr(state, "transport_time3", 0) or 0)
    ctx.transport_seat = int(getattr(state, "transport_seat", -1))


def _queue_world_bootstrap_transition_unchecked(
    session,
    ctx: WorldLoginContext,
) -> list[tuple[str, bytes]]:
    # TODO: Keep current packet ordering intact until world bootstrap is isolated from legacy replay helpers.
    if getattr(session, "post_loading_sent", False):
        Logger.info("[LOGIN] WORLD_BOOTSTRAP already queued; skipping duplicate")
        return []

    _set_login_state(session, LoginState.WORLD_BOOTSTRAP)
    Logger.debug("[LOGIN] sending init packet sequence")
    refresh_region_weather(session)
    ctx.weather = dict(getattr(session, "weather", {}) or {})

    responses: list[tuple[str, bytes]] = []
    pre_update_packets = build_pre_update_object_packets(ctx)
    update_packets: list[tuple[str, bytes]] = []
    if not getattr(session, "player_object_sent", False):
        update_packets = build_player_bootstrap_packets(session)
    post_update_packets = build_post_update_object_packets(ctx)
    bootstrap_packets = [
        (opcode_name, payload)
        for opcode_name, payload in build_world_bootstrap_packets(ctx)
        if opcode_name != "SMSG_MOVE_SET_ACTIVE_MOVER"
    ]

    for opcode_name, payload in pre_update_packets:
        if not SEND_ACCOUNT_DATA_TO_CLIENT and opcode_name == "SMSG_ACCOUNT_DATA_TIMES":
            Logger.info("[WorldLogin] suppressing SMSG_ACCOUNT_DATA_TIMES")
            continue
        Logger.info(f"[WorldLogin] sending {opcode_name}")
        if opcode_name == "SMSG_LOGIN_SET_TIME_SPEED":
            Logger.info("[WorldLogin] sending SMSG_LOGIN_SETTIMESPEED")
        if opcode_name == "SMSG_ACCOUNT_DATA_TIMES":
            session.account_data_times_sent = True
        responses.append((opcode_name, payload))
    responses.extend(update_packets)
    post_create_spell_packets = spells_handlers.build_active_mover_spell_sync_responses(session)
    if post_create_spell_packets:
        Logger.info(
            "[WorldLogin] sending %s post-create spell sync packets",
            len(post_create_spell_packets),
        )
        responses.extend(post_create_spell_packets)

    inventory_packets = build_login_inventory_sync_responses(session)
    if inventory_packets:
        Logger.info(f"[WorldLogin] sending {len(inventory_packets)} inventory sync packets")
        responses.extend(inventory_packets)
        responses.extend(trigger_inventory_activation(session))
    explored_response = build_explored_zones_update_response(session)
    if explored_response is not None:
        Logger.info("[WorldLogin] sending persisted explored zones state")
        responses.append(explored_response)
    for opcode_name, payload in post_update_packets:
        Logger.info(f"[WorldLogin] sending {opcode_name}")
        responses.append((opcode_name, payload))
    for opcode_name, payload in bootstrap_packets:
        if opcode_name == "SMSG_MOVE_SET_ACTIVE_MOVER":
            Logger.info("[WorldLoginExperiment] sending ACTIVE_MOVER")
        elif opcode_name == "SMSG_TIME_SYNC_REQUEST":
            Logger.info("[WorldLoginExperiment] sending TIME_SYNC_REQUEST")
        responses.append((opcode_name, payload))

    from server.modules.handlers.world.world_refresh import get_world_refresh_service
    from server.modules.handlers.world.opcodes import movement as movement_handlers

    responses.extend(
        get_world_refresh_service().refresh_after_login(
            session,
            context="login-bootstrap-complete",
            _object_refresh=movement_handlers.stream_world_objects_after_teleport,
        )
    )

    session.loading_screen_done = True
    session.post_loading_sent = True
    Logger.info("[LOGIN] WORLD_BOOTSTRAP queued player create + minimal bootstrap bundle")
    return responses


def _queue_world_bootstrap_transition(
    session,
    ctx: WorldLoginContext,
) -> list[tuple[str, bytes]]:
    """Build login bootstrap with atomic moving-object attachment restore."""
    from server.modules.handlers.world.runtime.world_attachment import (
        abort_login_world_attachment,
        prepare_login_world_attachment,
    )

    has_restore = isinstance(
        getattr(session, "pending_world_attachment_restore", None),
        dict,
    )
    if has_restore:
        prepare_login_world_attachment(session)
        ctx = _build_world_login_context(session)
    try:
        responses = _queue_world_bootstrap_transition_unchecked(session, ctx)
    except Exception:
        if has_restore:
            abort_login_world_attachment(
                session,
                reason="bootstrap_failed",
            )
        raise
    return responses


def _queue_teleport_world_transition(session, ctx: WorldLoginContext) -> list[tuple[str, bytes]]:
    trace_id = str(getattr(session, "loading_screen_trace_id", "unknown") or "unknown")
    bootstrap_started = time.monotonic()
    Logger.info(
        "[LoadingScreenTrace] trace_id=%s stage=bootstrap event=entering responses=0",
        trace_id,
    )
    # TODO: Teleport bootstrap still shares movement replay/bootstrap helpers with legacy world init.
    _taxi_xmap_debug(
        "[TAXI_XMAP_DEBUG] teleport_bootstrap_enter player=%s map=%s "
        "teleport_pending=%s worldport_ack_pending=%s phase=%s pending=%s",
        int(getattr(session, "char_guid", 0) or 0),
        int(getattr(session, "map_id", 0) or 0),
        int(bool(getattr(session, "teleport_pending", False))),
        int(bool(getattr(session, "worldport_ack_pending", False))),
        str(getattr(getattr(session, "taxi_state", None), "phase", "")),
        getattr(session, "pending_taxi_transfer", None),
    )
    if _sync_pending_transport_before_player_bootstrap(session):
        _sync_bootstrap_context_from_session(session, ctx)
    _reset_loaded_world_object_state(session)
    _set_login_state(session, LoginState.WORLD_BOOTSTRAP)
    refresh_region_weather(session)
    ctx.weather = dict(getattr(session, "weather", {}) or {})

    responses: list[tuple[str, bytes]] = []

    for opcode_name in ("SMSG_BIND_POINT_UPDATE",):
        payload = build_login_packet(opcode_name, ctx)
        if payload is None:
            continue
        Logger.info(f"[Teleport] sending {opcode_name}")
        responses.append((opcode_name, payload))

    far_worldport_spell_packets = spells_handlers.build_active_mover_spell_sync_responses(session)
    if far_worldport_spell_packets:
        Logger.info(
            "[Teleport] sending %s pre-active-mover spell sync packets",
            len(far_worldport_spell_packets),
        )
        responses.extend(far_worldport_spell_packets)
    session._far_worldport_known_spells_sent = any(
        opcode_name == "SMSG_SEND_KNOWN_SPELLS"
        for opcode_name, _payload in far_worldport_spell_packets
    )

    time_speed = build_login_packet("SMSG_LOGIN_SET_TIME_SPEED", ctx)
    if time_speed is not None:
        Logger.info("[Teleport] sending SMSG_LOGIN_SET_TIME_SPEED")
        responses.append(("SMSG_LOGIN_SET_TIME_SPEED", time_speed))

    step_started = time.monotonic()
    Logger.info(
        "[LoadingScreenTrace] trace_id=%s stage=player_bootstrap_packets event=entering",
        trace_id,
    )
    try:
        player_bootstrap_packets = build_player_bootstrap_packets(session)
    except Exception as exc:
        Logger.info(
            "[LoadingScreenTrace] trace_id=%s stage=player_bootstrap_packets "
            "event=exception elapsed_ms=%.3f error=%s",
            trace_id,
            (time.monotonic() - step_started) * 1000.0,
            str(exc),
        )
        raise
    finally:
        session._player_bootstrap_runtime_transport = None
    responses.extend(player_bootstrap_packets)
    Logger.info(
        "[LoadingScreenTrace] trace_id=%s stage=player_bootstrap_packets "
        "event=leaving elapsed_ms=%.3f packets=%s total_packets=%s",
        trace_id,
        (time.monotonic() - step_started) * 1000.0,
        len(player_bootstrap_packets),
        len(responses),
    )

    inventory_packets = build_login_inventory_sync_responses(session)
    if inventory_packets:
        Logger.info(f"[Teleport] sending {len(inventory_packets)} inventory sync packets")
        responses.extend(inventory_packets)
        responses.extend(trigger_inventory_activation(session))
    explored_response = build_explored_zones_update_response(session)
    if explored_response is not None:
        Logger.info("[Teleport] sending persisted explored zones state")
        responses.append(explored_response)

    time_sync = build_login_packet("SMSG_TIME_SYNC_REQUEST", ctx)
    if time_sync is not None:
        Logger.info("[Teleport] sending SMSG_TIME_SYNC_REQUEST")
        responses.append(("SMSG_TIME_SYNC_REQUEST", time_sync))

    for opcode_name in (
        "SMSG_PHASE_SHIFT_CHANGE",
        "SMSG_INIT_WORLD_STATES",
        "SMSG_WEATHER",
        "SMSG_QUERY_TIME_RESPONSE",
    ):
        payload = build_login_packet(opcode_name, ctx)
        if payload is None:
            continue
        Logger.info(f"[Teleport] sending {opcode_name}")
        responses.append((opcode_name, payload))

    from server.modules.handlers.world.transport_runtime import build_bootstrap_transport_value_updates

    step_started = time.monotonic()
    Logger.info(
        "[LoadingScreenTrace] trace_id=%s stage=transport_bootstrap_packets event=entering",
        trace_id,
    )
    try:
        transport_packets = build_bootstrap_transport_value_updates(session)
    except Exception as exc:
        Logger.info(
            "[LoadingScreenTrace] trace_id=%s stage=transport_bootstrap_packets "
            "event=exception elapsed_ms=%.3f error=%s",
            trace_id,
            (time.monotonic() - step_started) * 1000.0,
            str(exc),
        )
        raise
    responses.extend(transport_packets)
    Logger.info(
        "[LoadingScreenTrace] trace_id=%s stage=transport_bootstrap_packets "
        "event=leaving elapsed_ms=%.3f packets=%s total_packets=%s",
        trace_id,
        (time.monotonic() - step_started) * 1000.0,
        len(transport_packets),
        len(responses),
    )
    from server.modules.handlers.world.opcodes import movement as movement_handlers
    from server.modules.handlers.world.opcodes import taxi as taxi_handlers

    taxi_responses = taxi_handlers.continue_pending_cross_map_taxi(session)
    _taxi_xmap_debug(
        "[TAXI_XMAP_DEBUG] teleport_bootstrap_taxi_continue player=%s map=%s "
        "phase=%s pending=%s packets=%s",
        int(getattr(session, "char_guid", 0) or 0),
        int(getattr(session, "map_id", 0) or 0),
        str(getattr(getattr(session, "taxi_state", None), "phase", "")),
        getattr(session, "pending_taxi_transfer", None),
        [opcode for opcode, _payload in taxi_responses],
    )
    responses.extend(taxi_responses)

    pending_transport = getattr(session, "pending_transport_transfer", None)
    movement_handlers.complete_pending_transport_transfer(session)
    session.loading_screen_done = True
    session.post_loading_sent = True
    session.teleport_pending = False
    session.worldport_ack_pending = False
    session.teleport_destination = None
    from server.modules.handlers.world.teleport.lifecycle import get_teleport_lifecycle

    responses.extend(
        get_teleport_lifecycle().complete_transition(
            session,
            context="worldport-bootstrap-complete",
            refresh="bootstrap",
            _object_refresh=(
                movement_handlers.stream_world_objects_after_teleport
            ),
        )
    )
    if isinstance(pending_transport, dict):
        try:
            from server.modules.handlers.world.transport_debug_messages import build_message

            debug_response = build_message(
                session,
                "world_loaded",
                "[Transport] WORLD LOADED map=%s"
                % int(getattr(session, "map_id", 0) or 0),
                transfer_id=str(
                    pending_transport.get("transfer_id", "")
                    or getattr(session, "transport_debug_transfer_id", "transport")
                    or "transport"
                ),
            )
            if debug_response is not None:
                responses.append(debug_response)
        except Exception as exc:
            Logger.warning("[TransportDebug] world-loaded message failed error=%s", str(exc))
    Logger.info(
        "[LoadingScreenTrace] trace_id=%s stage=bootstrap event=leaving "
        "elapsed_ms=%.3f packets=%s empty=%s",
        trace_id,
        (time.monotonic() - bootstrap_started) * 1000.0,
        len(responses),
        "true" if not responses else "false",
    )
    return responses


def _current_transport_worldport_matches(session, pending: object) -> bool:
    """Return whether pending data still owns this transport generation."""
    if not isinstance(pending, dict):
        return False
    return (
        str(getattr(session, "world_transition_owner", "") or "")
        == "transport_worldport"
        and int(pending.get("world_transition_generation", 0) or 0)
        == int(getattr(session, "world_transition_generation", 0) or 0)
    )


def _fail_transport_worldport_bootstrap(
    session,
    pending: dict | None,
    *,
    reason: str,
) -> list[tuple[str, bytes]]:
    """Terminally fail a current transport worldport and start safe fallback."""
    if not isinstance(pending, dict):
        return []

    from server.modules.handlers.world.teleport.transition import (
        fail_world_transition,
    )

    expected_generation = int(
        pending.get(
            "world_transition_generation",
            getattr(session, "world_transition_generation", 0),
        )
        or 0
    )
    failed = fail_world_transition(
        session,
        expected_generation=expected_generation,
        expected_owner="transport_worldport",
        reason=str(reason),
    )
    if not failed:
        Logger.info(
            "[TeleportTransition] transport failure ignored owner=%s "
            "generation=%s expected_generation=%s",
            str(getattr(session, "world_transition_owner", "") or "none"),
            int(getattr(session, "world_transition_generation", 0) or 0),
            expected_generation,
        )
        return []

    from server.modules.handlers.world.transport_runtime import (
        clear_player_transport_state,
        finalize_transport_boundary_event,
        restore_transport_boundary_event,
    )

    session.pending_transport_transfer = None
    session.transport_transfer_pending = False
    clear_player_transport_state(
        session,
        reason="worldport_failed",
        opcode_name="bootstrap_failure",
    )

    safe_map = int(pending.get("safe_map", pending.get("source_map", 0)) or 0)
    safe_values = tuple(
        pending.get(key)
        for key in (
            "safe_x",
            "safe_y",
            "safe_z",
            "safe_o",
        )
    )
    if any(value is None for value in safe_values):
        Logger.error(
            "[TeleportTransition] transport fallback unavailable player=%s "
            "generation=%s reason=missing_safe_position",
            int(getattr(session, "char_guid", 0) or 0),
            expected_generation,
        )
        restore_transport_boundary_event(
            pending,
            reason="missing_safe_position",
        )
        return []

    from server.modules.handlers.world.teleport.map_transfer import (
        TeleportDestination,
        apply_map_transfer,
    )

    safe_x, safe_y, safe_z, safe_o = (
        float(value) for value in safe_values
    )
    try:
        responses = apply_map_transfer(
            session,
            TeleportDestination(
                map_id=safe_map,
                x=safe_x,
                y=safe_y,
                z=safe_z,
                orientation=safe_o,
                name="transport-worldport-fallback",
            ),
            reason="transport_worldport_failure",
        )
    except Exception:
        restore_transport_boundary_event(
            pending,
            reason="safe_fallback_rejected",
        )
        raise
    finalize_transport_boundary_event(pending, outcome="failed_fallback")
    Logger.warning(
        "[TeleportTransition] transport worldport failed; fallback started "
        "player=%s failed_generation=%s fallback_generation=%s map=%s",
        int(getattr(session, "char_guid", 0) or 0),
        expected_generation,
        int(getattr(session, "world_transition_generation", 0) or 0),
        safe_map,
    )
    return responses


def ensure_worldport_bootstrap_started(
    session,
    signal: str,
    *,
    expected_generation: int | None = None,
    expected_owner: str | None = None,
) -> list[tuple[str, bytes]]:
    """Start the current worldport bootstrap once for either client signal.

    Loading-screen completion and WORLDPORT_ACK are both untrusted requests to
    start bootstrap.  Successful bootstrap remains the only completion path.
    """
    generation = int(
        getattr(session, "world_transition_generation", 0) or 0
    )
    owner = str(getattr(session, "world_transition_owner", "") or "")
    signal_name = str(signal or "unknown")

    if expected_generation is None:
        expected_generation = int(
            getattr(session, "world_transition_loading_generation", 0) or 0
        )
    if expected_owner is None:
        expected_owner = owner

    if (
        generation <= 0
        or not owner
        or int(expected_generation or 0) != generation
        or str(expected_owner or "") != owner
    ):
        Logger.info(
            "[WorldportBootstrap] signal rejected signal=%s "
            "expected_generation=%s current_generation=%s "
            "expected_owner=%s current_owner=%s reason=stale_ownership",
            signal_name,
            int(expected_generation or 0),
            generation,
            str(expected_owner or "none"),
            owner or "none",
        )
        return []

    if not bool(getattr(session, "teleport_pending", False)):
        Logger.info(
            "[WorldportBootstrap] signal ignored signal=%s generation=%s "
            "owner=%s reason=no_pending_worldport",
            signal_name,
            generation,
            owner,
        )
        return []

    bootstrap_generation = int(
        getattr(session, "world_transition_bootstrap_generation", 0) or 0
    )
    bootstrap_status = str(
        getattr(session, "world_transition_bootstrap_status", "IDLE") or "IDLE"
    )
    if bootstrap_generation == generation and bootstrap_status in {
        "STARTING",
        "COMPLETED",
        "FAILED",
    }:
        Logger.info(
            "[WorldportBootstrap] signal ignored signal=%s generation=%s "
            "owner=%s reason=already_%s",
            signal_name,
            generation,
            owner,
            bootstrap_status.lower(),
        )
        return []

    session.world_transition_bootstrap_generation = generation
    session.world_transition_bootstrap_status = "STARTING"
    pending = getattr(session, "pending_transport_transfer", None)
    Logger.info(
        "[WorldportBootstrap] starting signal=%s generation=%s owner=%s",
        signal_name,
        generation,
        owner,
    )

    try:
        login_ctx = _build_world_login_context(session)
        responses = _queue_teleport_world_transition(session, login_ctx)
    except Exception as exc:
        session.world_transition_bootstrap_status = "FAILED"
        log_transport_event(
            TransportDebugEvent.BOOTSTRAP_REJECTED,
            transport_guid=int(
                (pending.get("destination_guid", 0) or 0)
                if isinstance(pending, dict)
                else 0
            ),
            player_guid=int(getattr(session, "char_guid", 0) or 0),
            transfer_id=str(
                pending.get("transfer_id", "")
                if isinstance(pending, dict)
                else ""
            ),
            reason=str(exc),
        )
        if _current_transport_worldport_matches(session, pending):
            return _fail_transport_worldport_bootstrap(
                session,
                pending,
                reason=str(exc),
            )
        raise

    responses.insert(
        0,
        (
            "SMSG_MESSAGECHAT",
            encode_skyfire_messagechat_system_payload(
                "[Teleport] loading done -> "
                f"{str(getattr(session, 'teleport_destination', '') or '?')}"
            ),
        ),
    )
    Logger.info(
        "[WorldportBootstrap] completed signal=%s generation=%s "
        "owner=%s packets=%s",
        signal_name,
        generation,
        owner,
        len(responses),
    )
    return responses


@register("CMSG_AUTH_SESSION")
def handle_auth_session(session, ctx: PacketContext):
    decoded = log_cmsg(ctx)

    session.account_name = (
        decoded.get("account")
        or decoded.get("username")
        or decoded.get("I")
    )
    session.realm_id = decoded.get("VirtualRealmID")

    if not session.account_name:
        Logger.error("[WorldHandlers] AUTH_SESSION missing account name")
        return 1, None

    account_id = DatabaseConnection.get_account_id_by_username(session.account_name)
    if account_id is None:
        Logger.error(f"[WorldHandlers] Unknown account '{session.account_name}'")
        return 1, None

    session.account_id = account_id
    session.player_guid = None
    session.world_guid = None
    session.char_guid = None
    session.player_name = None
    session.addons, session.banned_addons = prepare_session_addons(decoded.get("addons") or [])
    session.addon_trailing_value = int(decoded.get("addons_crc", 0) or 0)
    _reset_login_flow_state(session)
    _set_login_state(session, LoginState.AUTHED)

    Logger.info(
        f"[WorldHandlers] AUTH_SESSION account={session.account_name} "
        f"account_id={session.account_id} realm_id={session.realm_id} "
        f"addons={len(session.addons)} banned={len(session.banned_addons)}"
    )

    login_ctx = _build_world_login_context(session)
    return 0, build_char_screen_packets(login_ctx)


@register("CMSG_ENUM_CHARACTERS")
def handle_enum_characters(session, ctx: PacketContext):
    account_id = session.account_id
    realm_id = session.realm_id

    if account_id is None or realm_id is None:
        raise RuntimeError(
            "[WorldHandlers] Missing session account_id or realm_id "
            f"(account_id={account_id}, realm_id={realm_id})"
        )

    payload = build_ENUM_CHARACTERS_RESULT(
        account_id=account_id,
        realm_id=realm_id,
    )
    _set_login_state(session, LoginState.CHAR_SCREEN)
    return 0, [("SMSG_ENUM_CHARACTERS_RESULT", payload)]




@register("CMSG_PLAYER_LOGIN")
def handle_player_login(session, ctx: PacketContext):
    payload = ctx.payload
    log_cmsg(ctx)
    Logger.info("[LOGIN] player entering world")

    login_guid = None
    if len(payload) == 6:
        login_guid = int.from_bytes(payload, "little", signed=False)
    elif len(payload) >= 6:
        login_guid = int.from_bytes(payload[:6], "little", signed=False)

    session.account_data = {}
    session.account_data_times = {i: 0 for i in range(8)}
    session.account_data_mask = 0
    load_global_account_data(session)

    char_guid = _resolve_login_character_guid(
        login_guid=login_guid,
        payload=payload,
        account_id=session.account_id,
        realm_id=session.realm_id,
        account_name=getattr(session, "account_name", None),
    )
    if char_guid is None:
        Logger.error("[WorldHandlers] CMSG_PLAYER_LOGIN could not resolve selected character")
        return 1, None

    realm_id = session.realm_id
    selected_world_guid = int(
        GuidHelper.make(
            high=HighGuid.PLAYER,
            realm=int(realm_id or 0),
            low=int(char_guid or 0),
        )
    )

    session.player_guid = selected_world_guid
    session.world_guid = selected_world_guid
    session.char_guid = char_guid
    session.active_mover_guid = selected_world_guid

    load_character_account_data(session)
    session.account_data_mask = account_data_mask_for_types(PER_CHARACTER_ACCOUNT_DATA_TYPES)

    Logger.info(
        "[GUID MODE]\n"
        f"selected_guid = 0x{selected_world_guid:X}\n"
        f"session_guid = 0x{int(session.world_guid or 0):X}"
    )
    Logger.info(f"[GUID MODE ACTIVE] player_guid=0x{int(session.player_guid or 0):X}")

    row = DatabaseConnection.get_character(char_guid, realm_id)
    if not row:
        Logger.error(f"[WorldHandlers] Character not found guid={char_guid} realm={realm_id}")
        return 1, None

    stored_race = int(getattr(row, "race", 0) or 0)
    remapped_race = int(_SANDBOX_RACE_REMAP.get(stored_race, stored_race))
    if remapped_race != stored_race:
        try:
            row.race = remapped_race
            DatabaseConnection.chars().commit()
            Logger.info(
                "[LOGIN] sandbox race remap guid=%s stored=%s active=%s",
                int(char_guid),
                int(stored_race),
                int(remapped_race),
            )
        except Exception as exc:
            DatabaseConnection.chars().rollback()
            Logger.warning(
                "[LOGIN] sandbox race remap failed guid=%s stored=%s active=%s: %s",
                int(char_guid),
                int(stored_race),
                int(remapped_race),
                exc,
            )
            row.race = remapped_race

    session._character_row = row
    selected_name = str(getattr(row, "name", "") or f"Player{char_guid}")

    Logger.info(
        f"[WorldHandlers] PLAYER_LOGIN selected name={selected_name} "
        f"char_guid={char_guid} realm={realm_id}"
    )

    loaded_position = position_from_row(row)
    normalized_loaded_position = normalize_position(correct_z_if_invalid(loaded_position), safe_z=True)

    if normalized_loaded_position is None:
        Logger.warning(
            "[POS_SAVE] invalid DB position on login player=%s raw=%s; falling back to origin",
            int(char_guid),
            format_position(loaded_position),
        )
        normalized_loaded_position = Position(
            map=int(getattr(row, "map", 0) or 0),
            x=0.0,
            y=0.0,
            z=0.0,
            orientation=0.0,
        )

    session.zone = int(row.zone or 0)
    session.current_area = int(session.zone)
    from server.modules.handlers.world.position.publication import publish_absolute

    publish_absolute(
        session,
        map_id=int(row.map or 0),
        instance_id=int(row.instance_id or 0),
        x=float(normalized_loaded_position.x),
        y=float(normalized_loaded_position.y),
        z=float(normalized_loaded_position.z),
        orientation=float(normalized_loaded_position.orientation),
        resolve_area=True,
    )

    Logger.info(
        "[Position] load guid=%s name=%s map=%s zone=%s area=%s x=%.3f y=%.3f z=%.3f o=%.3f",
        int(char_guid),
        selected_name,
        int(session.map_id),
        int(session.zone),
        int(session.current_area),
        float(session.x),
        float(session.y),
        float(session.z),
        float(session.orientation),
    )

    from server.modules.handlers.world.opcodes import npc_interaction

    npc_interaction.restore_homebind_from_database(session)

    capture_persist_position_from_session(session)
    remember_saved_position(session)

    DatabaseConnection.save_character_online_state(
        int(char_guid),
        int(realm_id),
        online=1,
    )

    session.level = int(row.level or 1)
    session.class_id = int(row.class_ or 0)
    session.race = int(row.race or 0)
    session.gender = int(row.gender or 0)
    session.cinematic_played = int(getattr(row, "cinematic", _CINEMATIC_OFF) or _CINEMATIC_OFF)
    session.pending_cinematic_id = _resolve_pending_cinematic_id(session.race, session.cinematic_played)

    spells_handlers._restore_default_movement_speeds(session)

    session.is_mounted = False
    session.mount_spell = None
    session.active_auras = {}
    session.active_mount_aura_spell_id = None
    session.active_mount_aura_slot = 0
    _reset_morph_state(session, session.race, session.gender)
    _reset_loaded_world_object_state(session)

    session.money = int(row.money or 0)
    session.health = int(row.health or 1)

    session.display_power, session.power_primary, session.max_power_primary = _resolve_primary_power_for_row(
        row,
        session.class_id,
    )

    session.faction_template = int(PLAYER_FACTION_TEMPLATE_BY_RACE.get(session.race, 0))

    session.player_bytes = int(row.playerBytes or 0)
    session.player_bytes2 = int(row.playerBytes2 or 0)
    session.player_flags = int(row.playerFlags or 0)
    session.unit_flags = int(getattr(session, "unit_flags", 0) or 0)
    session.mount_display_id = 0

    session.player_name = selected_name

    session.equipment_cache_raw = [
        int(value)
        for value in str(getattr(row, "equipmentCache", "") or "").split()
        if value.strip()
    ]

    session.explored_zones_raw = str(getattr(row, "exploredZones", "") or "")
    session.taximask_raw = str(getattr(row, "taximask", "") or "")
    session.map_cheat_enabled = False
    session.taxi_cheat_enabled = False
    session.chosen_title = int(getattr(row, "chosenTitle", 0) or 0)
    session.known_titles_raw = str(getattr(row, "knownTitles", "") or "")

    inventory_state = refresh_session_inventory(session)
    has_equipped_items = any(
        int(getattr(item, "bag", -1)) == 0 and 0 <= int(getattr(item, "slot", -1)) < 19
        for item in getattr(inventory_state, "items_by_guid", {}).values()
    )
    if not has_equipped_items:
        chars_db = None
        try:
            from server.modules.handlers.world.characters.characters import _seed_character_starting_inventory

            chars_db = DatabaseConnection.chars()
            seeded_items = _seed_character_starting_inventory(
                chars_db,
                int(char_guid),
                int(session.race),
                int(session.class_id),
                int(session.gender),
            )
            if seeded_items:
                chars_db.commit()
                Logger.info(
                    "[WorldLogin] backfilled %s starting inventory items guid=%s",
                    int(seeded_items),
                    int(char_guid),
                )
                refresh_session_inventory(session)
        except Exception as exc:
            if chars_db is not None:
                try:
                    chars_db.rollback()
                except Exception:
                    pass
            Logger.warning(
                "[WorldLogin] starting inventory backfill failed guid=%s: %s",
                int(char_guid),
                exc,
            )
    attach_session_to_world_state(session, map_id=int(session.map_id))

    spells_handlers.initialize_session_spells(session, int(char_guid))
    spells_handlers.restore_persisted_mount_state(session, int(char_guid), int(realm_id))

    session.action_buttons = DatabaseConnection.get_character_action_buttons(char_guid)

    session.phase_data = {}
    session.world_states = {}
    session.single_world_state = {}
    refresh_region_weather(session)

    session.server_time = int(time.time())
    session.game_time = pack_wow_game_time(
        session.server_time + int(getattr(session, "time_offset", 0) or 0)
    )

    session.time_speed = float(getattr(session, "time_speed", 0.01666667) or 0.01666667)
    session.time_sync_seq = 0

    _reset_login_flow_state(
        session,
        preserve_loading_screen_done=bool(getattr(session, "loading_screen_done", False)),
    )

    from server.modules.handlers.world.runtime.world_attachment import (
        load_saved_world_attachment,
        prepare_login_world_attachment,
    )

    load_saved_world_attachment(session, row)
    if prepare_login_world_attachment(session):
        session.zone = int(
            resolve_zone_from_position(
                int(session.map_id),
                float(session.x),
                float(session.y),
            ) or int(session.zone or 0)
        )
        session.current_area = int(
            resolve_area_from_position(
                int(session.map_id),
                float(session.x),
                float(session.y),
            ) or int(session.zone or 0)
        )

    from server.modules.handlers.world.taxi_runtime import restore_persisted_taxi

    restore_persisted_taxi(session, getattr(row, "taxi_path", None))

    _resolve_session_ids(session)
    _set_login_state(session, LoginState.PLAYER_LOGIN)

    achievement_login_responses = initialize_session_achievements(session)

    Logger.success(
        f"[WorldHandlers] PLAYER_LOGIN name={session.player_name} "
        f"char_guid={char_guid} map={session.map_id} zone={session.zone} realm={realm_id}"
    )

    login_ctx = _build_world_login_context(session)

    responses: list[tuple[str, bytes]] = []
    responses.extend(build_player_login_packets(login_ctx))
    responses.extend(achievement_login_responses)

    if getattr(session, "loading_screen_done", False):
        Logger.info("[WorldHandlers] PLAYER_LOGIN consuming deferred LOADING_SCREEN_NOTIFY show=0")
        responses.extend(_queue_world_bootstrap_transition(session, login_ctx))

    Logger.debug("[LOGIN] sending init packet sequence")
    Logger.info("[WorldHandlers] PLAYER_LOGIN queued player login bundle")

    return 0, responses

@register("CMSG_LOADING_SCREEN_NOTIFY")
def handle_loading_screen_notify(session, ctx: PacketContext):
    handler_started = time.monotonic()
    trace_id = str(getattr(session, "loading_screen_trace_id", "") or "")
    if not trace_id:
        trace_id = (
            f"{int(getattr(session, 'char_guid', 0) or 0)}-"
            f"{int(handler_started * 1000.0)}"
        )
    session.loading_screen_trace_id = trace_id
    Logger.info(
        "[LoadingScreenTrace] trace_id=%s stage=handler event=entering opcode=%s",
        trace_id,
        str(getattr(ctx, "name", "CMSG_LOADING_SCREEN_NOTIFY")),
    )
    decode_started = time.monotonic()
    Logger.info(
        "[LoadingScreenTrace] trace_id=%s stage=decode event=entering",
        trace_id,
    )
    try:
        decoded = log_cmsg(ctx)
    except Exception as exc:
        Logger.info(
            "[LoadingScreenTrace] trace_id=%s stage=decode event=exception "
            "elapsed_ms=%.3f error=%s",
            trace_id,
            (time.monotonic() - decode_started) * 1000.0,
            str(exc),
        )
        raise
    Logger.info(
        "[LoadingScreenTrace] trace_id=%s stage=decode event=leaving elapsed_ms=%.3f",
        trace_id,
        (time.monotonic() - decode_started) * 1000.0,
    )
    showing = _decode_loading_screen_showing(decoded, ctx.payload)
    _resolve_session_ids(session)

    from server.modules.handlers.world.teleport.transition import (
        current_near_teleport_is_owned,
        mark_world_transition_loading_started,
    )

    if current_near_teleport_is_owned(session):
        Logger.info(
            "[WorldHandlers] LOADING_SCREEN_NOTIFY ignored during current "
            "near teleport generation=%s",
            int(getattr(session, "world_transition_generation", 0) or 0),
        )
        return 0, None

    session.loading_screen_visible = bool(showing)
    if showing:
        mark_world_transition_loading_started(session)
        _set_login_state(session, LoginState.LOADING_SCREEN)
        Logger.info("[WorldHandlers] LOADING_SCREEN_NOTIFY show=1")
        Logger.info(
            "[LoadingScreenTrace] trace_id=%s stage=handler event=leaving "
            "elapsed_ms=%.3f reason=showing packets=0",
            trace_id,
            (time.monotonic() - handler_started) * 1000.0,
        )
        return 0, None

    if (
        _is_pre_player_login_state(session.login_state)
        or not getattr(session, "char_guid", None)
        or not getattr(session, "world_guid", None)
    ):
        session.loading_screen_done = True
        Logger.info(
            f"[WorldHandlers] LOADING_SCREEN_NOTIFY show=0 deferred until PLAYER_LOGIN "
            f"(state={session.login_state.value if session.login_state else 'None'})"
        )
        Logger.info(
            "[LoadingScreenTrace] trace_id=%s stage=handler event=leaving "
            "elapsed_ms=%.3f reason=deferred packets=0",
            trace_id,
            (time.monotonic() - handler_started) * 1000.0,
        )
        return 0, None

    if session.login_state not in {
        LoginState.PLAYER_LOGIN,
        LoginState.LOADING_SCREEN,
        LoginState.WORLD_BOOTSTRAP,
        LoginState.IN_WORLD,
    }:
        Logger.info(
            f"[WorldHandlers] LOADING_SCREEN_NOTIFY ignored outside login flow "
            f"(state={session.login_state.value if session.login_state else 'None'})"
        )
        Logger.info(
            "[LoadingScreenTrace] trace_id=%s stage=handler event=leaving "
            "elapsed_ms=%.3f reason=invalid_state packets=0",
            trace_id,
            (time.monotonic() - handler_started) * 1000.0,
        )
        return 0, None
    if getattr(session, "teleport_pending", False):
        if bool(getattr(session, "_worldporttest_active", False)):
            Logger.info(
                "[WorldportTest] loading_notify player=%s map=%s",
                int(getattr(session, "char_guid", 0) or 0),
                int(getattr(session, "map_id", 0) or 0),
            )
        Logger.info(
            f"[WorldHandlers] LOADING_SCREEN_NOTIFY show=0 completing teleport "
            f"destination={getattr(session, 'teleport_destination', None)}"
        )
        _taxi_xmap_debug(
            "[TAXI_XMAP_DEBUG] loading_screen_complete player=%s map=%s "
            "destination=%s phase=%s pending=%s",
            int(getattr(session, "char_guid", 0) or 0),
            int(getattr(session, "map_id", 0) or 0),
            str(getattr(session, "teleport_destination", "") or ""),
            str(getattr(getattr(session, "taxi_state", None), "phase", "")),
            getattr(session, "pending_taxi_transfer", None),
        )
        try:
            responses = ensure_worldport_bootstrap_started(
                session,
                "loading_screen_notify",
                expected_generation=int(
                    getattr(
                        session,
                        "world_transition_loading_generation",
                        0,
                    )
                    or 0
                ),
                expected_owner=str(
                    getattr(session, "world_transition_owner", "") or ""
                ),
            )
        except Exception as exc:
            Logger.info(
                "[LoadingScreenTrace] trace_id=%s stage=bootstrap event=exception "
                "elapsed_ms=%.3f error=%s",
                trace_id,
                (time.monotonic() - handler_started) * 1000.0,
                str(exc),
            )
            raise
        Logger.info(
            "[LoadingScreenTrace] trace_id=%s stage=handler event=leaving "
            "elapsed_ms=%.3f reason=teleport_complete packets=%s empty=%s",
            trace_id,
            (time.monotonic() - handler_started) * 1000.0,
            len(responses),
            "true" if not responses else "false",
        )
        if bool(getattr(session, "_worldporttest_active", False)):
            Logger.info(
                "[WorldportTest] bootstrap_complete player=%s map=%s packets=%s",
                int(getattr(session, "char_guid", 0) or 0),
                int(getattr(session, "map_id", 0) or 0),
                len(responses),
            )
        return 0, responses
    if getattr(session, "post_loading_sent", False):
        pending = getattr(session, "pending_transport_transfer", None)
        log_transport_event(
            TransportDebugEvent.BOOTSTRAP_SKIPPED,
            transport_guid=int(
                (pending.get("destination_guid", 0) or 0)
                if isinstance(pending, dict)
                else 0
            ),
            player_guid=int(getattr(session, "char_guid", 0) or 0),
            reason="duplicate_loading_completion",
        )
        Logger.info("[WorldHandlers] LOADING_SCREEN_NOTIFY show=0 after bootstrap; ignoring duplicate")
        Logger.info(
            "[LoadingScreenTrace] trace_id=%s stage=handler event=leaving "
            "elapsed_ms=%.3f reason=duplicate packets=0",
            trace_id,
            (time.monotonic() - handler_started) * 1000.0,
        )
        return 0, None

    login_ctx = _build_world_login_context(session)
    responses = _queue_world_bootstrap_transition(session, login_ctx)
    Logger.info(
        "[LoadingScreenTrace] trace_id=%s stage=handler event=leaving "
        "elapsed_ms=%.3f reason=normal_bootstrap packets=%s empty=%s",
        trace_id,
        (time.monotonic() - handler_started) * 1000.0,
        len(responses),
        "true" if not responses else "false",
    )
    return 0, responses


@register("CMSG_OPENING_CINEMATIC")
def handle_opening_cinematic(session, ctx: PacketContext):
    Logger.info("[CINEMATIC] CMSG_OPENING_CINEMATIC")
    responses = _build_pending_cinematic_response(session)
    return 0, responses or None


@register("CMSG_COMPLETE_CINEMATIC")
def handle_complete_cinematic(session, ctx: PacketContext):
    Logger.info("[CINEMATIC] CMSG_COMPLETE_CINEMATIC")
    session.pending_cinematic_id = 0
    session.cinematic_played = _CINEMATIC_PLAYED
    DatabaseConnection.save_character_cinematic_state(
        int(getattr(session, "char_guid", 0) or 0),
        int(getattr(session, "realm_id", 0) or 0),
        _CINEMATIC_PLAYED,
    )
    return 0, None


@register("CMSG_SET_ACTIVE_MOVER")
def handle_set_active_mover(session, ctx: PacketContext):
    Logger.info(
        f"[WorldHandlers] ACTIVE_MOVER received for session.char_guid={session.char_guid} "
        f"session.world_guid=0x{int(session.world_guid or 0):016X}"
    )
    if session.login_state != LoginState.WORLD_BOOTSTRAP:
        Logger.info(
            f"[WorldHandlers] ACTIVE_MOVER ignored outside WORLD_BOOTSTRAP "
            f"(state={session.login_state.value if session.login_state else 'None'})"
        )
        return 0, None

    _assert_player_object_sent(session)
    from server.modules.handlers.world.runtime.world_attachment import (
        complete_login_world_attachment,
    )

    complete_login_world_attachment(session)
    _set_login_state(session, LoginState.IN_WORLD)
    player = get_player_runtime_store().add(Player.from_session(session))
    responses: list[tuple[str, bytes]] = []
    destination_refresh_pending = bool(
        getattr(
            session,
            "_worldport_destination_visibility_refresh_pending",
            False,
        )
    )
    if destination_refresh_pending:
        session._worldport_destination_visibility_refresh_pending = False
    from server.modules.handlers.world.world_refresh import get_world_refresh_service
    from server.modules.handlers.world.opcodes import movement as movement_handlers

    responses.extend(
        get_world_refresh_service().refresh_after_login(
            session,
            context="login-active-mover-visibility",
            synchronize_player_visibility=True,
            stream_world_objects=False,
            _visibility_sync=sync_player_visibility,
        )
    )
    sync_all_players_on_map(int(player.map_id))
    if destination_refresh_pending:
        responses.extend(
            get_world_refresh_service().refresh_after_login(
                session,
                context="worldport-active-mover-commit",
                synchronize_player_visibility=False,
                stream_world_objects=True,
                _object_refresh=(
                    movement_handlers.stream_world_objects_after_teleport
                ),
            )
        )
    responses.extend(_build_pending_cinematic_response(session))
    motd = str(getattr(_build_world_login_context(session), "motd", "") or "").strip()
    if motd and not session.chat_motd_sent:
        session.chat_motd_sent = True
        # Fallback if we need to restore screen MOTD:
        # notification_payload = build_motd_notification_payload(motd)
        # Logger.info("[WorldHandlers] ACTIVE_MOVER acknowledged; sending MOTD notification fallback")
        # responses.append(("SMSG_NOTIFICATION", notification_payload))
        Logger.info("[WorldHandlers] ACTIVE_MOVER acknowledged; sending MOTD as system chat")
        responses.append(("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(motd)))

    if not getattr(session, "account_settings_sent", False):
        session.account_settings_sent = True
        if SEND_ACCOUNT_DATA_TO_CLIENT:
            Logger.info("[WorldHandlers] ACTIVE_MOVER acknowledged; waiting for client account-data requests")
        else:
            Logger.info("[WorldHandlers] ACTIVE_MOVER acknowledged; suppressing account settings packets")

    if getattr(session, "_far_worldport_known_spells_sent", False):
        session._far_worldport_known_spells_sent = False
        Logger.info("[WorldLogin] ACTIVE_MOVER skipping far-worldport known-spells replay")
    else:
        responses.extend(spells_handlers.build_active_mover_spell_sync_responses(session))
    mount_restore_packets = spells_handlers.build_login_mount_restore_responses(session)
    if mount_restore_packets:
        Logger.info(
            "[WorldLogin] ACTIVE_MOVER sending %s mount restore packets",
            len(mount_restore_packets),
        )
        responses.extend(mount_restore_packets)
    from server.modules.handlers.world.taxi_runtime import activate_restored_taxi

    responses.extend(activate_restored_taxi(session))
    Logger.debug("[LOGIN] active mover acknowledged")

    if responses:
        return 0, responses

    responses.extend(build_minimal_post_timesync_account_packets(session))
    Logger.info("[WorldHandlers] ACTIVE_MOVER acknowledged; no additional bootstrap packets sent")
    return 0, None


@register("CMSG_READY_FOR_ACCOUNT_DATA_TIMES")
def handle_ready_for_account_data_times(session, data):
    return misc_handlers.handle_ready_for_account_data_times(session, data)


@register("CMSG_REQUEST_ACCOUNT_DATA")
def handle_request_account_data(session, data):
    return misc_handlers.handle_request_account_data(session, data)


@register("CMSG_UPDATE_ACCOUNT_DATA")
def handle_update_account_data(session, data):
    return misc_handlers.handle_update_account_data(session, data)


@register("CMSG_REQUEST_HOTFIX")
def handle_request_hotfix(session, data):
    return misc_handlers.handle_request_hotfix(session, data)


@register("CMSG_CHAR_CREATE")
def handle_char_create(session, data):
    return handle_char_create_packet(data)


@register("CMSG_CHAR_DELETE")
def handle_char_delete(session, data):
    return handle_char_delete_packet(data)


@register("CMSG_REORDER_CHARACTERS")
def handle_reorder_characters(session, data):
    return handle_reorder_characters_packet(data)
