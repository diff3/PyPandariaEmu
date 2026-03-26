from __future__ import annotations

import time
from typing import Any, Optional, Tuple

from shared.Logger import Logger
from server.modules.protocol.PacketContext import PacketContext
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.guid import GuidHelper, HighGuid
from server.modules.handlers.world.characters.characters import (
    handle_CMSG_CHAR_CREATE as handle_char_create_packet,
    handle_CMSG_CHAR_DELETE as handle_char_delete_packet,
    handle_CMSG_REORDER_CHARACTERS as handle_reorder_characters_packet,
)
from server.modules.handlers.world.login.context import WorldLoginContext
from server.modules.handlers.world.login.packets import (
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
from server.session.world_session import LoginState
from server.modules.handlers.world.account_data import (
    PER_CHARACTER_ACCOUNT_DATA_TYPES,
    SEND_ACCOUNT_DATA_TO_CLIENT,
    account_data_mask_for_types,
    build_minimal_post_timesync_account_packets,
    load_character_account_data,
    load_global_account_data,
)
from server.modules.handlers.world.bootstrap import replay as bootstrap_replay
from server.modules.handlers.world.chat.codec import build_motd_notification_payload
from server.modules.handlers.world.constants.character_data import (
    DEFAULT_MAX_PRIMARY_POWER_BY_DISPLAY,
    PLAYER_DISPLAY_POWER_BY_CLASS,
    PLAYER_FACTION_TEMPLATE_BY_RACE,
)
from server.modules.handlers.world.dispatcher import register
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
from server.modules.handlers.world.state.runtime import attach_session_to_world_state, pack_wow_game_time


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
    session.teleport_destination = None


def _build_world_login_context(session) -> WorldLoginContext:
    ctx = WorldLoginContext.from_session(session)
    ctx.exact_0002_mode = str(bootstrap_replay.UPDATE_OBJECT_1773613176_0002_MODE or "barncastle")
    return ctx


def _is_pre_player_login_state(state: Optional[LoginState]) -> bool:
    return state in {None, LoginState.AUTHED, LoginState.CHAR_SCREEN}


def _queue_world_bootstrap_transition(session, ctx: WorldLoginContext) -> list[tuple[str, bytes]]:
    # TODO: Keep current packet ordering intact until world bootstrap is isolated from legacy replay helpers.
    if getattr(session, "post_loading_sent", False):
        Logger.info("[LOGIN] WORLD_BOOTSTRAP already queued; skipping duplicate")
        return []

    _set_login_state(session, LoginState.WORLD_BOOTSTRAP)
    Logger.debug("[LOGIN] sending init packet sequence")

    responses: list[tuple[str, bytes]] = []
    pre_update_packets = build_pre_update_object_packets(ctx)
    update_packets: list[tuple[str, bytes]] = []
    if not getattr(session, "player_object_sent", False):
        update_packets = bootstrap_replay.replay_movement_focus_sequence(session)
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
    for opcode_name, payload in post_update_packets:
        Logger.info(f"[WorldLogin] sending {opcode_name}")
        responses.append((opcode_name, payload))
    for opcode_name, payload in bootstrap_packets:
        if opcode_name == "SMSG_MOVE_SET_ACTIVE_MOVER":
            Logger.info("[WorldLoginExperiment] sending ACTIVE_MOVER")
        elif opcode_name == "SMSG_TIME_SYNC_REQUEST":
            Logger.info("[WorldLoginExperiment] sending TIME_SYNC_REQUEST")
        responses.append((opcode_name, payload))

    session.loading_screen_done = True
    session.post_loading_sent = True
    Logger.info("[LOGIN] WORLD_BOOTSTRAP queued replayed UPDATE_OBJECT sequence + minimal bootstrap bundle")
    return responses


def _queue_teleport_world_transition(session, ctx: WorldLoginContext) -> list[tuple[str, bytes]]:
    # TODO: Teleport bootstrap still shares movement replay/bootstrap helpers with legacy world init.
    _set_login_state(session, LoginState.WORLD_BOOTSTRAP)

    responses: list[tuple[str, bytes]] = []

    for opcode_name in (
        "SMSG_FEATURE_SYSTEM_STATUS",
        "SMSG_LOGIN_VERIFY_WORLD",
        "SMSG_LOGIN_SET_TIME_SPEED",
        "SMSG_BIND_POINT_UPDATE",
    ):
        payload = build_login_packet(opcode_name, ctx)
        if payload is None:
            continue
        Logger.info(f"[Teleport] sending {opcode_name}")
        responses.append((opcode_name, payload))

    Logger.info("[Teleport] replaying sniffed movement focus sequence")
    responses.extend(bootstrap_replay.replay_movement_focus_sequence(session))

    time_sync = build_login_packet("SMSG_TIME_SYNC_REQUEST", ctx)
    if time_sync is not None:
        Logger.info("[Teleport] sending SMSG_TIME_SYNC_REQUEST")
        responses.append(("SMSG_TIME_SYNC_REQUEST", time_sync))

    for opcode_name in (
        "SMSG_PHASE_SHIFT_CHANGE",
        "SMSG_INIT_WORLD_STATES",
        "SMSG_WEATHER",
        "SMSG_QUERY_TIME_RESPONSE",
        "SMSG_UI_TIME",
    ):
        payload = build_login_packet(opcode_name, ctx)
        if payload is None:
            continue
        Logger.info(f"[Teleport] sending {opcode_name}")
        responses.append((opcode_name, payload))

    session.loading_screen_done = True
    session.post_loading_sent = True
    session.teleport_pending = False
    session.teleport_destination = None
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
    _reset_login_flow_state(session)
    _set_login_state(session, LoginState.AUTHED)

    Logger.info(
        f"[WorldHandlers] AUTH_SESSION account={session.account_name} "
        f"account_id={session.account_id} realm_id={session.realm_id}"
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
    selected_name = str(getattr(row, "name", "") or f"Player{char_guid}")
    Logger.info(
        f"[WorldHandlers] PLAYER_LOGIN selected name={selected_name} "
        f"char_guid={char_guid} realm={realm_id}"
    )

    session.map_id = int(row.map or 0)
    session.zone = int(row.zone or 0)
    session.instance_id = int(row.instance_id or 0)

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

    session.x = float(normalized_loaded_position.x)
    session.y = float(normalized_loaded_position.y)
    session.z = float(normalized_loaded_position.z)
    session.orientation = float(normalized_loaded_position.orientation)
    Logger.info(
        "[Position] load guid=%s name=%s map=%s zone=%s x=%.3f y=%.3f z=%.3f o=%.3f",
        int(char_guid),
        selected_name,
        int(session.map_id),
        int(session.zone),
        float(session.x),
        float(session.y),
        float(session.z),
        float(session.orientation),
    )
    capture_persist_position_from_session(session)
    remember_saved_position(session)
    DatabaseConnection.save_character_online_state(
        int(char_guid),
        int(realm_id),
        online=1,
    )

    spells_handlers._restore_default_movement_speeds(session)
    session.is_mounted = False
    session.mount_spell = None

    session.level = int(row.level or 1)
    session.class_id = int(row.class_ or 0)
    session.race = int(row.race or 0)
    session.gender = int(row.gender or 0)

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
    session.equipment_cache_raw = [
        int(value)
        for value in str(getattr(row, "equipmentCache", "") or "").split()
        if value.strip()
    ]
    session.player_name = selected_name
    attach_session_to_world_state(session, map_id=int(session.map_id))

    spells_handlers.initialize_session_spells(session, int(char_guid))
    session.action_buttons = DatabaseConnection.get_character_action_buttons(char_guid)

    session.phase_data = {}
    session.world_states = {}
    session.single_world_state = {}
    session.weather = {}

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

    _resolve_session_ids(session)
    _set_login_state(session, LoginState.PLAYER_LOGIN)

    Logger.success(
        f"[WorldHandlers] PLAYER_LOGIN name={session.player_name} "
        f"char_guid={char_guid} map={session.map_id} zone={session.zone} realm={realm_id}"
    )

    login_ctx = _build_world_login_context(session)
    responses: list[tuple[str, bytes]] = []
    responses.extend(build_player_login_packets(login_ctx))
    if getattr(session, "loading_screen_done", False):
        Logger.info("[WorldHandlers] PLAYER_LOGIN consuming deferred LOADING_SCREEN_NOTIFY show=0")
        responses.extend(_queue_world_bootstrap_transition(session, login_ctx))

    Logger.debug("[LOGIN] sending init packet sequence")
    Logger.info("[WorldHandlers] PLAYER_LOGIN queued player login bundle")
    return 0, responses


@register("CMSG_LOADING_SCREEN_NOTIFY")
def handle_loading_screen_notify(session, ctx: PacketContext):
    decoded = log_cmsg(ctx)
    showing = _decode_loading_screen_showing(decoded, ctx.payload)
    _resolve_session_ids(session)

    session.loading_screen_visible = bool(showing)
    if showing:
        _set_login_state(session, LoginState.LOADING_SCREEN)
        Logger.info("[WorldHandlers] LOADING_SCREEN_NOTIFY show=1")
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
        return 0, None
    if getattr(session, "teleport_pending", False):
        Logger.info(
            f"[WorldHandlers] LOADING_SCREEN_NOTIFY show=0 completing teleport "
            f"destination={getattr(session, 'teleport_destination', None)}"
        )
        login_ctx = _build_world_login_context(session)
        responses = _queue_teleport_world_transition(session, login_ctx)
        return 0, responses
    if getattr(session, "post_loading_sent", False):
        Logger.info("[WorldHandlers] LOADING_SCREEN_NOTIFY show=0 after bootstrap; ignoring duplicate")
        return 0, None

    login_ctx = _build_world_login_context(session)
    responses = _queue_world_bootstrap_transition(session, login_ctx)
    return 0, responses


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
    _set_login_state(session, LoginState.IN_WORLD)
    responses: list[tuple[str, bytes]] = []
    motd = str(getattr(_build_world_login_context(session), "motd", "") or "").strip()
    if motd and not session.chat_motd_sent:
        session.chat_motd_sent = True
        notification_payload = build_motd_notification_payload(motd)
        Logger.info("[WorldHandlers] ACTIVE_MOVER acknowledged; sending MOTD notification fallback")
        responses.append(("SMSG_NOTIFICATION", notification_payload))

    if not getattr(session, "account_settings_sent", False):
        session.account_settings_sent = True
        if SEND_ACCOUNT_DATA_TO_CLIENT:
            Logger.info("[WorldHandlers] ACTIVE_MOVER acknowledged; waiting for client account-data requests")
        else:
            Logger.info("[WorldHandlers] ACTIVE_MOVER acknowledged; suppressing account settings packets")

    responses.extend(spells_handlers.build_active_mover_spell_sync_responses(session))
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
