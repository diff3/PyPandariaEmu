from __future__ import annotations

import time
from typing import Optional, Tuple

from DSL.modules.EncoderHandler import EncoderHandler
from shared.Logger import Logger
from server.modules.handlers.world.login.packets import (
    handle_CMSG_REQUEST_HOTFIX as handle_request_hotfix_packet,
)
from server.modules.handlers.world.account_data import (
    DB_ACCOUNT_DATA_137_TYPES,
    GLOBAL_ACCOUNT_DATA_STORAGE_TYPES,
    GLOBAL_ACCOUNT_DATA_TYPES,
    SEND_ACCOUNT_DATA_TO_CLIENT,
    USE_DB_ACCOUNT_DATA_137,
    account_data_mask_for_types,
    account_data_text_for_type,
    account_data_times_list_for_types,
    build_minimal_post_timesync_account_packets,
    build_update_account_data_payload,
    decode_account_data_request_type,
    decode_account_data_update_payload,
    flush_account_data_types_to_db,
    is_global_account_data_type,
    load_character_account_data,
    load_global_account_data,
    normalize_account_data_text,
    persist_account_data_entry,
)
from server.modules.protocol.PacketContext import PacketContext
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.handlers.world.login.packets import build_login_packet
from server.modules.handlers.world.dispatcher import register
from server.modules.handlers.world.opcodes import login as login_handlers
from server.modules.handlers.world.opcodes.movement import (
    _capture_persist_position_from_session as capture_persist_position_from_session,
    _mark_position_dirty as mark_position_dirty,
    _save_session_position as save_session_position,
)
from server.modules.handlers.world.packet_logging import log_cmsg
from server.modules.handlers.world.state.runtime import advance_global_time, refresh_region_weather

def _build_request_cemetery_list_response_payload(
    cemetery_ids: list[int] | None = None,
    *,
    is_microdungeon: int = 0,
) -> bytes:
    cemetery_ids = [int(cemetery_id) for cemetery_id in (cemetery_ids or [])]
    return EncoderHandler.encode_packet(
        "SMSG_REQUEST_CEMETERY_LIST_RESPONSE",
        {
            "is_microdungeon": int(is_microdungeon),
            "count": len(cemetery_ids),
            "cemetery_ids": cemetery_ids,
        },
    )


@register("CMSG_PING")
def handle_ping(session, ctx: PacketContext) -> Tuple[int, Optional[bytes]]:
    decoded = log_cmsg(ctx)
    ping_val = int(decoded.get("ping_id", 0) or 0)
    try:
        pong_payload = EncoderHandler.encode_packet("SMSG_PONG", {"ping_id": ping_val})
        return 0, ("SMSG_PONG", pong_payload)
    except Exception as exc:
        Logger.error(f"[WorldHandlers] SMSG_PONG encode failed: {exc}")
        return 1, None


@register("CMSG_LOGOUT_REQUEST")
def handle_logout_request(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    log_cmsg(ctx)
    Logger.info("[WorldHandlers] CMSG_LOGOUT_REQUEST")
    if USE_DB_ACCOUNT_DATA_137:
        flush_account_data_types_to_db(session, tuple(DB_ACCOUNT_DATA_137_TYPES), seed_defaults=True)
    capture_persist_position_from_session(session)
    mark_position_dirty(session)
    save_session_position(session, reason="logout", online=0, force=True)

    try:
        logout_response = EncoderHandler.encode_packet(
            "SMSG_LOGOUT_RESPONSE",
            {
                "logout_result": 0,
                "instant_logout": 1,
            },
        )
    except Exception as exc:
        Logger.error(f"[WorldHandlers] SMSG_LOGOUT_RESPONSE encode failed: {exc}")
        return 1, None

    return 0, [
        ("SMSG_LOGOUT_RESPONSE", logout_response),
        ("SMSG_LOGOUT_COMPLETE", b""),
    ]


@register("CMSG_TIME_SYNC_RESPONSE")
def handle_time_sync_response(session, ctx: PacketContext):
    decoded = ctx.decoded or {}
    seq = decoded.get("sequence_id", 0)
    client_ticks = decoded.get("client_ticks", 0)

    session.last_time_sync_seq = seq
    session.time_sync_ok = True
    advance_global_time(1)
    refresh_region_weather(session)

    Logger.success(f"[TIME_SYNC] OK seq={seq} client_ticks={client_ticks}")

    if (
        int(getattr(session, "char_guid", 0) or 0) == 2
        and int(getattr(session, "map_id", 0) or 0) == 1
        and int(getattr(session, "zone", 0) or 0) == 876
        and int(getattr(session, "skyfire_login_stage", 0) or 0) == 2
    ):
        Logger.info("[WorldHandlers] TIME_SYNC_RESPONSE received after post-time-sync block")
        session.skyfire_login_stage = 3
        Logger.info("[WorldHandlers] TIME_SYNC_RESPONSE advanced SkyFire GMIsland stage 3")
        return 0, None

    return 0, None


@register("CMSG_DISCARDED_TIME_SYNC_ACKS")
def handle_discarded_time_sync_acks(session, ctx: PacketContext):
    Logger.info("[TIME_SYNC] Client discarded pending time sync ACKs")
    return 0, None


@register("CMSG_REQUEST_ACCOUNT_DATA")
def handle_request_account_data(session, ctx: PacketContext):
    if USE_DB_ACCOUNT_DATA_137:
        account_id = int(getattr(session, "account_id", 0) or 0)
        char_guid = int(getattr(session, "char_guid", 0) or 0)
        if account_id:
            load_global_account_data(session, account_id)
        if char_guid:
            load_character_account_data(session, char_guid)
        Logger.info("[ACCOUNT_DATA] mode=db request using preloaded global+character data")

    data_type = decode_account_data_request_type(ctx.payload)
    Logger.info(f"[ACCOUNT_DATA] request type={data_type} raw={ctx.payload.hex()}")

    if not SEND_ACCOUNT_DATA_TO_CLIENT:
        Logger.info(f"[ACCOUNT_DATA] suppressing SMSG_UPDATE_ACCOUNT_DATA type={data_type}")
        return 0, None

    if is_global_account_data_type(int(data_type)):
        load_global_account_data(session)
    else:
        load_character_account_data(session)

    stored_text = session.account_data.get(int(data_type))
    if stored_text is None:
        stored_text = account_data_text_for_type(int(data_type), str(session.account_name or ""))

    normalized_text = normalize_account_data_text(int(data_type), str(stored_text or ""))
    if normalized_text != str(stored_text or ""):
        stored_text = normalized_text
        session.account_data[int(data_type)] = stored_text
        stored_timestamp = int(session.account_data_times.get(int(data_type)) or time.time())
        session.account_data_times[int(data_type)] = stored_timestamp
        persist_account_data_entry(session, int(data_type), stored_text, stored_timestamp)

    stored_timestamp = session.account_data_times.get(int(data_type))
    response = build_update_account_data_payload(
        int(data_type),
        str(stored_text or ""),
        timestamp=int(stored_timestamp) if stored_timestamp is not None else None,
    )
    return 0, [("SMSG_UPDATE_ACCOUNT_DATA", response)]


@register("CMSG_REQUEST_CEMETERY_LIST")
def handle_request_cemetery_list(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.info("[WorldHandlers] CMSG_REQUEST_CEMETERY_LIST")
    response = _build_request_cemetery_list_response_payload([])
    return 0, [("SMSG_REQUEST_CEMETERY_LIST_RESPONSE", response)]


@register("CMSG_REQUEST_PLAYED_TIME")
def handle_request_played_time(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    row = None
    if session.char_guid is not None and session.realm_id is not None:
        try:
            row = DatabaseConnection.get_character(int(session.char_guid), int(session.realm_id))
        except Exception as exc:
            Logger.warning(f"[WorldHandlers] REQUEST_PLAYED_TIME row lookup failed: {exc}")

    total_time = int(getattr(row, "totaltime", 0) or 0)
    level_time = int(getattr(row, "leveltime", 0) or 0)
    response = EncoderHandler.encode_packet(
        "SMSG_PLAYED_TIME",
        {
            "total_time": total_time,
            "level_time": level_time,
            "show_in_chat": 0,
        },
    )
    Logger.info(
        f"[WorldHandlers] CMSG_REQUEST_PLAYED_TIME total_time={total_time} "
        f"level_time={level_time}"
    )
    return 0, [("SMSG_PLAYED_TIME", response)]


@register("CMSG_QUERY_TIME")
def handle_query_time(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.info("[WorldHandlers] CMSG_QUERY_TIME")
    response = build_login_packet("SMSG_QUERY_TIME_RESPONSE", login_handlers._build_world_login_context(session))
    if response is None:
        Logger.error("[WorldHandlers] Missing builder for SMSG_QUERY_TIME_RESPONSE")
        return 1, None
    return 0, [("SMSG_QUERY_TIME_RESPONSE", response)]


@register("CMSG_REQUEST_FORCED_REACTIONS")
def handle_request_forced_reactions(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.info("[WorldHandlers] CMSG_REQUEST_FORCED_REACTIONS")
    response = build_login_packet("SMSG_SET_FORCED_REACTIONS", login_handlers._build_world_login_context(session))
    if response is None:
        Logger.error("[WorldHandlers] Missing builder for SMSG_SET_FORCED_REACTIONS")
        return 1, None
    return 0, [("SMSG_SET_FORCED_REACTIONS", response)]


@register("CMSG_WORLD_STATE_UI_TIMER_UPDATE")
def handle_world_state_ui_timer_update(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    Logger.info("[WorldHandlers] CMSG_WORLD_STATE_UI_TIMER_UPDATE")
    response = build_login_packet("SMSG_UI_TIME", login_handlers._build_world_login_context(session))
    if response is None:
        Logger.error("[WorldHandlers] Missing builder for SMSG_UI_TIME")
        return 1, None
    return 0, [("SMSG_UI_TIME", response)]


@register("CMSG_REQUEST_HOTFIX")
def handle_request_hotfix(session, ctx: PacketContext):
    Logger.info(
        f"[WorldHandlers] CMSG_REQUEST_HOTFIX passthrough "
        f"(state={session.login_state.value if session.login_state else 'None'})"
    )
    return handle_request_hotfix_packet(ctx)


@register("CMSG_READY_FOR_ACCOUNT_DATA_TIMES")
def handle_ready_for_account_data_times(session, ctx: PacketContext):
    Logger.info("[WORLD] Client ready for account data times")

    if USE_DB_ACCOUNT_DATA_137:
        account_id = int(getattr(session, "account_id", 0) or 0)
        char_guid = int(getattr(session, "char_guid", 0) or 0)
        if account_id:
            load_global_account_data(session, account_id)
        if char_guid:
            load_character_account_data(session, char_guid)
        data_types = tuple(GLOBAL_ACCOUNT_DATA_STORAGE_TYPES)
        Logger.info(
            "[ACCOUNT_DATA] mode=db times types=%s"
            % ",".join(str(v) for v in data_types)
        )
    else:
        data_types = tuple(GLOBAL_ACCOUNT_DATA_TYPES)
        load_global_account_data(session)

    if not SEND_ACCOUNT_DATA_TO_CLIENT:
        Logger.info("[WORLD] suppressing SMSG_ACCOUNT_DATA_TIMES")
        return 0, None

    now = int(time.time())
    payload = EncoderHandler.encode_packet(
        "SMSG_ACCOUNT_DATA_TIMES",
        {
            "has_account_data_times": 1,
            "timestamps": account_data_times_list_for_types(session, now, data_types),
            "mask": account_data_mask_for_types(data_types),
            "server_time": now,
        },
    )
    session.account_data_times_sent = True
    return 0, [("SMSG_ACCOUNT_DATA_TIMES", payload)]


@register("CMSG_UPDATE_ACCOUNT_DATA")
def handle_update_account_data(session, ctx: PacketContext):
    log_cmsg(ctx)
    parsed = decode_account_data_update_payload(ctx.payload)

    data_type = int(parsed.get("type") or 0)
    timestamp = int(parsed.get("timestamp") or 0)
    account_text = str(parsed.get("account_data") or "")

    if 0 <= data_type < 8:
        session.account_data[data_type] = account_text
        session.account_data_times[data_type] = timestamp
        if account_text:
            session.account_data_mask |= (1 << data_type)
        else:
            session.account_data_mask &= ~(1 << data_type)
        persist_account_data_entry(session, data_type, account_text, timestamp)

    preview = account_text[:120].replace("\r", "\\r").replace("\n", "\\n")
    Logger.info(
        f"[ACCOUNT_DATA] update type={data_type} timestamp={timestamp} "
        f"decompressed_size={int(parsed.get('decompressed_size') or 0)} "
        f"compressed_size={int(parsed.get('compressed_size') or 0)} "
        f"stored_len={len(account_text)} preview={preview!r}"
    )

    error = parsed.get("error")
    if error:
        Logger.warning(f"[ACCOUNT_DATA] update parse warning={error}")
    warning = parsed.get("warning")
    if warning:
        Logger.warning(f"[ACCOUNT_DATA] update parse warning={warning}")

    return 0, None
