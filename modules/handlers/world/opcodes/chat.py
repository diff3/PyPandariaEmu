from __future__ import annotations

import random
import time
from typing import Optional, Tuple

from DSL.modules.EncoderHandler import EncoderHandler
from shared.Logger import Logger
from shared.PathUtils import get_captures_root
from server.modules.protocol.PacketContext import PacketContext
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.handlers.world.login.packets import build_login_packet
from server.modules.handlers.world.bootstrap.replay import (
    build_single_u32_update_object_payload,
    send_raw_packet,
)
from server.modules.handlers.world.chat.router import chat_router
from server.modules.handlers.world.chat.codec import (
    CHAT_MSG_SAY,
    CHAT_MSG_WHISPER,
    CHAT_MSG_WHISPER_INFORM,
    CHAT_MSG_YELL,
    TEXT_EMOTE_TO_ANIM_EMOTE,
    build_raw_replay_messagechat_packet,
    decode_chat_message,
    encode_messagechat_payload,
    encode_skyfire_messagechat_system_payload,
    encode_text_emote_payload,
)
from server.modules.handlers.world.dispatcher import register
from server.modules.handlers.world.opcodes import login as login_handlers
from server.modules.handlers.world.opcodes import entities as entities_handlers
from server.modules.handlers.world.opcodes.movement import (
    _save_current_position_like_command as save_current_position_like_command,
)
from server.modules.handlers.world.packet_logging import log_cmsg
from server.modules.handlers.world.state.runtime import (
    broadcast_region_weather,
    broadcast_system_message,
    broadcast_world_time,
    pack_wow_game_time,
    resolve_weather_type,
)
from server.modules.handlers.world.teleport.runtime import teleport_player
from server.modules.handlers.world.teleport.teleport_service import (
    add_teleport as add_named_teleport,
    find_teleport,
    nearest_teleport,
    remove_teleport as remove_named_teleport,
    search_teleports,
)


# TODO: Move messagechat packet encoders and raw replay helpers out of legacy once
# entity/chat packet builders are isolated from the old monolith.
RAW_REPLAY_SAY_CHAT_PROFILE = None
USE_SYSTEM_CHAT_FALLBACK = True
RAW_SNIFFED_MESSAGECHAT_CAPTURE = "SMSG_MESSAGECHAT_1774505644_0004.json"
_UNIT_FIELD_ANIMTIER = 0x4C
_UNIT_FIELD_EMOTE_STATE = 0x59
_PLAYER_FIELD_PLAYER_FLAGS = 0xA2
_STAND_STATE_STANDING = 0
_STAND_STATE_SITTING = 1
_STAND_STATE_SLEEPING = 3
_STAND_STATE_KNEEL = 8
_PLAYER_FLAGS_AFK = 0x00000002
_PLAYER_FLAGS_DND = 0x00000004
_DEFAULT_AFK_MESSAGE = "Away from keyboard"
_DEFAULT_DND_MESSAGE = "Do not disturb"
_TEXT_EMOTE_TO_STAND_STATE = {
    59: _STAND_STATE_KNEEL,
    86: _STAND_STATE_SITTING,
    87: _STAND_STATE_SLEEPING,
    141: _STAND_STATE_STANDING,
}


def _notification_response(message: str) -> list[tuple[str, bytes]]:
    # Fallback if we need to restore center-screen notifications:
    # return [("SMSG_NOTIFICATION", build_motd_notification_payload(message))]
    return [("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(message))]


def _debug_feedback_response(message: str) -> list[tuple[str, bytes]]:
    # Fallback if we need both notification + system chat again:
    # return [
    #     ("SMSG_NOTIFICATION", build_motd_notification_payload(message)),
    #     ("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(message)),
    # ]
    return [("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(message))]


def _list_sniffed_messagechat_captures() -> list[str]:
    capture_dir = get_captures_root(focus=True) / "debug"
    return sorted(path.name for path in capture_dir.glob("SMSG_MESSAGECHAT*.json"))


def _sniffed_messagechat_response(capture_name: str | None = None) -> list[tuple[str, bytes]]:
    selected_capture = str(capture_name or RAW_SNIFFED_MESSAGECHAT_CAPTURE)
    capture_path = get_captures_root(focus=True) / "debug" / selected_capture
    if not capture_path.exists():
        Logger.warning(f"[CHAT][SNIFF] missing capture path={capture_path}")
        return _notification_response(f"Missing chat sniff: {selected_capture}")
    opcode_name, payload = send_raw_packet(None, "SMSG_MESSAGECHAT", capture_path)
    return [(opcode_name, payload)]


def _namequery_response(session, query_arg: str) -> list[tuple[str, bytes]]:
    query_value = str(query_arg or "").strip().lower()
    if query_value in ("", "self", "me"):
        guid = int(getattr(session, "world_guid", 0) or 0)
    else:
        try:
            numeric = int(query_value, 16) if query_value.startswith("0x") else int(query_value)
        except ValueError:
            return _notification_response("Usage: send namequery <self|guid>")
        if numeric <= 0:
            return _notification_response("Usage: send namequery <self|guid>")
        guid = numeric
        if guid <= 0xFFFFFFFF:
            realm_id = int(getattr(session, "realm_id", 0) or 0)
            guid = (int(realm_id & 0xFFFF) << 40) | (0x0003 << 48) | int(guid & 0xFFFFFFFF)

    if guid <= 0:
        return _notification_response("No valid guid for namequery")

    payload = entities_handlers.build_query_player_name_response(session, guid)
    Logger.info(f"[CHAT][NAMEQUERY] guid=0x{int(guid):016X} size={len(payload)}")
    return [("SMSG_QUERY_PLAYER_NAME_RESPONSE", payload)]


def _dispatch_responses_to_sessions(targets, responses) -> None:
    normalized_targets = list(targets or [])
    if not normalized_targets or not responses:
        return
    for target in normalized_targets:
        sender = getattr(target, "send_response", None)
        if callable(sender):
            sender(responses)


def _sender_chat_guid(session) -> int:
    return int(
        getattr(session, "char_guid", 0)
        or getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or 0
    )


def _normalize_player_name(value: str) -> str:
    return str(value or "").strip().casefold()


def _find_active_session_by_player_name(session, target_name: str):
    normalized_target = _normalize_player_name(target_name)
    if not normalized_target:
        return None

    state = getattr(session, "global_state", None)
    for candidate in list(getattr(state, "sessions", set()) or ()):
        if not callable(getattr(candidate, "send_response", None)):
            continue
        candidate_name = _normalize_player_name(getattr(candidate, "player_name", ""))
        if candidate_name == normalized_target:
            return candidate
    return None


def _iter_map_sessions(session) -> list:
    state = getattr(session, "global_state", None)
    map_id = int(getattr(session, "map_id", 0) or 0)
    results = []
    for candidate in list(getattr(state, "sessions", set()) or ()):
        if not callable(getattr(candidate, "send_response", None)):
            continue
        if int(getattr(candidate, "char_guid", 0) or 0) <= 0:
            continue
        if int(getattr(candidate, "map_id", 0) or 0) != map_id:
            continue
        results.append(candidate)
    return results


def _build_chat_response(
    *,
    chat_type: int,
    language: int,
    sender_guid: int,
    sender_name: str,
    target_guid: int,
    target_name: str,
    message: str,
) -> tuple[str, bytes]:
    return (
        "SMSG_MESSAGECHAT",
        encode_messagechat_payload(
            chat_type=chat_type,
            language=language,
            sender_guid=sender_guid,
            sender_name=sender_name,
            target_guid=target_guid,
            target_name=target_name,
            message=message,
        ),
    )


def _dispatch_or_return(session, responses: list[tuple[str, bytes]]):
    targets = _iter_map_sessions(session)
    if targets:
        _dispatch_responses_to_sessions(targets, responses)
        return 0, None
    return 0, responses


def _dispatch_world_system_message(session, message: str):
    responses = _notification_response(message)
    targets = chat_router.get_targets(session, "say")
    if targets:
        _dispatch_responses_to_sessions(targets, responses)
        return 0, None
    return 0, responses


def _clear_persistent_emote_state(session) -> list[tuple[str, bytes]]:
    if int(getattr(session, "npc_emote_state", 0) or 0) != 10:
        return []
    player_guid = _sender_chat_guid(session)
    setattr(session, "npc_emote_state", 0)
    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_single_u32_update_object_payload(
                map_id=int(getattr(session, "map_id", 0) or 0),
                guid=player_guid,
                field_index=_UNIT_FIELD_EMOTE_STATE,
                value=0,
            ),
        )
    ]


def _current_stand_state(session) -> int:
    return int(getattr(session, "player_stand_state", _STAND_STATE_STANDING) or _STAND_STATE_STANDING)


def _set_stand_state(session, stand_state: int) -> list[tuple[str, bytes]]:
    target_state = int(stand_state or _STAND_STATE_STANDING)
    current_state = _current_stand_state(session)
    setattr(session, "player_stand_state", target_state)
    if current_state == target_state:
        return []
    player_guid = _sender_chat_guid(session)
    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_single_u32_update_object_payload(
                map_id=int(getattr(session, "map_id", 0) or 0),
                guid=player_guid,
                field_index=_UNIT_FIELD_ANIMTIER,
                value=target_state,
            ),
        )
    ]


def _clear_stand_state(session) -> list[tuple[str, bytes]]:
    if _current_stand_state(session) == _STAND_STATE_STANDING:
        return []
    return _set_stand_state(session, _STAND_STATE_STANDING)


def _clear_stateful_emote_states(session) -> list[tuple[str, bytes]]:
    return _clear_stand_state(session) + _clear_persistent_emote_state(session)


def _build_player_flags_update(session) -> tuple[str, bytes]:
    return (
        "SMSG_UPDATE_OBJECT",
        build_single_u32_update_object_payload(
            map_id=int(getattr(session, "map_id", 0) or 0),
            guid=_sender_chat_guid(session),
            field_index=_PLAYER_FIELD_PLAYER_FLAGS,
            value=int(getattr(session, "player_flags", 0) or 0),
        ),
    )


def _set_presence_flags(session, *, afk: bool | None = None, dnd: bool | None = None, auto_reply_msg: str | None = None):
    player_flags = int(getattr(session, "player_flags", 0) or 0)
    if afk is not None:
        setattr(session, "is_afk", bool(afk))
        if afk:
            player_flags |= _PLAYER_FLAGS_AFK
        else:
            player_flags &= ~_PLAYER_FLAGS_AFK
    if dnd is not None:
        setattr(session, "is_dnd", bool(dnd))
        if dnd:
            player_flags |= _PLAYER_FLAGS_DND
        else:
            player_flags &= ~_PLAYER_FLAGS_DND
    if auto_reply_msg is not None:
        setattr(session, "auto_reply_msg", str(auto_reply_msg or ""))
    session.player_flags = int(player_flags)
    return _dispatch_or_return(session, [_build_player_flags_update(session)])


def _toggle_afk(session, message: str):
    message = str(message or "").strip()
    if bool(getattr(session, "is_afk", False)):
        if message:
            return _set_presence_flags(session, afk=True, auto_reply_msg=message)
        code, responses = _set_presence_flags(session, afk=False, auto_reply_msg="")
        world_code, world_responses = _dispatch_world_system_message(
            session,
            f"{getattr(session, 'player_name', 'Player')} is no longer AFK",
        )
        if responses and world_responses:
            return code or world_code, list(responses) + list(world_responses)
        return code or world_code, responses or world_responses

    auto_reply = message or _DEFAULT_AFK_MESSAGE
    code, responses = _set_presence_flags(session, afk=True, dnd=False, auto_reply_msg=auto_reply)
    world_code, world_responses = _dispatch_world_system_message(
        session,
        f"{getattr(session, 'player_name', 'Player')} is AFK",
    )
    if responses and world_responses:
        return code or world_code, list(responses) + list(world_responses)
    return code or world_code, responses or world_responses


def _toggle_dnd(session, message: str):
    message = str(message or "").strip()
    if bool(getattr(session, "is_dnd", False)):
        if message:
            return _set_presence_flags(session, dnd=True, auto_reply_msg=message)
        code, responses = _set_presence_flags(session, dnd=False, auto_reply_msg="")
        world_code, world_responses = _dispatch_world_system_message(
            session,
            f"{getattr(session, 'player_name', 'Player')} is no longer DND",
        )
        if responses and world_responses:
            return code or world_code, list(responses) + list(world_responses)
        return code or world_code, responses or world_responses

    auto_reply = message or _DEFAULT_DND_MESSAGE
    code, responses = _set_presence_flags(session, afk=False, dnd=True, auto_reply_msg=auto_reply)
    world_code, world_responses = _dispatch_world_system_message(
        session,
        f"{getattr(session, 'player_name', 'Player')} is DND",
    )
    if responses and world_responses:
        return code or world_code, list(responses) + list(world_responses)
    return code or world_code, responses or world_responses


def _handle_chat_command_old(session, message: str) -> Optional[list[tuple[str, bytes]]]:
    command = str(message or "").strip()

    if command.lower().startswith(".roll"):
        roll = random.randint(1, 100)
        msg = f"{session.player_name} rolls {roll} (1-100)"
        payload = encode_messagechat_payload(
            chat_type=CHAT_MSG_SAY,
            language=0,
            sender_guid=session.player_guid,
            sender_name=session.player_name,
            target_guid=0,
            target_name="",
            message=msg,
        )
        return [("SMSG_MESSAGECHAT", payload)]

    if command.lower() == ".getxy":
        Logger.info(
            "[GETXY] "
            f"map={int(getattr(session, 'map_id', 0) or 0)} "
            f"x={float(getattr(session, 'x', 0.0) or 0.0):.2f} "
            f"y={float(getattr(session, 'y', 0.0) or 0.0):.2f} "
            f"z={float(getattr(session, 'z', 0.0) or 0.0):.2f} "
            f"o={float(getattr(session, 'orientation', 0.0) or 0.0):.2f}"
        )
        return []

    if command.lower().startswith(".weather"):
        parts = command.split()
        if len(parts) not in (2, 3):
            Logger.info("[Weather] Usage: .weather <clear|rain|snow|storm|sand|id> [0.0-1.0]")
            return []

        weather_key = parts[1].strip().lower()
        density = 0.0 if weather_key in ("clear", "fine", "sun") else 1.0
        abrupt = 1
        if len(parts) == 3:
            try:
                density = max(0.0, min(1.0, float(parts[2])))
            except ValueError:
                Logger.info(f"[Weather] Invalid density command={command!r}")
                return []

        try:
            weather_type = int(weather_key)
        except ValueError:
            weather_type = resolve_weather_type(weather_key, density)

        if weather_type < 0:
            Logger.info(f"[Weather] Unknown weather command={command!r}")
            return []

        Logger.info(
            f"[Weather] type={int(weather_type)} density={float(density):.2f} abrupt={abrupt}"
        )
        broadcast_region_weather(
            session,
            int(weather_type),
            float(density),
            abrupt,
            announce=f"[Weather] type={int(weather_type)} density={float(density):.2f}",
        )
        return []

    if command.lower().startswith(".time"):
        parts = command.split(maxsplit=1)
        if len(parts) != 2:
            Logger.info("[Time] Usage: .time <HH:MM|day|night|dawn|dusk|noon|midnight>")
            return []

        arg = parts[1].strip().lower()
        presets = {
            "day": (12, 0),
            "noon": (12, 0),
            "night": (0, 0),
            "midnight": (0, 0),
            "dawn": (6, 0),
            "dusk": (18, 0),
            "sunrise": (6, 0),
            "sunset": (18, 0),
        }

        if arg in presets:
            hour, minute = presets[arg]
        else:
            time_parts = arg.split(":", 1)
            if len(time_parts) != 2:
                Logger.info(f"[Time] Invalid time command={command!r}")
                return []
            try:
                hour = int(time_parts[0])
                minute = int(time_parts[1])
            except ValueError:
                Logger.info(f"[Time] Invalid time command={command!r}")
                return []
            if not (0 <= hour <= 23 and 0 <= minute <= 59):
                Logger.info(f"[Time] Out-of-range time command={command!r}")
                return []

        now = int(time.time())
        lt = time.localtime(now)
        current_seconds = int(lt.tm_hour) * 3600 + int(lt.tm_min) * 60 + int(lt.tm_sec)
        target_seconds = int(hour) * 3600 + int(minute) * 60 + int(lt.tm_sec)

        session.server_time = now
        session.time_offset = target_seconds - current_seconds
        session.time_speed = 0.01666667
        session.game_time = pack_wow_game_time(session.server_time + session.time_offset)

        Logger.info(
            f"[Time] hour={hour:02d} minute={minute:02d} "
            f"offset={int(session.time_offset)} packed=0x{int(session.game_time):08X}"
        )
        broadcast_world_time(
            int(hour),
            int(minute),
            announce=f"[Time] {hour:02d}:{minute:02d}",
        )
        return []

    if command.lower().startswith(".system "):
        message = str(command[8:] or "").strip()
        if not message:
            return _notification_response("Usage: .system <message>")
        Logger.info(f"[SystemChat] message={message!r}")
        broadcast_system_message(message, scope="world")
        return []

    if command.lower() == ".save":
        ok = save_current_position_like_command(session, reason="command", online=1, force=True)

        map_id = int(getattr(session, "persist_map_id", 0) or 0)
        zone = int(getattr(session, "persist_zone", 0) or 0)
        x = float(getattr(session, "persist_x", 0.0) or 0.0)
        y = float(getattr(session, "persist_y", 0.0) or 0.0)
        z = float(getattr(session, "persist_z", 0.0) or 0.0)
        orientation = float(getattr(session, "persist_orientation", 0.0) or 0.0)
        player_name = (
            str(getattr(session, "player_name", "") or "").strip()
            or f"Player{int(getattr(session, 'char_guid', 0) or 0)}"
        )

        if ok:
            message = (
                f"[Save] {player_name} map={map_id} zone={zone} "
                f"x={x:.2f} y={y:.2f} z={z:.2f} o={orientation:.2f}"
            )
            Logger.info(message)
        else:
            message = f"[Save] failed for {player_name}"
            Logger.warning(message)

        # Fallback if we need to restore center-screen notifications:
        # return [("SMSG_NOTIFICATION", build_motd_notification_payload(message))]
        return [("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(message))]

    if command.lower().startswith(".telxyz"):
        parts = command.split()
        player_name = (
            str(getattr(session, "player_name", "") or "").strip()
            or f"Player{int(getattr(session, 'char_guid', 0) or 0)}"
        )
        if len(parts) != 6:
            Logger.info(f"[Teleport] Invalid .telxyz syntax command={command!r}")
            payload_out = encode_messagechat_payload(
                chat_type=CHAT_MSG_SAY,
                language=0,
                sender_guid=int(getattr(session, "player_guid", 0) or getattr(session, "world_guid", 0) or 0),
                sender_name=player_name,
                target_guid=0,
                target_name="",
                message="Usage: .telxyz <map> <x> <y> <z> <orientation>",
            )
            return [("SMSG_MESSAGECHAT", payload_out)]

        try:
            map_id = int(parts[1])
            x = float(parts[2])
            y = float(parts[3])
            z = float(parts[4])
            orientation = float(parts[5])
        except (TypeError, ValueError):
            Logger.info(f"[Teleport] Invalid .telxyz args command={command!r}")
            return []

        Logger.info(
            f"[Teleport] {player_name} -> manual ({map_id} {x:.2f} {y:.2f} {z:.2f} {orientation:.2f})"
        )
        return teleport_player(
            session,
            map_id,
            x,
            y,
            z,
            orientation,
            destination_name=f"manual:{map_id}:{x:.2f}:{y:.2f}:{z:.2f}:{orientation:.2f}",
        )

    if not command.startswith(".tel"):
        return None

    parts = command.split()
    if len(parts) == 1:
        return _notification_response("Usage: .tel <name> | .tel search <name> | .tel add <name> | .tel rm <name> | .tel nearest")

    action = parts[1].strip().lower()
    if action == "search":
        query = command.split(None, 2)[2] if len(parts) >= 3 else ""
        matches = search_teleports(query)
        if not matches:
            return _notification_response("Matches: none")
        return _notification_response(f"Matches: {', '.join(matches)}")

    if action == "add":
        name = command.split(None, 2)[2].strip() if len(parts) >= 3 else ""
        if not name:
            return _notification_response("Usage: .tel add <name>")
        try:
            entry = add_named_teleport(
                DatabaseConnection.world(),
                name,
                int(getattr(session, "map_id", 0) or 0),
                float(getattr(session, "x", 0.0) or 0.0),
                float(getattr(session, "y", 0.0) or 0.0),
                float(getattr(session, "z", 0.0) or 0.0),
                float(getattr(session, "orientation", 0.0) or 0.0),
            )
        except Exception as exc:
            Logger.warning(f"[Teleport] add failed name={name!r}: {exc}")
            return _notification_response("Teleport add failed")
        return _notification_response(f"Teleport added: {entry['name']}")

    if action == "rm":
        name = command.split(None, 2)[2].strip() if len(parts) >= 3 else ""
        if not name:
            return _notification_response("Usage: .tel rm <name>")
        try:
            removed = remove_named_teleport(DatabaseConnection.world(), name)
        except Exception as exc:
            Logger.warning(f"[Teleport] rm failed name={name!r}: {exc}")
            return _notification_response("Teleport remove failed")
        if not removed:
            return _notification_response("Teleport not found")
        return _notification_response("Teleport removed")

    if action == "nearest":
        nearest = nearest_teleport(
            int(getattr(session, "map_id", 0) or 0),
            float(getattr(session, "x", 0.0) or 0.0),
            float(getattr(session, "y", 0.0) or 0.0),
        )
        if nearest is None:
            return _notification_response("Nearest: none")
        return _notification_response(f"Nearest: {nearest['name']}")

    destination_name = command.split(None, 1)[1].strip() if len(parts) >= 2 else ""
    destination = find_teleport(destination_name)
    if destination is None:
        Logger.info(f"[Teleport] Unknown destination command={command!r}")
        return _notification_response("Teleport not found")

    map_id = int(destination["map"])
    x = float(destination["x"])
    y = float(destination["y"])
    z = float(destination["z"])
    orientation = float(destination["o"])
    player_name = (
        str(getattr(session, "player_name", "") or "").strip()
        or f"Player{int(getattr(session, 'char_guid', 0) or 0)}"
    )

    Logger.info(
        f"[Teleport] {player_name} -> {destination['name']} ({x:.2f} {y:.2f} {z:.2f})"
    )
    return teleport_player(
        session,
        map_id,
        x,
        y,
        z,
        orientation,
        destination_name=str(destination["name"]),
    )


def _handle_chat_command(session, message: str) -> Optional[list[tuple[str, bytes]]]:
    command = str(message or "").strip()

    command_lower = command.lower()

    if command_lower == ".sniffchat":
        Logger.info(f"[CHAT][SNIFF] replay source={RAW_SNIFFED_MESSAGECHAT_CAPTURE}")
        responses = _debug_feedback_response(f"send chatsniff 1: {RAW_SNIFFED_MESSAGECHAT_CAPTURE}")
        responses.extend(_sniffed_messagechat_response())
        return responses

    send_prefixes = (".send chatsniff", "send chatsniff")
    if command_lower.startswith(send_prefixes):
        parts = command.split()
        captures = _list_sniffed_messagechat_captures()
        if not captures:
            return _notification_response("No sniff chat captures found")

        capture_index = 1
        if len(parts) >= 3:
            try:
                capture_index = int(parts[2])
            except ValueError:
                return _notification_response("Usage: .send chatsniff <1-n>")

        if capture_index < 1 or capture_index > len(captures):
            return _notification_response(
                f"Usage: .send chatsniff <1-{len(captures)}>"
            )

        selected_capture = captures[capture_index - 1]
        Logger.info(
            f"[CHAT][SNIFF] replay index={capture_index}/{len(captures)} "
            f"source={selected_capture}"
        )
        responses = _debug_feedback_response(
            f"send chatsniff {capture_index}: {selected_capture}"
        )
        responses.extend(_sniffed_messagechat_response(selected_capture))
        return responses

    namequery_prefixes = (".send namequery", "send namequery")
    if command_lower.startswith(namequery_prefixes):
        parts = command.split(maxsplit=2)
        query_arg = parts[2] if len(parts) >= 3 else "self"
        responses = _debug_feedback_response(f"send namequery {query_arg}")
        responses.extend(_namequery_response(session, query_arg))
        return responses

    chatsniffnq_prefixes = (".send chatsniffnq", "send chatsniffnq")
    if command_lower.startswith(chatsniffnq_prefixes):
        parts = command.split()
        captures = _list_sniffed_messagechat_captures()
        if not captures:
            return _notification_response("No sniff chat captures found")

        capture_index = 1
        if len(parts) >= 3:
            try:
                capture_index = int(parts[2])
            except ValueError:
                return _notification_response("Usage: .send chatsniffnq <1-n>")

        if capture_index < 1 or capture_index > len(captures):
            return _notification_response(
                f"Usage: .send chatsniffnq <1-{len(captures)}>"
            )

        selected_capture = captures[capture_index - 1]
        Logger.info(
            f"[CHAT][SNIFFNQ] replay index={capture_index}/{len(captures)} "
            f"source={selected_capture}"
        )
        responses = _debug_feedback_response(
            f"send chatsniffnq {capture_index}: {selected_capture}"
        )
        responses.extend(_namequery_response(session, "self"))
        responses.extend(_sniffed_messagechat_response(selected_capture))
        return responses

    return _handle_chat_command_old(session, message)


def _handle_chat_message_old(session, ctx: PacketContext):
    chat = decode_chat_message(ctx.name, ctx.payload, ctx.decoded)
    message = chat["message"]
    if not message:
        return 0, None

    command_responses = _handle_chat_command(session, message)
    if command_responses is not None:
        return 0, command_responses if command_responses else None

    player_name = session.player_name
    sender_guid = int(getattr(session, "char_guid", 0) or getattr(session, "player_guid", 0) or 0)
    language = int(chat.get("language") or 0)

    Logger.debug(f"[CHAT] opcode={ctx.name}")
    Logger.info(f"[CHAT] {player_name}: {message}")

    if USE_SYSTEM_CHAT_FALLBACK:
        payload_out = encode_skyfire_messagechat_system_payload(f"[{player_name}] {message}")
        Logger.info(
            f"[CHAT][FALLBACK] mode=system player={player_name!r} bytes={len(payload_out)} message={message!r}"
        )
    else:
        payload_out = encode_messagechat_payload(
            chat_type=CHAT_MSG_SAY,
            language=language,
            sender_guid=sender_guid,
            sender_name=player_name,
            target_guid=0,
            target_name="",
            message=message,
        )

    chat_response = ("SMSG_MESSAGECHAT", payload_out)
    targets = chat_router.get_targets(session, "say")
    dispatched = False
    if targets:
        _dispatch_responses_to_sessions(targets, [chat_response])
        dispatched = True

    # Fallback if we need per-message screen notifications again:
    # responses: list[tuple[str, bytes]] = [("SMSG_NOTIFICATION", notification_payload)]
    responses: list[tuple[str, bytes]] = []
    raw_replay_messagechat = build_raw_replay_messagechat_packet(
        profile=RAW_REPLAY_SAY_CHAT_PROFILE
    )
    if raw_replay_messagechat is not None:
        responses.append(raw_replay_messagechat)
    if not dispatched:
        responses.insert(0, chat_response)
    return 0, responses


def _handle_chat_message(session, ctx: PacketContext):
    chat = decode_chat_message(ctx.name, ctx.payload, ctx.decoded)
    message = chat["message"]
    if not message:
        return 0, None

    command_responses = _handle_chat_command(session, message)
    if command_responses is not None:
        return 0, command_responses if command_responses else None

    player_name = session.player_name
    sender_guid = _sender_chat_guid(session)
    language = int(chat.get("language") or 0)

    Logger.debug(f"[CHAT] opcode={ctx.name}")
    Logger.info(f"[CHAT] {player_name}: {message}")

    if ctx.name == "CMSG_MESSAGECHAT_SAY":
        payload_out = encode_messagechat_payload(
            chat_type=CHAT_MSG_SAY,
            language=language,
            sender_guid=sender_guid,
            sender_name=player_name,
            target_guid=0,
            target_name="",
            message=message,
        )
        say_chat_response = ("SMSG_MESSAGECHAT", payload_out)
        targets = chat_router.get_targets(session, "say")
        if targets:
            # Fallback if we want to mirror say as system feedback too:
            # system_chat_response = (
            #     "SMSG_MESSAGECHAT",
            #     encode_skyfire_messagechat_system_payload(f"{player_name}: {message}"),
            # )
            # _dispatch_responses_to_sessions(targets, [system_chat_response, say_chat_response])
            _dispatch_responses_to_sessions(targets, [say_chat_response])
            return 0, None
        # return 0, [system_chat_response, say_chat_response]
        return 0, [say_chat_response]

    if ctx.name == "CMSG_MESSAGECHAT_YELL":
        if USE_SYSTEM_CHAT_FALLBACK:
            Logger.info(f"[CHAT][YELL] using skyfire packet path sender={player_name!r} message={message!r}")
        yell_chat_response = _build_chat_response(
            chat_type=CHAT_MSG_YELL,
            language=language,
            sender_guid=sender_guid,
            sender_name=player_name,
            target_guid=0,
            target_name="",
            message=message,
        )
        targets = chat_router.get_targets(session, "yell")
        if targets:
            _dispatch_responses_to_sessions(targets, [yell_chat_response])
            return 0, None
        return 0, [yell_chat_response]

    if ctx.name == "CMSG_MESSAGECHAT_WHISPER":
        target_name = str(chat.get("target") or "").strip()
        if not target_name:
            Logger.info(f"[CHAT][WHISPER] missing target from={player_name!r} message={message!r}")
            Logger.debug(f"[CHAT][WHISPER] decoded={chat!r} raw={bytes(ctx.payload or b'').hex()}")
            return 0, _notification_response("Whisper target missing")

        target_session = _find_active_session_by_player_name(session, target_name)
        if target_session is None:
            Logger.info(
                f"[CHAT][WHISPER] target offline from={player_name!r} target={target_name!r} message={message!r}"
            )
            return 0, _notification_response(f"{target_name} is not online")

        target_player_name = (
            str(getattr(target_session, "player_name", "") or "").strip()
            or target_name
        )
        target_guid = _sender_chat_guid(target_session)
        recipient_response = _build_chat_response(
            chat_type=CHAT_MSG_WHISPER,
            language=language,
            sender_guid=sender_guid,
            sender_name=player_name,
            target_guid=target_guid,
            target_name=target_player_name,
            message=message,
        )
        echo_response = _build_chat_response(
            chat_type=CHAT_MSG_WHISPER_INFORM,
            language=language,
            sender_guid=sender_guid,
            sender_name=player_name,
            target_guid=target_guid,
            target_name=target_player_name,
            message=message,
        )

        if target_session is not session:
            _dispatch_responses_to_sessions([target_session], [recipient_response])
        responses = [echo_response]
        if bool(getattr(target_session, "is_afk", False)):
            auto_reply_msg = str(getattr(target_session, "auto_reply_msg", "") or _DEFAULT_AFK_MESSAGE)
            responses.extend(_notification_response(f"{target_player_name} is AFK: {auto_reply_msg}"))
        elif bool(getattr(target_session, "is_dnd", False)):
            auto_reply_msg = str(getattr(target_session, "auto_reply_msg", "") or _DEFAULT_DND_MESSAGE)
            responses.extend(_notification_response(f"{target_player_name} is DND: {auto_reply_msg}"))
        return 0, responses

    if USE_SYSTEM_CHAT_FALLBACK:
        payload_out = encode_skyfire_messagechat_system_payload(f"[{player_name}] {message}")
        Logger.info(
            f"[CHAT][FALLBACK] mode=system player={player_name!r} bytes={len(payload_out)} message={message!r}"
        )
    else:
        payload_out = encode_messagechat_payload(
            chat_type=CHAT_MSG_SAY,
            language=language,
            sender_guid=sender_guid,
            sender_name=player_name,
            target_guid=0,
            target_name="",
            message=message,
        )

    chat_response = ("SMSG_MESSAGECHAT", payload_out)
    targets = chat_router.get_targets(session, "say")
    dispatched = False
    if targets:
        _dispatch_responses_to_sessions(targets, [chat_response])
        dispatched = True

    # Fallback if we need per-message screen notifications again:
    # responses: list[tuple[str, bytes]] = [("SMSG_NOTIFICATION", notification_payload)]
    responses: list[tuple[str, bytes]] = []
    raw_replay_messagechat = build_raw_replay_messagechat_packet(
        profile=RAW_REPLAY_SAY_CHAT_PROFILE
    )
    if raw_replay_messagechat is not None:
        responses.append(raw_replay_messagechat)
    if not dispatched:
        responses.insert(0, chat_response)
    return 0, responses


@register("CMSG_CHAT_JOIN_CHANNEL")
def handle_chat_join_channel(session, ctx: PacketContext):
    channel_name = "General"
    decoded = ctx.decoded or {}
    if decoded.get("channel_name"):
        channel_name = str(decoded.get("channel_name") or "General").strip() or "General"

    session.chat_joined = True
    Logger.info(f"[WorldHandlers] CHAT_JOIN_CHANNEL accepted channel={channel_name!r}")

    if session.chat_motd_sent:
        return 0, None

    session.chat_motd_sent = True
    Logger.info("[WorldHandlers] sending MOTD after chat join")
    motd = str(getattr(login_handlers._build_world_login_context(session), "motd", "") or "").strip()
    if not motd:
        return 0, None
    # Fallback if we need to restore SMSG_MOTD:
    # motd_payload = build_login_packet("SMSG_MOTD", login_handlers._build_world_login_context(session))
    # if motd_payload is None:
    #     return 0, None
    # return 0, [("SMSG_MOTD", motd_payload)]
    return 0, [("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(motd))]


@register("CMSG_MESSAGECHAT_SAY")
def handle_messagechat_say(session, ctx: PacketContext):
    return _handle_chat_message(session, ctx)


@register("CMSG_MESSAGECHAT_YELL")
def handle_messagechat_yell(session, ctx: PacketContext):
    return _handle_chat_message(session, ctx)


@register("CMSG_MESSAGECHAT_WHISPER")
def handle_messagechat_whisper(session, ctx: PacketContext):
    return _handle_chat_message(session, ctx)


@register("CMSG_CHAT_MESSAGE_AFK")
def handle_messagechat_afk(session, ctx: PacketContext):
    chat = decode_chat_message(ctx.name, ctx.payload, ctx.decoded)
    return _toggle_afk(session, str(chat.get("message") or ""))


@register("CMSG_MESSAGECHAT_DND")
def handle_messagechat_dnd(session, ctx: PacketContext):
    chat = decode_chat_message(ctx.name, ctx.payload, ctx.decoded)
    return _toggle_dnd(session, str(chat.get("message") or ""))


@register("CMSG_SEND_TEXT_EMOTE")
def handle_send_text_emote(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    decoded = log_cmsg(ctx)
    emote_id = int((decoded or {}).get("emote_id") or 0)
    emote_num = int((decoded or {}).get("emote_num") or 0)
    target_guid = int((decoded or {}).get("target_guid") or 0)
    player_guid = _sender_chat_guid(session)
    anim_emote = int(TEXT_EMOTE_TO_ANIM_EMOTE.get(emote_id, 0) or 0)

    Logger.info(
        f"[EMOTE][TEXT] emote_id={emote_id} emote_num={emote_num} anim_emote={anim_emote} "
        f"player_guid=0x{player_guid:016X} target_guid=0x{target_guid:016X}"
    )

    responses: list[tuple[str, bytes]] = [
        (
            "SMSG_TEXT_EMOTE",
            encode_text_emote_payload(
                player_guid=player_guid,
                target_guid=target_guid,
                text_emote=emote_id,
                emote_num=emote_num,
            ),
        )
    ]

    stand_state = _TEXT_EMOTE_TO_STAND_STATE.get(emote_id)
    if stand_state is not None:
        responses = _clear_persistent_emote_state(session) + responses
        responses.extend(_set_stand_state(session, stand_state))
        return _dispatch_or_return(session, responses)

    if anim_emote == 10:
        responses = _clear_stand_state(session) + responses
        setattr(session, "npc_emote_state", 10)
        responses.append(
            (
                "SMSG_UPDATE_OBJECT",
                build_single_u32_update_object_payload(
                    map_id=int(getattr(session, "map_id", 0) or 0),
                    guid=player_guid,
                    field_index=_UNIT_FIELD_EMOTE_STATE,
                    value=10,
                ),
            )
        )
    elif anim_emote > 0:
        responses = _clear_stateful_emote_states(session) + responses
        setattr(session, "npc_emote_state", 0)
        emote_payload = EncoderHandler.encode_packet(
            "SMSG_EMOTE",
            {
                "emote_id": anim_emote,
                "guid": player_guid,
            },
        )
        responses.append(("SMSG_EMOTE", emote_payload))

    return _dispatch_or_return(session, responses)


@register("CMSG_EMOTE")
def handle_emote(session, ctx: PacketContext) -> Tuple[int, Optional[list[tuple[str, bytes]]]]:
    decoded = log_cmsg(ctx)
    emote_id = int((decoded or {}).get("emote_id") or 0)
    player_guid = _sender_chat_guid(session)
    Logger.info(f"[EMOTE] emote_id={emote_id} player_guid=0x{player_guid:016X}")
    responses = _clear_stateful_emote_states(session)
    payload = EncoderHandler.encode_packet(
        "SMSG_EMOTE",
        {
            "emote_id": emote_id,
            "guid": player_guid,
        },
    )
    responses.append(("SMSG_EMOTE", payload))
    return _dispatch_or_return(session, responses)
