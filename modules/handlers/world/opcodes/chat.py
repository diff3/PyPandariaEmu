from __future__ import annotations

import random
import struct
import time
from typing import Optional, Tuple

from DSL.modules.EncoderHandler import EncoderHandler
from shared.Logger import Logger
from server.modules.protocol.PacketContext import PacketContext
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.handlers.world.login.packets import build_login_packet
from server.modules.game.guid import GuidHelper
from server.modules.game.inventory import (
    add_item_to_character,
    auto_equip_item,
    swap_character_item,
)
from server.modules.handlers.world.bootstrap.replay import (
    build_multi_u32_update_object_payload,
    build_single_u32_update_object_payload,
)
from server.modules.handlers.world.inventory_sync import (
    build_login_inventory_sync_responses,
    build_inventory_delta_responses,
    build_item_snapshot_responses,
    inventory_result_affects_equipment,
    trigger_inventory_activation,
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
from server.modules.handlers.world.commands import chat_commands
from server.modules.handlers.world.dispatcher import register
from server.modules.handlers.world.opcodes import login as login_handlers
from server.modules.handlers.world.state.runtime import (
    build_explored_zones_update_response,
    resync_player_appearance,
    set_session_explored_zones_state,
)
from server.modules.handlers.world.opcodes import spells as spells_handlers
from server.modules.handlers.world.opcodes.movement import (
    build_move_set_speed_payload,
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
from server.modules.handlers.world.position.area_service import resolve_zone_from_position
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
_CHAT_MOUNT_DISPLAY_ID = 2404
_PLAYER_FIELD_LEVEL = 55
_TIER_SET_ITEMS: dict[tuple[str, int], tuple[int, ...]] = {
    # Mage Tier 1 (Arcanist) – stable baseline set
    ("mage", 1): (
        16795,  # Head
        16797,  # Shoulder
        16798,  # Chest
        16800,  # Hands
        16796,  # Legs
        16799,  # Bindings
        16801,  # Gloves
        16802,  # Belt
    ),

    # Shaman Tier 1 (Earthfury) – also stable
    ("shaman", 1): (
        16814,  # Head (Earthfury Helmet)
        16817,  # Shoulder (Earthfury Epaulets)
        16816,  # Chest (Earthfury Vestments)
        16812,  # Hands (Earthfury Gauntlets)
        16813,  # Legs (Earthfury Legguards)
    ),
}
_TEXT_EMOTE_TO_STAND_STATE = {
    59: _STAND_STATE_KNEEL,
    86: _STAND_STATE_SITTING,
    87: _STAND_STATE_SLEEPING,
    141: _STAND_STATE_STANDING,
}
_ITEM_HIGHGUID = 0x400
_ITEM_FIELD_STACK_COUNT = 0x10
_PLAYER_FIELD_INV_SLOTS = (0x8 + 0x98) + 0x325
_PLAYER_FIELD_PACK_SLOTS = (0x8 + 0x98) + 0x353
_PLAYER_FIELD_EXPLORED_ZONES = (0x8 + 0x98) + 0x5BB
_PLAYER_EXPLORED_ZONES_SIZE = 200
_ITEM_CREATE_FLAGS = b"\x00\x00\x00\x00\x00\x00"
_ITEM_CREATE_MASK = bytes.fromhex("f30581000000000000000000")


def _notification_response(message: str) -> list[tuple[str, bytes]]:
    # Fallback if we need to restore center-screen notifications:
    # return [("SMSG_NOTIFICATION", build_motd_notification_payload(message))]
    return [("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(message))]


def _append_feedback_response(
    responses: list[tuple[str, bytes]] | None,
    message: str,
) -> list[tuple[str, bytes]]:
    merged = list(responses or [])
    merged.extend(_notification_response(message))
    return merged


def _make_skyfire_guid(low: int, entry: int, high: int) -> int:
    shift = 48 if int(high) in {0xF101, 0xF102} else 52
    return (
        (int(low) & 0xFFFFFFFF)
        | ((int(entry) & 0xFFFFF) << 32)
        | ((int(high) & 0xFFFFF) << shift)
    )


def _make_item_world_guid(item_low_guid: int) -> int:
    return _make_skyfire_guid(int(item_low_guid), 0, _ITEM_HIGHGUID)


def _build_item_create_update_payload(session, item) -> bytes:
    item_guid = _make_item_world_guid(int(item.item_guid))
    field_values = (
        int(item_guid & 0xFFFFFFFF),
        int((item_guid >> 32) & 0xFFFFFFFF),
        3,
        int(item.entry),
        0,
        0x3F800000,
        int(getattr(session, "char_guid", 0) or 0),
        int(getattr(session, "char_guid", 0) or 0),
        int(item.count),
        1,
    )

    entry = bytearray()
    entry += struct.pack("<B", 1)
    entry += GuidHelper.pack(int(item_guid))
    entry += struct.pack("<B", 1)
    entry += _ITEM_CREATE_FLAGS
    entry += struct.pack("<B", len(_ITEM_CREATE_MASK) // 4)
    entry += _ITEM_CREATE_MASK
    for value in field_values:
        entry += struct.pack("<I", int(value) & 0xFFFFFFFF)
    entry += struct.pack("<B", 0)

    payload = bytearray()
    payload += struct.pack("<HI", int(getattr(session, "map_id", 0) or 0) & 0xFFFF, 1)
    payload += entry
    return bytes(payload)


def _inventory_slot_field_index(bag: int, slot: int) -> Optional[int]:
    bag = int(bag)
    slot = int(slot)
    if bag != 0:
        return None
    if 0 <= slot < 23:
        return _PLAYER_FIELD_INV_SLOTS + (slot * 2)
    if 23 <= slot < 39:
        return _PLAYER_FIELD_PACK_SLOTS + ((slot - 23) * 2)
    return None


def _build_inventory_slot_update_responses(session, item) -> list[tuple[str, bytes]]:
    field_index = _inventory_slot_field_index(int(item.bag), int(item.slot))
    if field_index is None:
        return []

    item_guid = _make_item_world_guid(int(item.item_guid))
    player_guid = int(getattr(session, "char_guid", 0) or 0)
    map_id = int(getattr(session, "map_id", 0) or 0)
    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_single_u32_update_object_payload(
                map_id=map_id,
                guid=player_guid,
                field_index=field_index,
                value=int(item_guid & 0xFFFFFFFF),
            ),
        ),
        (
            "SMSG_UPDATE_OBJECT",
            build_single_u32_update_object_payload(
                map_id=map_id,
                guid=player_guid,
                field_index=field_index + 1,
                value=int((item_guid >> 32) & 0xFFFFFFFF),
            ),
        ),
    ]


def _build_forced_inventory_slot_resend_responses(session) -> list[tuple[str, bytes]]:
    state = getattr(session, "inventory_state", None)
    if state is None or not hasattr(state, "get"):
        return []

    selected_slot = None
    item_world_guid = 0
    for slot in range(39):
        item = state.get(0, slot)
        if item is None:
            continue
        selected_slot = int(slot)
        item_world_guid = _make_item_world_guid(int(getattr(item, "item_guid", 0) or 0))
        break

    if selected_slot is None:
        selected_slot = 0

    field_index = _inventory_slot_field_index(0, int(selected_slot))
    if field_index is None:
        return []

    Logger.debug(
        "[INVTEST] forced PLAYER_FIELD_INV_SLOT resend slot=%s value=%s",
        int(selected_slot),
        int(item_world_guid),
    )
    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_multi_u32_update_object_payload(
                map_id=int(getattr(session, "map_id", 0) or 0),
                guid=int(getattr(session, "char_guid", 0) or 0),
                field_updates=[
                    (field_index, int(item_world_guid & 0xFFFFFFFF)),
                    (field_index + 1, int((item_world_guid >> 32) & 0xFFFFFFFF)),
                ],
            ),
        )
    ]


def _build_inventory_count_update_response(session, item) -> tuple[str, bytes]:
    return (
        "SMSG_UPDATE_OBJECT",
        build_single_u32_update_object_payload(
            map_id=int(getattr(session, "map_id", 0) or 0),
            guid=_make_item_world_guid(int(item.item_guid)),
            field_index=_ITEM_FIELD_STACK_COUNT,
            value=int(item.count),
        ),
    )


def _build_map_exploration_update_response(session, reveal_all: bool) -> tuple[str, bytes]:
    explored_zones = set_session_explored_zones_state(session, bool(reveal_all))
    char_guid = int(getattr(session, "char_guid", 0) or 0)
    realm_id = int(getattr(session, "realm_id", 0) or 0)
    if char_guid > 0 and realm_id > 0:
        DatabaseConnection.save_character_explored_zones(
            char_guid,
            realm_id,
            explored_zones,
        )

    response = build_explored_zones_update_response(session)
    if response is not None:
        return response

    field_value = 0xFFFFFFFF if bool(reveal_all) else 0
    return (
        "SMSG_UPDATE_OBJECT",
        build_multi_u32_update_object_payload(
            map_id=int(getattr(session, "map_id", 0) or 0),
            guid=_sender_chat_guid(session),
            field_updates=[
                (_PLAYER_FIELD_EXPLORED_ZONES + offset, field_value)
                for offset in range(_PLAYER_EXPLORED_ZONES_SIZE)
            ],
        ),
    )


def _build_additem_sync_responses(session, result) -> list[tuple[str, bytes]]:
    responses: list[tuple[str, bytes]] = []
    created_item_guids = {int(item_guid) for item_guid in getattr(result, "created_item_guids", ())}
    changed_items = list(getattr(result, "changed_items", ()) or ())
    if not changed_items and getattr(result, "item", None) is not None:
        changed_items = [result.item]

    for item in changed_items:
        if int(getattr(item, "bag", -1)) != 0:
            continue
        if int(getattr(item, "item_guid", 0) or 0) in created_item_guids:
            responses.extend(build_item_snapshot_responses(session, item))
        responses.extend(_build_inventory_slot_update_responses(session, item))
        if int(getattr(item, "item_guid", 0) or 0) not in created_item_guids:
            responses.append(_build_inventory_count_update_response(session, item))
    return responses


def _build_inventory_mutation_sync_responses(session, result) -> list[tuple[str, bytes]]:
    return build_inventory_delta_responses(session, result)


def _handle_additem(session, entry: int, count: int) -> list[tuple[str, bytes]]:
    result = add_item_to_character(session, entry, count)

    responses: list[tuple[str, bytes]] = []

    if result.ok:
        # Use the same sync path as .additem
        responses.extend(_build_inventory_mutation_sync_responses(session, result))

    responses.extend(
        _notification_response(f"[Inventory] {result.message}")
    )

    return responses


def handle_addtier_command(session, args: list[str]) -> list[tuple[str, bytes]]:
    if len(args) != 2:
        return _notification_response("Usage: .addtier <class> <tier>")

    class_name = str(args[0]).strip().lower()
    try:
        tier = int(args[1], 0)
    except ValueError:
        return _notification_response("Usage: .addtier <class> <tier>")

    item_entries = _TIER_SET_ITEMS.get((class_name, int(tier)))
    if not item_entries:
        return _notification_response(f"[AddTier] unsupported class/tier: {class_name} {tier}")

    Logger.info(
        "[ADDTIER] class=%s tier=%s items=%s",
        class_name,
        int(tier),
        len(item_entries),
    )

    responses: list[tuple[str, bytes]] = []

    # Reuse additem logic for each item
    for item_entry in item_entries:
        responses.extend(_handle_additem(session, int(item_entry), 1))

    # Optional but recommended: force full resync for stability
    responses.extend(build_login_inventory_sync_responses(session))

    responses.extend(
        _notification_response(
            f"[AddTier] {class_name} T{int(tier)} items={len(item_entries)}"
        )
    )

    return responses


def send_run_speed(player, speed: float) -> tuple[str, bytes]:
    guid = int(getattr(player, "char_guid", 0) or getattr(player, "player_guid", 0) or 0)
    run_speed = float(speed)
    Logger.info("[SPEED] guid=%s speed=%.2f", guid, run_speed)
    return (
        "SMSG_MOVE_SET_RUN_SPEED",
        build_move_set_speed_payload(player, "SMSG_MOVE_SET_RUN_SPEED", run_speed),
    )


def _build_speed_command_responses(session) -> list[tuple[str, bytes]]:
    speed_packets = (
        ("SMSG_MOVE_SET_WALK_SPEED", float(getattr(session, "walk_speed", 2.5) or 2.5)),
        ("SMSG_MOVE_SET_SWIM_SPEED", float(getattr(session, "swim_speed", 4.7) or 4.7)),
        ("SMSG_MOVE_SET_FLIGHT_SPEED", float(getattr(session, "fly_speed", 7.0) or 7.0)),
    )
    responses = [
        (opcode_name, build_move_set_speed_payload(session, opcode_name, speed_value))
        for opcode_name, speed_value in speed_packets
    ]
    responses.insert(1, send_run_speed(session, float(getattr(session, "run_speed", 7.0) or 7.0)))
    responses.append(
        (
            "SMSG_MESSAGECHAT",
            encode_skyfire_messagechat_system_payload(
                f"[Speed] run={float(getattr(session, 'run_speed', 0.0) or 0.0):.2f}"
            ),
        )
    )
    return responses


def _build_fixplayer_responses(session, mode: int = 0) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.bootstrap import replay as bootstrap_replay
    from server.modules.handlers.world.state.runtime import (
        _build_player_create_update_response,
        _build_player_move_response,
        _build_player_value_update_responses,
    )

    guid = int(getattr(session, "char_guid", 0) or getattr(session, "player_guid", 0) or 0)
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)
    z = float(getattr(session, "z", 0.0) or 0.0)
    run_speed = float(getattr(session, "run_speed", 7.0) or 7.0)
    Logger.info(
        "[FIXPLAYER] guid=%s mode=%s run=%.2f pos=(%.2f,%.2f,%.2f)",
        guid,
        int(mode),
        run_speed,
        x,
        y,
        z,
    )

    responses: list[tuple[str, bytes]] = []
    normalized_mode = int(mode)
    if normalized_mode >= 2:
        ctx = login_handlers._build_world_login_context(session)
        for opcode_name in (
            "SMSG_LOGIN_VERIFY_WORLD",
            "SMSG_LOGIN_SET_TIME_SPEED",
            "SMSG_BIND_POINT_UPDATE",
        ):
            payload = build_login_packet(opcode_name, ctx)
            if payload is None:
                continue
            responses.append((opcode_name, payload))

        responses.append(bootstrap_replay._build_dynamic_active_mover_packet(session))
        create_response = _build_player_create_update_response(session)
        if create_response is not None:
            responses.append(create_response)
        responses.extend(_build_player_value_update_responses(session))
        responses.extend(build_login_inventory_sync_responses(session))
        responses.extend(trigger_inventory_activation(session))

        time_sync = build_login_packet("SMSG_TIME_SYNC_REQUEST", ctx)
        if time_sync is not None:
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
            responses.append((opcode_name, payload))
    elif normalized_mode == 1:
        responses.append(bootstrap_replay._build_dynamic_active_mover_packet(session))
        create_response = _build_player_create_update_response(session)
        if create_response is not None:
            responses.append(create_response)
        responses.extend(_build_player_value_update_responses(session))
    else:
        responses.extend(_build_player_value_update_responses(session))

    for opcode_name, speed_value in (
        ("SMSG_MOVE_SET_WALK_SPEED", float(getattr(session, "walk_speed", 2.5) or 2.5)),
        ("SMSG_MOVE_SET_RUN_SPEED", run_speed),
        ("SMSG_MOVE_SET_SWIM_SPEED", float(getattr(session, "swim_speed", 4.7) or 4.7)),
        ("SMSG_MOVE_SET_FLIGHT_SPEED", float(getattr(session, "fly_speed", 7.0) or 7.0)),
    ):
        responses.append((opcode_name, build_move_set_speed_payload(session, opcode_name, speed_value)))

    from server.modules.handlers.world.opcodes import movement as movement_handlers

    move_response = None
    refresh_builder = getattr(movement_handlers, "_build_run_speed_refresh_response", None)
    if callable(refresh_builder):
        move_response = refresh_builder(session)
    if move_response is None:
        move_response = _build_player_move_response(session)
    if move_response is not None:
        responses.append(move_response)
    return responses


def _apply_fixplayer_destination(session, destination_name: str) -> str | None:
    destination = find_teleport(destination_name)
    if destination is None:
        return None

    map_id = int(destination["map"])
    x = float(destination["x"])
    y = float(destination["y"])
    z = float(destination["z"])
    orientation = float(destination["o"])
    session.map_id = map_id
    session.x = x
    session.y = y
    session.z = z
    session.orientation = orientation
    session.zone = int(resolve_zone_from_position(map_id, x, y) or int(getattr(session, "zone", 0) or 0))
    session.instance_id = 0
    session.teleport_destination = str(destination["name"])
    return str(destination["name"])


def _build_fixspeed_responses(session) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.opcodes.movement import build_same_map_teleport_payload

    session.teleport_pending = False
    session.near_teleport_pending = True
    session.fixspeed_pending = True
    Logger.info(
        "[FIXSPEED] guid=%s queued same-map teleport pos=(%.2f,%.2f,%.2f,%.2f) run=%.2f",
        int(getattr(session, "char_guid", 0) or getattr(session, "player_guid", 0) or 0),
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
        float(getattr(session, "orientation", 0.0) or 0.0),
        float(getattr(session, "run_speed", 7.0) or 7.0),
    )
    return [
        (
            "SMSG_MESSAGECHAT",
            encode_skyfire_messagechat_system_payload("[FixSpeed] queued same-map resync"),
        ),
        ("SMSG_MOVE_TELEPORT", build_same_map_teleport_payload(session)),
    ]


def _build_level_command_responses(session) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.state.runtime import _build_player_value_update_responses

    responses = list(_build_player_value_update_responses(session))
    guid = int(getattr(session, "char_guid", 0) or getattr(session, "player_guid", 0) or 0)
    if guid <= 0:
        return responses

    responses.append(
        (
            "SMSG_UPDATE_OBJECT",
            build_single_u32_update_object_payload(
                map_id=int(getattr(session, "map_id", 0) or 0),
                guid=guid,
                field_index=_PLAYER_FIELD_LEVEL,
                value=int(getattr(session, "level", 1) or 1),
            ),
        )
    )
    return responses


_CHAT_COMMANDS_CONFIGURED = False


def _configure_chat_commands() -> None:
    global _CHAT_COMMANDS_CONFIGURED
    if _CHAT_COMMANDS_CONFIGURED:
        return

    chat_commands.configure(
        apply_fixplayer_destination=lambda session, destination_name: _apply_fixplayer_destination(
            session,
            destination_name,
        ),
        append_feedback_response=lambda responses, message: _append_feedback_response(
            responses,
            message,
        ),
        build_fixplayer_responses=lambda session, mode=0: _build_fixplayer_responses(session, mode),
        build_fixspeed_responses=lambda session: _build_fixspeed_responses(session),
        build_login_inventory_sync_responses=lambda session: build_login_inventory_sync_responses(session),
        build_level_command_responses=lambda session: _build_level_command_responses(session),
        build_map_exploration_update_response=lambda session, reveal_all: _build_map_exploration_update_response(
            session,
            reveal_all,
        ),
        build_speed_command_responses=lambda session: _build_speed_command_responses(session),
        chat_mount_display_id=_CHAT_MOUNT_DISPLAY_ID,
        notification_response=lambda message: _notification_response(message),
        tier_set_items=_TIER_SET_ITEMS,
    )
    _CHAT_COMMANDS_CONFIGURED = True


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
    _configure_chat_commands()
    return chat_commands.handle_command(session, message)


def _handle_chat_command(session, message: str) -> Optional[list[tuple[str, bytes]]]:
    _configure_chat_commands()
    return chat_commands.handle_command(session, message)


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
