#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import random
import re
import time
from types import SimpleNamespace
from typing import Any, Callable, Optional

import yaml
from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.game.inventory import (
    add_item_to_character,
)
try:
    from server.modules.game.inventory import persist_session_inventory
except ImportError:
    def persist_session_inventory(_session) -> bool:
        return True
from server.modules.handlers.world.chat.codec import (
    encode_skyfire_messagechat_system_payload,
)
from server.modules.handlers.world.achievement_service import (
    find_achievement_by_name,
    grant_achievement_by_id,
    repair_achievement_visibility,
)
from server.modules.handlers.world.inventory_sync import (
    build_inventory_delta_responses,
    build_login_inventory_sync_responses,
)
from server.modules.handlers.world.opcodes import spells as spells_handlers
from server.modules.handlers.world.opcodes.movement import (
    _save_current_position_like_command as save_current_position_like_command,
)
from server.modules.handlers.world.position.area_service import resolve_zone_from_position
from server.modules.handlers.world.state.runtime import (
    broadcast_region_weather,
    broadcast_system_message,
    broadcast_world_time,
    pack_wow_game_time,
    resolve_weather_type,
)
from server.modules.handlers.world.teleport.teleport_service import (
    add_teleport as add_named_teleport,
    find_teleport,
    nearest_teleport,
    remove_teleport as remove_named_teleport,
    search_teleports,
)
from server.modules.handlers.world.title_service import (
    apply_title,
    build_title_earned_payload,
    resolve_title_bit,
    title_is_known,
)

CommandHandler = Callable[[Any, list[str]], list[tuple[str, bytes]]]


@dataclass(frozen=True)
class Command:
    handler: CommandHandler
    usage: str
    allow_args: bool = True
    require_args: bool = False


PRIMARY_COMMANDS: dict[str, Command] = {}
ALIASES: dict[str, str] = {}
COMMANDS: dict[str, Command] = {}
HELPERS: dict[str, Any] = {}
_OBJECT_END = 0x8
_UNIT_END = _OBJECT_END + 0x98
_PLAYER_FIELD_COINAGE = _UNIT_END + 0x3DD
MORPH_NAME_TO_DISPLAY = {
    # Boss / heroes
    "sylvanas": 28213,
    "arthas": 22234,
    "jaina": 30863,
    "deathwing": 32809,
    "illidan": 21137,
    "thrall": 4527,

    # Undead / spooky
    "skeleton": 9784,
    "lich": 15945,

    # Creatures
    "murloc": 21723, 
    "elemental": 171,
    "baby_dragon": 400,

    # Fun / iconic
    "wisp": 10045,
}
UNIT_FIELD_DISPLAYID = 69
CHEAT_BAG_ENTRY = 82446
CHEAT_BAG_COUNT = 4
CHEAT_TARGET_LEVEL = 90
CHEAT_EQUIPMENT_SLOTS = tuple(range(19))
CHEAT_BAG_SLOTS = tuple(range(19, 23))
CHEAT_CLASS_NAMES = {
    1: "warrior",
    2: "paladin",
    3: "hunter",
    4: "rogue",
    5: "priest",
    6: "deathknight",
    7: "shaman",
    8: "mage",
    9: "warlock",
    10: "monk",
    11: "druid",
}
CHEAT_MOUNT_ACTION_BUTTONS = (
    ("Ancient Frostsaber", 16056),
    ("Purple Skeletal Warhorse", 23246),
    ("Shado-Pan Riding Tiger", 129932),
    ("Ashes of Al'ar", 40192),
    ("Big Love Rocket", 71342),
    ("Heavenly Onyx Cloud Serpent", 127158),
    ("Icebound Frostbrood Vanquisher", 72807),
    ("Invincible", 72286),
    ("Mimiron's Head", 63796),
    ("Red Flying Cloud", 130092),
)
CHEAT_ACTION_BUTTON_TYPE_MOUNT = 0


def configure(**helpers: Any) -> None:
    """Store helper callbacks provided by the chat opcode module."""
    HELPERS.update(helpers)


def _helper(name: str) -> Any:
    """Return a configured helper or fail fast."""
    if name == "build_map_exploration_update_responses":
        legacy_helper = HELPERS.get("build_map_exploration_update_response")
        if callable(legacy_helper):
            return lambda session, reveal_all: [legacy_helper(session, reveal_all)]
    if name not in HELPERS:
        raise RuntimeError(f"chat command helper not configured: {name}")
    return HELPERS[name]


def register_command(
    name: str,
    usage: str,
    *,
    allow_args: bool = True,
    require_args: bool = False,
    aliases: tuple[str, ...] = (),
) -> Callable[[CommandHandler], CommandHandler]:
    """Keep command metadata next to the handler definition."""
    def decorator(func: CommandHandler) -> CommandHandler:
        setattr(
            func,
            "_chat_command",
            Command(
                handler=func,
                usage=usage,
                allow_args=bool(allow_args),
                require_args=bool(require_args),
            ),
        )
        setattr(func, "_chat_aliases", tuple(aliases))
        setattr(func, "_chat_command_name", name)
        return func

    return decorator


def _notification_response(message: str) -> list[tuple[str, bytes]]:
    """Build a system chat response."""
    helper = HELPERS.get("notification_response")
    if callable(helper):
        return helper(message)
    return [("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(message))]


def _append_feedback_response(
    responses: list[tuple[str, bytes]] | None,
    message: str,
) -> list[tuple[str, bytes]]:
    """Append a system chat line after command responses."""
    helper = HELPERS.get("append_feedback_response")
    if callable(helper):
        return helper(responses, message)
    merged = list(responses or [])
    merged.extend(_notification_response(message))
    return merged


def _build_login_inventory_sync(session) -> list[tuple[str, bytes]]:
    """Run the existing inventory sync path."""
    helper = HELPERS.get("build_login_inventory_sync_responses")
    if callable(helper):
        return list(helper(session))
    return list(build_login_inventory_sync_responses(session))


def _sender_chat_guid(session) -> int:
    """Resolve the best sender guid for chat packets."""
    return int(
        getattr(session, "char_guid", 0)
        or getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or 0
    )


def _split_command(message: str) -> tuple[str, list[str]] | None:
    """Normalize raw chat text into command name and args."""
    command = str(message or "").strip()
    if not command:
        return None

    parts = command.split()
    head = parts[0].lower()

    if head.startswith("."):
        head = head[1:]
    elif head not in {"mapcheat"}:
        return None

    return head, parts[1:]


def _is_explicit_command(message: str) -> bool:
    """Treat leading dot as an explicit command attempt."""
    return str(message or "").strip().startswith(".")


def _call_command(name: str, session, args: list[str]) -> list[tuple[str, bytes]]:
    """Call a command from the runtime lookup map."""
    return COMMANDS[name].handler(session, args)


def _client_bag_for_item(session, item) -> int | None:
    """Resolve inventory internal bag ids to client bag ids for move/equip commands."""
    bag = int(getattr(item, "bag", 0) or 0)
    if bag == 0:
        return 0

    state = getattr(session, "inventory_state", None)
    if state is None:
        return None
    for bag_slot in CHEAT_BAG_SLOTS:
        bag_item = state.get(0, int(bag_slot))
        if bag_item and int(getattr(bag_item, "item_guid", 0) or 0) == bag:
            return int(bag_slot) - 18
    return None


def _build_action_button_update(session) -> list[tuple[str, bytes]]:
    try:
        from server.modules.handlers.world.login.packets import build_login_packet
    except Exception as exc:
        Logger.warning("[Cheat] action button update unavailable: %s", exc)
        return []

    payload = build_login_packet(
        "SMSG_UPDATE_ACTION_BUTTONS",
        SimpleNamespace(
            action_buttons=list(getattr(session, "action_buttons", []) or []),
            action_button_state=1,
        ),
    )
    if payload is None:
        return []
    return [("SMSG_UPDATE_ACTION_BUTTONS", payload)]


def _gps_strings(session) -> tuple[str, str]:
    """Build chat and log strings for the current position."""
    map_id = int(getattr(session, "map_id", 0) or 0)
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)
    z = float(getattr(session, "z", 0.0) or 0.0)
    orientation = float(getattr(session, "orientation", 0.0) or 0.0)

    feedback = f"[GPS] map={map_id} x={x:.2f} y={y:.2f} z={z:.2f} o={orientation:.2f}"
    tel_coord = f".tel coord {map_id} {x:.2f} {y:.2f} {z:.2f} {orientation:.2f}"

    return feedback, tel_coord


def _resolve_max_level(session) -> int:
    """Use class level stats as the safest level cap source."""
    rows = DatabaseConnection.get_level_stats_for_class(
        int(getattr(session, "race", 0) or 0),
        int(getattr(session, "class_id", 0) or 0),
    )
    if rows:
        return max(int(getattr(row, "level", 0) or 0) for row in rows)
    return 90


def _clamp_level(session, level: int) -> int:
    """Keep level in a valid range."""
    return max(1, min(int(level), int(_resolve_max_level(session))))


def _parse_level_target(session, args: list[str]) -> tuple[int, str] | None:
    """Parse .level forms into a target level."""
    current_level = int(getattr(session, "level", 1) or 1)

    if not args:
        return current_level + 1, "add"

    if len(args) == 1:
        try:
            delta = int(args[0], 0)
        except ValueError:
            return None
        return current_level + int(delta), "add"

    if len(args) == 2 and str(args[0]).strip().lower() == "set":
        try:
            return int(args[1], 0), "set"
        except ValueError:
            return None

    return None


def _help_lines() -> list[str]:
    """Return help lines for real commands only."""
    return [command.usage for command in PRIMARY_COMMANDS.values()]


def _resolve_morph_display_id(arg: str) -> int:
    """Resolve a morph target from display id or simple name."""
    value = str(arg or "").strip()
    if not value:
        return 0
    try:
        return int(value, 0)
    except ValueError:
        return int(MORPH_NAME_TO_DISPLAY.get(value.casefold(), 0) or 0)


def _resolve_native_display_id(session) -> int:
    """Resolve the normal player display id for demorph fallback."""
    race = int(getattr(session, "race", 0) or 0)
    gender = int(getattr(session, "gender", 0) or 0)
    fallback = int(
        getattr(session, "original_display_id", 0)
        or getattr(session, "native_display_id", 0)
        or 15476
    )
    try:
        from server.modules.handlers.world.login.packets import _resolve_player_display_id
    except ImportError:
        return fallback
    return int(_resolve_player_display_id(race, gender, fallback) or fallback)


def dump_command_map() -> None:
    """Log the command map in a simple name -> usage format."""
    for name, command in PRIMARY_COMMANDS.items():
        Logger.info("[CHAT][COMMAND] %s -> %s", name, command.usage)
    for alias, name in ALIASES.items():
        Logger.info("[CHAT][COMMAND] %s -> %s", alias, PRIMARY_COMMANDS[name].usage)


def handle_command(session, message: str) -> Optional[list[tuple[str, bytes]]]:
    """Parse, resolve, validate, and dispatch one command."""
    explicit_command = _is_explicit_command(message)
    parsed = _split_command(message)
    if parsed is None:
        if explicit_command:
            return _notification_response(f"Unknown command: {str(message or '').strip()}")
        return None

    command_name, args = parsed
    command = COMMANDS.get(command_name)
    if command is None:
        if explicit_command:
            return _notification_response(f"Unknown command: {str(message or '').strip()}")
        return None

    if not command.allow_args and args:
        return _notification_response(f"Usage: {command.usage}")
    if command.require_args and not args:
        return _notification_response(f"Usage: {command.usage}")

    return command.handler(session, args)


@register_command("help", ".help")
def cmd_help(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Return a compact list of available commands."""
    responses = _notification_response("[Help] commands:")
    for usage in _help_lines():
        responses.extend(_notification_response(usage))
    return responses


@register_command("roll", ".roll")
def cmd_roll(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Roll 1-100 and broadcast the result as a system message."""
    roll = random.randint(1, 100)
    message = f"{session.player_name} rolls {roll} (1-100)"
    broadcast_system_message(message, scope="world")
    return []


@register_command("gps", ".gps", allow_args=False)
def cmd_gps(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Show position in chat and log a ready-to-paste telxyz command."""
    feedback, telxyz = _gps_strings(session)
    Logger.info(feedback)
    Logger.info(telxyz)
    return _notification_response(feedback)


@register_command("spawngo", ".spawngo", allow_args=False)
def cmd_spawngo(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Load nearby gameobjects from the world database for the current player."""
    from server.modules.game.guid import GameObjectGuid, MoTransportGuid
    from server.modules.handlers.world.bootstrap.gameobjects import (
        _build_gameobject_update_payload,
    )
    from server.modules.handlers.world.bootstrap.playerobjects import (
        make_update_object_response,
    )

    loaded_gameobjects = getattr(session, "loaded_gameobjects", None)
    if not isinstance(loaded_gameobjects, set):
        loaded_gameobjects = set()
        session.loaded_gameobjects = loaded_gameobjects

    map_id = int(getattr(session, "map_id", 0) or 0)
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)
    realm_id = int(getattr(session, "realm_id", 1) or 1)
    entries = DatabaseConnection.get_gameobjects_near(map_id, x, y, radius=120.0, limit=200)

    responses: list[tuple[str, bytes]] = []
    for entry in entries:
        if int(entry.get("type", 0) or 0) == 15:
            world_guid = MoTransportGuid.from_spawn_guid(int(entry.get("guid", 0) or 0))
        else:
            world_guid = GameObjectGuid.from_spawn_guid(
                int(entry.get("guid", 0) or 0),
                realm_id,
            )
        if world_guid in loaded_gameobjects:
            continue
        loaded_gameobjects.add(world_guid)
        Logger.info(
            "[SPAWN_GO] entry=%s pos=(%.2f, %.2f, %.2f)",
            int(entry.get("entry", 0) or 0),
            float(entry.get("x", 0.0) or 0.0),
            float(entry.get("y", 0.0) or 0.0),
            float(entry.get("z", 0.0) or 0.0),
        )
        entry["world_guid"] = world_guid
        if int(entry.get("type", 0) or 0) == 15:
            entry["_transport_create_source_path"] = "database"
        responses.append(
            make_update_object_response(
                _build_gameobject_update_payload(map_id=map_id, entry=entry, realm_id=realm_id)
            )
        )

    count = len(responses)
    Logger.info("[SPAWN_GO] count=%s", count)

    message = f"[SpawnGO] loaded {count} gameobjects"
    responses.extend(_notification_response(message))
    return responses


def _gameobject_cache_status() -> dict[str, int | bool]:
    config = ConfigLoader.load_config()
    preload_enabled = bool(config.get("worldserver", {}).get("preload_gameobjects", True))
    cache_by_map = getattr(DatabaseConnection, "_cache_gameobjects_by_map", {}) or {}
    cache_loaded = bool(getattr(DatabaseConnection, "_cache_gameobjects_loaded", False))
    total = sum(len(entries) for entries in cache_by_map.values())
    return {
        "preload_enabled": preload_enabled,
        "cache_loaded": cache_loaded,
        "maps": int(len(cache_by_map)),
        "total": int(total),
    }


def _hide_loaded_gameobjects(session) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.opcodes.movement import _build_out_of_range_update_object_payload

    loaded_gameobjects = getattr(session, "loaded_gameobjects", None)
    if not isinstance(loaded_gameobjects, set):
        loaded_gameobjects = set()
        session.loaded_gameobjects = loaded_gameobjects

    map_id = int(getattr(session, "map_id", 0) or 0)
    responses = [
        (
            "SMSG_UPDATE_OBJECT",
            _build_out_of_range_update_object_payload(map_id=map_id, guid=int(guid)),
        )
        for guid in sorted(int(guid) for guid in loaded_gameobjects)
    ]
    loaded_gameobjects.clear()
    loaded_transports = getattr(session, "loaded_transport_entries", None)
    if isinstance(loaded_transports, dict):
        loaded_transports.clear()
    return responses


def _show_nearby_gameobjects(session) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.bootstrap.gameobjects import build_database_gameobject_responses

    loaded_gameobjects = getattr(session, "loaded_gameobjects", None)
    if not isinstance(loaded_gameobjects, set):
        loaded_gameobjects = set()
        session.loaded_gameobjects = loaded_gameobjects

    return list(build_database_gameobject_responses(session, loaded_guids=loaded_gameobjects))


def _hide_loaded_npcs(session) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.opcodes.movement import _build_out_of_range_update_object_payload

    loaded_npcs = getattr(session, "loaded_npcs", None)
    if not isinstance(loaded_npcs, set):
        loaded_npcs = set()
        session.loaded_npcs = loaded_npcs

    map_id = int(getattr(session, "map_id", 0) or 0)
    responses = [
        (
            "SMSG_UPDATE_OBJECT",
            _build_out_of_range_update_object_payload(map_id=map_id, guid=int(guid)),
        )
        for guid in sorted(int(guid) for guid in loaded_npcs)
    ]
    loaded_npcs.clear()
    return responses


def _show_nearby_npcs(session) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.bootstrap.creatures import build_database_creature_responses

    loaded_npcs = getattr(session, "loaded_npcs", None)
    if not isinstance(loaded_npcs, set):
        loaded_npcs = set()
        session.loaded_npcs = loaded_npcs

    responses = list(build_database_creature_responses(session, loaded_guids=loaded_npcs))
    Logger.info(
        "[WorldNPC] show map=%s x=%.3f y=%.3f z=%.3f loaded=%s responses=%s",
        int(getattr(session, "map_id", 0) or 0),
        float(getattr(session, "x", 0.0) or 0.0),
        float(getattr(session, "y", 0.0) or 0.0),
        float(getattr(session, "z", 0.0) or 0.0),
        int(len(loaded_npcs)),
        int(len(responses)),
    )
    return responses


def _refresh_nearby_npcs(session) -> tuple[list[tuple[str, bytes]], int]:
    """Force a client-side NPC refresh, then return all packets and create count."""
    clear_responses = _hide_loaded_npcs(session)
    show_responses = _show_nearby_npcs(session)
    return clear_responses + show_responses, len(show_responses)


def _npc_cache_status() -> dict[str, int | bool]:
    config = ConfigLoader.load_config()
    preload_enabled = bool(config.get("worldserver", {}).get("preload_npcs", False))
    cache_by_map = getattr(DatabaseConnection, "_cache_creatures_by_map", {}) or {}
    cache_loaded = bool(getattr(DatabaseConnection, "_cache_creatures_loaded", False))
    template_count = len(getattr(DatabaseConnection, "_cache_creature_templates", {}) or {})
    total = sum(len(entries) for entries in cache_by_map.values())
    return {
        "preload_enabled": preload_enabled,
        "cache_loaded": cache_loaded,
        "maps": int(len(cache_by_map)),
        "total": int(total),
        "templates": int(template_count),
    }


def world_go_status(session, _args):
    status = _gameobject_cache_status()
    visible = bool(getattr(session, "gameobjects_visible", True))
    loaded_now = len(getattr(session, "loaded_gameobjects", set()) or ())
    return _notification_response(
        f"[WorldGO] visible={int(visible)} loaded_now={int(loaded_now)} "
        f"cache_loaded={int(status['cache_loaded'])} preload={int(status['preload_enabled'])} "
        f"cached_total={int(status['total'])} maps={int(status['maps'])}"
    )


def world_go_hide(session, _args):
    session.gameobjects_visible = False
    responses = _hide_loaded_gameobjects(session)
    responses.extend(_notification_response("[WorldGO] hidden"))
    return responses


def world_go_show(session, _args):
    from server.modules.handlers.world.feature_config import gameobjects_enabled

    if not gameobjects_enabled():
        return _notification_response("[WorldGO] disabled by config")
    session.gameobjects_visible = True
    session.last_gameobject_stream_at = 0.0
    responses = _show_nearby_gameobjects(session)
    responses.extend(_notification_response(f"[WorldGO] shown {len(responses)} updates"))
    return responses


def world_npc_status(session, _args):
    status = _npc_cache_status()
    visible = bool(getattr(session, "npcs_visible", False))
    auto = bool(getattr(session, "npc_auto_stream", False))
    loaded_now = len(getattr(session, "loaded_npcs", set()) or ())
    return _notification_response(
        f"[WorldNPC] visible={int(visible)} auto={int(auto)} loaded_now={int(loaded_now)} "
        f"cache_loaded={int(status['cache_loaded'])} preload={int(status['preload_enabled'])} "
        f"cached_total={int(status['total'])} templates={int(status['templates'])} maps={int(status['maps'])}"
    )


def world_npc_hide(session, _args):
    session.npcs_visible = False
    session.npc_auto_stream = False
    responses = _hide_loaded_npcs(session)
    npc_flags_by_guid = getattr(session, "npc_flags_by_guid", None)
    if isinstance(npc_flags_by_guid, dict):
        npc_flags_by_guid.clear()
    responses.extend(_notification_response("[WorldNPC] hidden"))
    return responses


def world_npc_show(session, _args):
    from server.modules.handlers.world.feature_config import npcs_enabled

    if not npcs_enabled():
        return _notification_response("[WorldNPC] disabled by config")
    session.npcs_visible = True
    session.last_npc_stream_at = 0.0
    responses, shown_count = _refresh_nearby_npcs(session)
    responses.extend(_notification_response(f"[WorldNPC] shown {shown_count} updates"))
    return responses


def world_npc_on(session, _args):
    from server.modules.handlers.world.feature_config import npcs_enabled

    if not npcs_enabled():
        return _notification_response("[WorldNPC] disabled by config")
    session.npcs_visible = True
    session.npc_auto_stream = True
    session.last_npc_stream_at = 0.0
    responses, shown_count = _refresh_nearby_npcs(session)
    responses.extend(_notification_response(f"[WorldNPC] auto on {shown_count} updates"))
    return responses


def world_npc_off(session, _args):
    session.npc_auto_stream = False
    return _notification_response("[WorldNPC] auto off")


def world_lift_status(session, _args):
    loaded_now = len(getattr(session, "loaded_transport_entries", {}) or {})
    return _notification_response(
        f"[TransportElevator] legacy lift controls removed; runtime_transports={int(loaded_now)}"
    )


def world_lift_on(session, _args):
    return _notification_response("[TransportElevator] legacy lift controls removed; use WorldTransportManager")


def world_lift_off(session, _args):
    return _notification_response("[TransportElevator] legacy lift controls removed; use WorldTransportManager")


def world_lift_show(session, args):
    return world_lift_on(session, args)


def world_lift_hide(session, args):
    return world_lift_off(session, args)


def world_boat_test(session, args):
    return _notification_response("[WorldBoat] manual test disabled; movement is DBC-only")


def world_boat_clear(session, _args):
    return _notification_response("[WorldBoat] manual test disabled; nothing to clear")


def world_boat_status(session, _args):
    return _notification_response("[WorldBoat] manual_loaded=0 disabled=1")


@register_command("taxi", ".taxi <on|off|status>")
def cmd_taxi(session, args: list[str]) -> list[tuple[str, bytes]]:
    if not args:
        enabled = bool(getattr(session, "taxi_cheat_enabled", False))
        return _notification_response(f"[Taxi] cheat={int(enabled)}")

    sub = str(args[0]).lower()
    if sub == "on":
        session.taxi_cheat_enabled = True
        return _notification_response("[Taxi] cheat on")
    if sub == "off":
        session.taxi_cheat_enabled = False
        return _notification_response("[Taxi] cheat off")
    if sub == "status":
        enabled = bool(getattr(session, "taxi_cheat_enabled", False))
        return _notification_response(f"[Taxi] cheat={int(enabled)}")
    return _notification_response("Usage: .taxi <on|off|status>")


@register_command("world", ".world <go|npc|lift|boat> <hide|show|status|on|off|test|clear>")
def cmd_world(session, args: list[str]) -> list[tuple[str, bytes]]:
    if len(args) < 2:
        return _notification_response("Usage: .world <go|npc|lift|boat> <hide|show|status|on|off|test|clear>")

    kind = args[0].lower()
    sub = args[1].lower()
    if kind == "go":
        if sub == "hide":
            return world_go_hide(session, args[2:])
        if sub == "show":
            return world_go_show(session, args[2:])
        if sub == "status":
            return world_go_status(session, args[2:])
    if kind == "npc":
        if sub == "hide":
            return world_npc_hide(session, args[2:])
        if sub == "show":
            return world_npc_show(session, args[2:])
        if sub == "status":
            return world_npc_status(session, args[2:])
        if sub == "on":
            return world_npc_on(session, args[2:])
        if sub == "off":
            return world_npc_off(session, args[2:])
    if kind == "lift":
        if sub == "hide":
            return world_lift_hide(session, args[2:])
        if sub == "show":
            return world_lift_show(session, args[2:])
        if sub == "status":
            return world_lift_status(session, args[2:])
        if sub == "on":
            return world_lift_on(session, args[2:])
        if sub == "off":
            return world_lift_off(session, args[2:])
    if kind == "boat":
        if sub == "test":
            return world_boat_test(session, args[2:])
        if sub == "clear":
            return world_boat_clear(session, args[2:])
        if sub == "status":
            return world_boat_status(session, args[2:])
    return _notification_response("Usage: .world <go|npc|lift|boat> <hide|show|status|on|off|test|clear>")


@register_command("level", ".level [delta]|set <level>")
def cmd_level(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Adjust or set player level."""
    parsed = _parse_level_target(session, args)
    if parsed is None:
        return _notification_response("Usage: .level [delta]|set <level>")

    requested_level, mode = parsed
    current_level = int(getattr(session, "level", 1) or 1)
    target_level = _clamp_level(session, requested_level)
    char_guid = int(getattr(session, "char_guid", 0) or 0)
    realm_id = int(getattr(session, "realm_id", 0) or 0)

    session.previous_level = int(current_level)
    session.level = int(target_level)
    if char_guid > 0 and realm_id > 0:
        DatabaseConnection.save_character_level(
            char_guid,
            realm_id,
            int(target_level),
            xp=0,
        )

    Logger.info(
        "[Level] mode=%s guid=%s level=%s->%s requested=%s",
        mode,
        char_guid,
        current_level,
        target_level,
        requested_level,
    )
    responses = list(_helper("build_level_command_responses")(session))
    return responses


@register_command("speed", ".speed <multiplier|default>")
def cmd_speed(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Change or reset movement speeds."""
    from server.modules.handlers.world.opcodes.movement import resync_movement

    if len(args) != 1:
        return _notification_response("Usage: .speed <multiplier|default>")

    value = str(args[0]).strip().lower()
    multiplier_label = value
    if value in {"default", "reset"}:
        spells_handlers._restore_default_movement_speeds(session)
        multiplier_label = "1.0"
    else:
        try:
            speed_multiplier = float(value)
        except ValueError:
            return _notification_response("Usage: .speed <multiplier|default>")
        if not (0.1 <= speed_multiplier <= 50.0):
            return _notification_response("Usage: .speed <0.1-50.0>")
        spells_handlers.set_custom_run_speed(
            session,
            float(getattr(spells_handlers, "_DEFAULT_RUN_SPEED", 7.0) or 7.0) * speed_multiplier,
        )
        multiplier_label = f"{float(speed_multiplier):.1f}"

    Logger.info(
        "[Speed] multiplier=%s run=%.2f",
        multiplier_label,
        float(getattr(session, "run_speed", 0.0) or 0.0),
    )
    responses = list(_helper("build_speed_command_responses")(session))
    responses.extend(resync_movement(session))
    Logger.debug("[SPEED] resync applied")
    responses.append(
        (
            "SMSG_MESSAGECHAT",
            encode_skyfire_messagechat_system_payload(
                f"[Speed] run={float(getattr(session, 'run_speed', 0.0) or 0.0):.2f}"
            ),
        )
    )
    return responses


@register_command("weather", ".weather <clear|rain|snow|storm|sand|id> [0.0-1.0]")
def cmd_weather(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Broadcast region weather to nearby players."""
    if len(args) not in (1, 2):
        Logger.info("[Weather] Usage: .weather <clear|rain|snow|storm|sand|id> [0.0-1.0]")
        return []

    weather_key = str(args[0]).strip().lower()
    density = 0.0 if weather_key in ("clear", "fine", "sun") else 1.0
    abrupt = 1
    if len(args) == 2:
        try:
            density = max(0.0, min(1.0, float(args[1])))
        except ValueError:
            Logger.info("[Weather] Invalid density command=%r", " ".join(args))
            return []

    try:
        weather_type = int(weather_key)
    except ValueError:
        weather_type = resolve_weather_type(weather_key, density)

    if weather_type < 0:
        Logger.info("[Weather] Unknown weather command=%r", " ".join(args))
        return []

    Logger.info(
        "[Weather] type=%s density=%.2f abrupt=%s",
        int(weather_type),
        float(density),
        abrupt,
    )
    broadcast_region_weather(
        session,
        int(weather_type),
        float(density),
        abrupt,
        announce=f"[Weather] type={int(weather_type)} density={float(density):.2f}",
    )
    return _notification_response(f"[Weather] type={int(weather_type)} density={float(density):.2f}")


@register_command("time", ".time <HH:MM|day|night|dawn|dusk|noon|midnight>")
def cmd_time(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Set the world time override."""
    if len(args) != 1:
        Logger.info("[Time] Usage: .time <HH:MM|day|night|dawn|dusk|noon|midnight>")
        return []

    arg = str(args[0]).strip().lower()
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
            Logger.info("[Time] Invalid time command=%r", arg)
            return []
        try:
            hour = int(time_parts[0])
            minute = int(time_parts[1])
        except ValueError:
            Logger.info("[Time] Invalid time command=%r", arg)
            return []
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            Logger.info("[Time] Out-of-range time command=%r", arg)
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
        "[Time] hour=%02d minute=%02d offset=%s packed=0x%08X",
        int(hour),
        int(minute),
        int(session.time_offset),
        int(session.game_time),
    )
    broadcast_world_time(
        int(hour),
        int(minute),
        announce=f"[Time] {hour:02d}:{minute:02d}",
    )
    return _notification_response(f"[Time] {hour:02d}:{minute:02d}")


@register_command("system", ".system <message>", require_args=True)
def cmd_system(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Broadcast a system message."""
    message = " ".join(args).strip()
    if not message:
        return _notification_response("Usage: .system <message>")
    Logger.info("[SystemChat] message=%r", message)
    broadcast_system_message(message, scope="world")
    return _notification_response(f"[System] sent: {message}")


@register_command("learnspell", ".learnspell <spell_id>", require_args=True)
def cmd_learnspell(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Learn one runtime-only spell for the current session."""
    if len(args) != 1:
        return _notification_response("Usage: .learnspell <spell_id>")

    try:
        spell_id = int(args[0], 0)
    except ValueError:
        return _notification_response("Usage: .learnspell <spell_id>")

    if spell_id <= 0:
        return _notification_response("Usage: .learnspell <spell_id>")

    spells_handlers.ensure_spell_known(session, spell_id)
    player_name = (
        str(getattr(session, "player_name", "") or "").strip()
        or f"Player{int(getattr(session, 'char_guid', 0) or 0)}"
    )
    Logger.info("[LEARN_SPELL] player=%s spell=%s", player_name, int(spell_id))

    responses = [spells_handlers.build_known_spells_response(session)]
    responses.extend(_notification_response(f"Learned spell {int(spell_id)}"))
    return responses


@register_command("castspell", ".castspell <spell_id>", require_args=True)
def cmd_castspell(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Cast one runtime test spell through the existing spell path."""
    if len(args) != 1:
        return _notification_response("Usage: .castspell <spell_id>")

    try:
        spell_id = int(args[0], 0)
    except ValueError:
        return _notification_response("Usage: .castspell <spell_id>")

    if spell_id <= 0:
        return _notification_response("Usage: .castspell <spell_id>")

    player_name = (
        str(getattr(session, "player_name", "") or "").strip()
        or f"Player{int(getattr(session, 'char_guid', 0) or 0)}"
    )
    Logger.info("[CAST_SPELL] player=%s spell=%s", player_name, int(spell_id))

    if not bool(getattr(spells_handlers, "is_mount_spell", lambda _spell_id: False)(int(spell_id))):
        return _notification_response(f"Spell {int(spell_id)} has no runtime cast handler")

    responses = list(spells_handlers.handle_mount(session, int(spell_id)))
    responses.extend(_notification_response(f"Casted spell {int(spell_id)}"))
    return responses

def build_spell_go(player, spell_id: int) -> tuple[str, bytes]:
    payload = bytearray.fromhex(
        "46 00 00 00 00 00 00 00 00 04 00 02 01 00 80 00 "
        "05 28 00 C4 00 00 B4 00 00 01 21 00 02 06 81 E5 "
        "B6 05 06 00 09 00 00 00 E0 93 04 00 02 01 F4 7D "
        "00 00 02 06"
    )

    # --- PATCH SPELL ID ---
    spell_offset = 44
    payload[spell_offset:spell_offset + 4] = int(spell_id).to_bytes(4, "little")

    # --- PATCH GUID (packed) ---
    guid = int(player.char_guid)

    mask = 0
    bytes_out = bytearray()

    for i in range(8):
        b = (guid >> (i * 8)) & 0xFF
        if b != 0:
            mask |= (1 << i)
            bytes_out.append(b)

    # ⚠️ Här måste du veta exakt offset i packet
    guid_mask_offset = 0
    payload[guid_mask_offset] = mask

    # skriv bytes direkt efter mask
    payload[guid_mask_offset + 1:guid_mask_offset + 1 + len(bytes_out)] = bytes_out

    return ("SMSG_SPELL_GO", bytes(payload))


def build_spell_start(player, spell_id: int) -> tuple[str, bytes]:
    payload = bytearray.fromhex(
        "00 00 00 40 00 00 00 00 00 00 00 00 40 00 01 00 "
        "EA 00 5C 00 00 00 0B 38 DC 05 00 00 E0 93 04 00 "
        "00 02 08 00 00 06 01 06 02 02 F4 7D 00 00"
    )

    spell_offset = 42
    payload[spell_offset:spell_offset + 4] = int(spell_id).to_bytes(4, "little")
    return ("SMSG_SPELL_START", bytes(payload))

@register_command("mount", ".mount", allow_args=False)
def cmd_mount(session, args: list[str]) -> list[tuple[str, bytes]]:
    mount_spell_id = int(_helper("chat_mount_spell_id"))
    Logger.info("[Mount] spell_id=%s", mount_spell_id)
    responses = list(spells_handlers.handle_mount(session, mount_spell_id))
    Logger.info(
        "[Mount] speed=%.2f mounted=%s",
        float(getattr(session, "run_speed", 0.0) or 0.0),
        bool(getattr(session, "is_mounted", False)),
    )
    Logger.info("[Mount] committed")
    return _append_feedback_response(responses, "[Mount] mount requested")

@register_command("dismount", ".dismount", allow_args=False)
def cmd_dismount(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Clear the debug mount display."""
    Logger.info("[Mount] .dismount -> clear display")
    responses = list(spells_handlers.dismount(session))
    Logger.info(
        "[Mount] spell_id=%s speed=%.2f",
        int(getattr(session, "mount_spell", 0) or 0),
        float(getattr(session, "run_speed", 0.0) or 0.0),
    )
    Logger.info("[Mount] committed")
    Logger.info("[Mount][Debug] chat .dismount responses=%s", len(responses))
    return _append_feedback_response(responses, "[Mount] dismount requested")


def _parse_money_delta(raw: str) -> int | None:
    value = str(raw or "").lower().strip()
    if not value:
        return None

    if value.lstrip("-").isdigit():
        return int(value)

    sign = -1 if value.startswith("-") else 1
    if value[0:1] in {"+", "-"}:
        value = value[1:]

    pattern = re.compile(r"(?:(\d+)g)?(?:(\d+)s)?(?:(\d+)c)?")
    match = pattern.fullmatch(value)
    if not match:
        return None

    g, s, c = match.groups()
    copper = int(g or 0) * 10000
    copper += int(s or 0) * 100
    copper += int(c or 0)
    if copper == 0:
        return None
    return sign * copper


@register_command("addmoney", ".addmoney", allow_args=True)
def cmd_addmoney(session, args: list[str]):
    from server.modules.handlers.world.bootstrap.playerobjects import build_multi_u32_update_object_payload
    from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload

    def msg(text: str):
        return [("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(text))]

    if not args or not args[0].strip():
        return msg("Usage: .addmoney <copper | 10g10s10c>")

    raw = args[0].lower().strip()
    copper = _parse_money_delta(raw)
    if copper is None:
        return msg("Invalid format. Example: 10g10s10c")

    current = int(getattr(session, "money", 0) or 0)
    new_amount = max(0, current + copper)
    session.money = new_amount

    try:
        DatabaseConnection.update_character_money(
            int(session.char_guid),
            int(session.realm_id),
            int(new_amount),
        )
    except Exception as exc:
        Logger.warning(
            "[Money] DB update failed guid=%s realm=%s amount=%s error=%s",
            int(getattr(session, "char_guid", 0) or 0),
            int(getattr(session, "realm_id", 0) or 0),
            int(new_amount),
            exc,
        )

    money_value = int(new_amount) & 0xFFFFFFFFFFFFFFFF
    money_fields = [
        (_PLAYER_FIELD_COINAGE, money_value & 0xFFFFFFFF),
        (_PLAYER_FIELD_COINAGE + 1, (money_value >> 32) & 0xFFFFFFFF),
    ]

    return [
        (
            "SMSG_UPDATE_OBJECT",
            build_multi_u32_update_object_payload(
                map_id=int(getattr(session, "map_id", 0) or 0),
                guid=_sender_chat_guid(session),
                field_updates=money_fields,
            ),
        ),
        ("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(f"{copper:+d} copper")),
    ]


@register_command("title", ".title <bitIndex|explorer|off>", require_args=True)
def cmd_title(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Grant and activate a player title by title bit index."""
    raw = str(args[0] if args else "").strip().lower()
    if raw in {"off", "none", "clear", "0"}:
        responses = apply_title(session, 0, grant_if_missing=False)
        return _append_feedback_response(responses, "[Title] cleared")

    try:
        bit_index = resolve_title_bit(raw)
    except ValueError:
        return _notification_response("Usage: .title <bitIndex|explorer|off>")

    try:
        was_known = False
        known_titles = getattr(session, "known_titles_raw", "")
        was_known = title_is_known(known_titles, bit_index)
        responses = apply_title(session, bit_index, grant_if_missing=True)
    except ValueError as exc:
        return _notification_response(f"[Title] {exc}")

    if bit_index > 0 and not was_known:
        responses.append(("SMSG_TITLE_EARNED", build_title_earned_payload(bit_index)))
    return _append_feedback_response(responses, f"[Title] active bit={bit_index}")


@register_command(
    "achievement",
    ".achievement <add|fix> [name]",
    require_args=True,
)
def cmd_achievement(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Grant an achievement by id or lazy name search."""
    subcommand = str(args[0] if args else "").casefold()
    if subcommand == "fix":
        responses = repair_achievement_visibility(session)
        responses.extend(_notification_response("[Achievement] fixed visible progress"))
        return responses

    if len(args) < 2 or subcommand != "add":
        return _notification_response("Usage: .achievement <add|fix> [name]")

    query = " ".join(args[1:]).strip()
    matches = find_achievement_by_name(query, limit=8)
    if not matches:
        return _notification_response(f"[Achievement] no match: {query}")

    exact_query = " ".join(query.split()).casefold()
    exact_matches = [
        item for item in matches
        if " ".join(str(item.name or "").split()).casefold() == exact_query
    ]
    if len(matches) > 1 and not exact_matches:
        summary = ", ".join(f"{item.achievement_id}:{item.name}" for item in matches)
        return _notification_response(f"[Achievement] matches: {summary}")

    achievement = exact_matches[0] if exact_matches else matches[0]
    earned, responses = grant_achievement_by_id(session, achievement.achievement_id)
    status = "added" if earned else "already complete"
    responses.extend(
        _notification_response(
            f"[Achievement] {status}: {achievement.achievement_id} {achievement.name}"
        )
    )
    return responses


@register_command("morph", ".morph <displayId|name|list>", require_args=True)
def cmd_morph(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Morph the player into a target display id or list available morphs."""
    if len(args) != 1:
        return _notification_response("Usage: .morph <displayId|name|list>")

    arg = str(args[0]).strip().lower()

    # morph_map = _helper("morph_name_to_display")
    morph_map = MORPH_NAME_TO_DISPLAY

    # List all morphs
    if arg == "list":
        names = sorted(morph_map.keys())
        names_str = ", ".join(names)
        return _notification_response(f"[Morph] available: {names_str}")

    display_id = _resolve_morph_display_id(arg)
    if display_id <= 0:
        return _notification_response("Morph target not found")

    original_display_id = int(getattr(session, "original_display_id", 0) or 0)
    if original_display_id <= 0:
        original_display_id = int(getattr(session, "display_id", 0) or 0)
        session.original_display_id = int(original_display_id)
        session.native_display_id = int(original_display_id)

    session.display_id = int(display_id)
    session.morph_display_id = int(display_id)
    session.is_morphed = True

    Logger.info("[MORPH] display_id=%s", int(display_id))

    responses = _helper("build_display_id_responses")(session, int(display_id))
    responses.extend(_notification_response(f"[Morph] display={int(display_id)}"))
    return responses


@register_command("demorph", ".demorph", allow_args=False)
def cmd_demorph(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Restore the player's native display id."""
    display_id = int(
        getattr(session, "original_display_id", 0)
        or getattr(session, "native_display_id", 0)
        or _resolve_native_display_id(session)
    )
    current_display_id = int(getattr(session, "display_id", 0) or 0)
    is_morphed = bool(getattr(session, "is_morphed", False))
    if display_id <= 0 or (not is_morphed and (current_display_id <= 0 or current_display_id == display_id)):
        return _notification_response("Not morphed")

    Logger.info("[DEMORPH] restored display_id=%s", int(display_id))
    session.display_id = int(display_id)
    session.morph_display_id = None
    session.is_morphed = False
    session.original_display_id = None
    session.native_display_id = int(display_id)

    responses = _helper("build_display_id_responses")(session, int(display_id))
    responses.extend(_notification_response(f"[Morph] restored={int(display_id)}"))
    return responses


@register_command("additem", ".additem <itemEntry> [count]")
def cmd_additem(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Add an item and run the normal inventory sync."""
    if len(args) not in (1, 2):
        return _notification_response("Usage: .additem <itemEntry> [count]")
    try:
        item_entry = int(args[0], 0)
        item_count = int(args[1], 0) if len(args) == 2 else 1
    except ValueError:
        return _notification_response("Usage: .additem <itemEntry> [count]")

    if bool(getattr(session, "inventory_dirty", False)):
        persist_session_inventory(session)

    result = add_item_to_character(session, item_entry, item_count)
    level = "info" if result.ok else "warning"
    getattr(Logger, level)(
        "[Inventory] .additem entry=%s count=%s result=%s",
        item_entry,
        item_count,
        result.message,
    )

    responses = build_inventory_delta_responses(session, result) if result.ok else []
    responses.extend(_notification_response(f"[Inventory] {result.message}"))
    return responses


@register_command("addtier", ".addtier <class> [tier]")
def cmd_addtier(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Add a predefined tier set or list available tiers."""
    if len(args) < 1:
        return _notification_response("Usage: .addtier <class> [tier]")

    class_name = str(args[0]).strip().lower().replace("_", "")

    tier_set_items = _helper("tier_set_items")
    class_data = tier_set_items.get(class_name)
    if not class_data:
        return _notification_response(f"[AddTier] unknown class: {class_name}")

    # Only class → list tiers
    if len(args) == 1:
        tiers = sorted(class_data.keys())
        tiers_str = ", ".join(str(t) for t in tiers)
        return _notification_response(f"[AddTier] {class_name} tiers: {tiers_str}")

    # Parse tier
    try:
        tier = int(args[1], 0)
    except ValueError:
        return _notification_response("Usage: .addtier <class> <tier>")

    item_entries = class_data.get(tier)
    if not item_entries:
        return _notification_response(f"[AddTier] unsupported tier: {class_name} {tier}")

    Logger.info(
        "[ADDTIER] class=%s tier=%s items=%s",
        class_name,
        tier,
        len(item_entries),
    )

    responses: list[tuple[str, bytes]] = []

    for item_entry in item_entries:
        responses.extend(_call_command("additem", session, [str(int(item_entry)), "1"]))

    responses.extend(_build_login_inventory_sync(session))

    responses.extend(
        _notification_response(
            f"[AddTier] {class_name} T{tier} items={len(item_entries)}"
        )
    )

    return responses


@register_command("cheat", ".cheat")
def cmd_cheat(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Boost the current character with map reveal, bags, tier gear and mount buttons."""
    if args:
        return _notification_response("Usage: .cheat")

    from server.modules.game import inventory as inventory_game

    responses: list[tuple[str, bytes]] = []
    char_guid = int(getattr(session, "char_guid", 0) or 0)

    level_command = COMMANDS.get("level")
    if level_command:
        responses.extend(level_command.handler(session, ["set", str(CHEAT_TARGET_LEVEL)]))

    if bool(getattr(session, "inventory_dirty", False)):
        persist_session_inventory(session)

    inventory_game.refresh_session_inventory(session)

    map_command = COMMANDS.get("mapcheat")
    if map_command:
        responses.extend(map_command.handler(session, ["on"]))

    removed_items = 0
    for slot in CHEAT_EQUIPMENT_SLOTS:
        result = inventory_game.destroy_character_item(session, 0, int(slot))
        if result.ok:
            removed_items += 1
    if removed_items:
        inventory_game.persist_session_inventory(session)
        inventory_game.refresh_session_inventory(session)

    mounted_bags = 0
    stored_bags = 0
    for _index in range(CHEAT_BAG_COUNT):
        result = add_item_to_character(session, CHEAT_BAG_ENTRY, 1)
        if not result.ok or result.item is None:
            Logger.warning("[Cheat] bag add failed: %s", result.message)
            continue

        state = getattr(session, "inventory_state", None)
        free_bag_slot = None
        if state is not None:
            for bag_slot in CHEAT_BAG_SLOTS:
                if state.get(0, int(bag_slot)) is None:
                    free_bag_slot = int(bag_slot)
                    break

        if free_bag_slot is None:
            stored_bags += 1
            continue

        move_result = inventory_game.move_item_to_root_slot_by_guid(
            session,
            int(result.item.item_guid),
            int(free_bag_slot),
        )
        if move_result.ok:
            mounted_bags += 1
            inventory_game.persist_session_inventory(session)
            inventory_game.refresh_session_inventory(session)
        else:
            stored_bags += 1
            Logger.warning("[Cheat] bag equip failed slot=%s: %s", free_bag_slot, move_result.message)

    class_name = CHEAT_CLASS_NAMES.get(int(getattr(session, "class_id", 0) or 0))
    if class_name == "paladin":
        tier = 2
    elif class_name == "monk":
        tier = 14
    else:
        tier = 1
    equipped_tier_items = 0
    added_tier_items = 0
    tier_set_items = _helper("tier_set_items")
    item_entries = tuple(tier_set_items.get(class_name or "", {}).get(tier, ()))
    for item_entry in item_entries:
        result = add_item_to_character(session, int(item_entry), 1)
        if not result.ok or result.item is None:
            Logger.warning("[Cheat] tier add failed entry=%s: %s", item_entry, result.message)
            continue
        added_tier_items += 1

        src_bag = _client_bag_for_item(session, result.item)
        if src_bag is None:
            continue
        equip_result = inventory_game.auto_equip_item(session, int(src_bag), int(result.item.slot))
        if equip_result.ok:
            equipped_tier_items += 1
            inventory_game.persist_session_inventory(session)
            inventory_game.refresh_session_inventory(session)
        else:
            Logger.warning("[Cheat] tier equip failed entry=%s: %s", item_entry, equip_result.message)

    spell_ids = [int(spell_id) for _name, spell_id in CHEAT_MOUNT_ACTION_BUTTONS]
    try:
        learned_spells = DatabaseConnection.ensure_character_spells(char_guid, spell_ids) if char_guid > 0 else []
        known_spells = set(int(spell_id) for spell_id in getattr(session, "known_spells", set()) or set())
        known_spells.update(int(spell_id) for spell_id in learned_spells)
        known_spells.update(spell_ids)
        session.known_spells = sorted(known_spells)
    except Exception as exc:
        Logger.warning("[Cheat] mount spell learn failed: %s", exc)

    buttons = list(getattr(session, "action_buttons", []) or [])
    if len(buttons) < 132:
        buttons.extend([0] * (132 - len(buttons)))
    for slot, (_name, spell_id) in enumerate(CHEAT_MOUNT_ACTION_BUTTONS):
        buttons[int(slot)] = ((CHEAT_ACTION_BUTTON_TYPE_MOUNT & 0xFF) << 24) | (int(spell_id) & 0x00FFFFFF)
        if char_guid > 0:
            DatabaseConnection.save_character_action_button(
                char_guid,
                int(slot),
                int(spell_id),
                CHEAT_ACTION_BUTTON_TYPE_MOUNT,
                spec=0,
            )
    session.action_buttons = buttons

    inventory_game.persist_session_inventory(session)
    inventory_game.refresh_session_inventory(session, persist=True)
    responses.append(spells_handlers.build_known_spells_response(session))
    responses.extend(_build_login_inventory_sync(session))
    responses.extend(_build_action_button_update(session))
    responses.extend(
        _notification_response(
            f"[Cheat] level={CHEAT_TARGET_LEVEL} bags={mounted_bags} mounted/{stored_bags} stored "
            f"gear_removed={removed_items} tier={class_name or 'unknown'} T{tier} "
            f"equipped={equipped_tier_items}/{added_tier_items} actionbar={len(CHEAT_MOUNT_ACTION_BUTTONS)}"
        )
    )
    return responses


@register_command("fixplayer", ".fixplayer [teleport]")
def cmd_fixplayer(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Resend player state, optionally from a teleport destination."""
    if not args:
        return _append_feedback_response(
            _helper("build_fixplayer_responses")(session, 0),
            "[FixPlayer] mode=0 resync sent",
        )

    destination_name = " ".join(args).strip()
    if not destination_name:
        return _notification_response("Usage: .fixplayer <teleport>")

    applied_name = _helper("apply_fixplayer_destination")(session, destination_name)
    if applied_name is None:
        return _notification_response("Teleport not found")

    return _append_feedback_response(
        _helper("build_fixplayer_responses")(session, 2),
        f"[FixPlayer] destination={applied_name}",
    )


@register_command("fixspeed", ".fixspeed", allow_args=False)
def cmd_fixspeed(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Queue a same-map speed resync."""
    return _helper("build_fixspeed_responses")(session)


@register_command("save", ".save", allow_args=False)
def cmd_save(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Persist the current player position."""
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

    return [("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(message))]


def _telxyz(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Teleport to explicit coordinates (internal helper)."""
    player_name = (
        str(getattr(session, "player_name", "") or "").strip()
        or f"Player{int(getattr(session, 'char_guid', 0) or 0)}"
    )

    if len(args) != 5:
        Logger.info("[Teleport] Invalid .telxyz syntax command=%r", args)
        return _notification_response("Usage: .tel coord <map> <x> <y> <z> <orientation>")

    try:
        map_id = int(args[0])
        x = float(args[1])
        y = float(args[2])
        z = float(args[3])
        orientation = float(args[4])
    except (TypeError, ValueError):
        Logger.info("[Teleport] Invalid .telxyz args command=%r", args)
        return _notification_response("Usage: .tel coord <map> <x> <y> <z> <orientation>")

    Logger.info(
        "[Teleport] %s -> manual (%s %.2f %.2f %.2f %.2f)",
        player_name,
        map_id,
        x,
        y,
        z,
        orientation,
    )

    current_map_id = int(getattr(session, "map_id", 0) or 0)
    session.teleport_destination = f"manual:{map_id}:{x:.2f}:{y:.2f}:{z:.2f}:{orientation:.2f}"

    responses = _helper("apply_player_state_change")(
        session,
        position=(x, y, z, orientation),
        map_id=map_id,
    )

    if current_map_id == int(map_id):
        return _append_feedback_response(
            responses,
            f"[Teleport] near start -> {session.teleport_destination} ({x:.1f} {y:.1f} {z:.1f})",
        )

    return _append_feedback_response(
        responses,
        f"[Teleport] transfer start -> {session.teleport_destination} map={int(map_id)} ({x:.1f} {y:.1f} {z:.1f})",
    )


@register_command(
    "tel",
    ".tel <name> | .tel search <name> | .tel add <name> | .tel rm <name> | .tel coord <map> <x> <y> <z> <orientation>"
)
def cmd_tel(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Handle named teleport commands."""
    if not args:
        return _notification_response(
            "Usage: .tel <name> | .tel search <name> | .tel add <name> | .tel rm <name> | .tel coord <map> <x> <y> <z> <orientation>"
        )

    action = str(args[0]).strip().lower()

    if action == "search":
        query = " ".join(args[1:]) if len(args) >= 2 else ""
        matches = search_teleports(query)
        if not matches:
            return _notification_response("Matches: none")
        return _notification_response(f"Matches: {', '.join(matches)}")

    if action == "add":
        name = " ".join(args[1:]).strip() if len(args) >= 2 else ""
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
            Logger.warning("[Teleport] add failed name=%r: %s", name, exc)
            return _notification_response("Teleport add failed")
        return _notification_response(f"Teleport added: {entry['name']}")

    if action == "rm":
        name = " ".join(args[1:]).strip() if len(args) >= 2 else ""
        if not name:
            return _notification_response("Usage: .tel rm <name>")
        try:
            removed = remove_named_teleport(DatabaseConnection.world(), name)
        except Exception as exc:
            Logger.warning("[Teleport] rm failed name=%r: %s", name, exc)
            return _notification_response("Teleport remove failed")
        if not removed:
            return _notification_response("Teleport not found")
        return _notification_response("Teleport removed")

    if action == "coord":
        if len(args) != 6:
            return _notification_response("Usage: .tel coord <map> <x> <y> <z> <orientation>")
        return _telxyz(session, args[1:])

    # Default: .tel <name>
    destination_name = " ".join(args).strip()
    destination = find_teleport(destination_name)
    if destination is None:
        Logger.info("[Teleport] Unknown destination command=%r", destination_name)
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
        "[Teleport] %s -> %s (%.2f %.2f %.2f)",
        player_name,
        destination["name"],
        x,
        y,
        z,
    )
    current_map_id = int(getattr(session, "map_id", 0) or 0)
    session.teleport_destination = str(destination["name"])
    responses = _helper("apply_player_state_change")(
        session,
        position=(x, y, z, orientation),
        map_id=map_id,
    )
    if current_map_id == int(map_id):
        return _append_feedback_response(
            responses,
            f"[Teleport] near start -> {session.teleport_destination} ({x:.1f} {y:.1f} {z:.1f})",
        )
    return _append_feedback_response(
        responses,
        f"[Teleport] transfer start -> {session.teleport_destination} map={int(map_id)} ({x:.1f} {y:.1f} {z:.1f})",
    )


@register_command("mapcheat", ".mapcheat <on|0>")
def cmd_mapcheat(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Toggle temporary explored-zone visibility for the current player."""
    from server.modules.handlers.world.feature_config import map_cheat_enabled

    if not map_cheat_enabled():
        return _notification_response("[MapCheat] exploration cheat is disabled on this server.")

    argument = str(args[0]).strip().lower() if args else ""
    if argument in {"on", "1", "all"}:
        responses = list(_helper("build_map_exploration_update_responses")(session, True))
        Logger.info(
            "[MapCheat] enabled guid=%s",
            int(getattr(session, "char_guid", 0) or 0),
        )
        responses.append(_notification_response("[MapCheat] all areas temporarily visible")[0])
        return responses
    if argument in {"0", "off", "reset", "none"}:
        responses = list(_helper("build_map_exploration_update_responses")(session, False))
        Logger.info(
            "[MapCheat] disabled guid=%s; resent real explored zones",
            int(getattr(session, "char_guid", 0) or 0),
        )
        responses.append(_notification_response("[MapCheat] real exploration restored")[0])
        return responses
    return _notification_response("Usage: mapcheat <on|0>")



def find_online_player_by_name(name: str):
    if not name:
        return None

    name = name.strip().lower()

    from server.worldserver import _ACTIVE_CLIENTS, _ACTIVE_CLIENTS_LOCK

    with _ACTIVE_CLIENTS_LOCK:
        for _, session, _ in _ACTIVE_CLIENTS.values():
            guid = int(getattr(session, "char_guid", 0) or 0)
            if guid <= 0:
                continue

            player_name = str(getattr(session, "player_name", "") or "").strip().lower()
            account_name = str(getattr(session, "account_name", "") or "").strip().lower()

            if name == player_name or name == account_name:
                return session

    return None


@register_command("goto", ".goto <player>")
def cmd_goto(session, args: list[str]) -> list[tuple[str, bytes]]:
    if not args:
        return _notification_response("Usage: .goto <player>")

    target_name = " ".join(args).strip()
    target = find_online_player_by_name(target_name)
    if target is None:
        return _notification_response("Player not found")

    from server.modules.handlers.world.opcodes import chat as chat_handlers

    responses = chat_handlers.apply_player_state_change(
        session,
        position=(
            float(getattr(target, "x", 0.0) or 0.0),
            float(getattr(target, "y", 0.0) or 0.0),
            float(getattr(target, "z", 0.0) or 0.0),
            float(getattr(target, "orientation", 0.0) or 0.0),
        ),
        map_id=int(getattr(target, "map_id", 0) or 0),
    )

    return _append_feedback_response(
        responses,
        f"[Goto] -> {target_name}"
    )

@register_command("fetch", ".fetch <player>")
def cmd_fetch(session, args: list[str]) -> list[tuple[str, bytes]]:
    if not args:
        return _notification_response("Usage: .fetch <player>")

    target_name = " ".join(args).strip()
    target = find_online_player_by_name(target_name)
    if target is None:
        return _notification_response("Player not found")

    from server.modules.handlers.world.opcodes import chat as chat_handlers

    responses = chat_handlers.apply_player_state_change(
        target,
        position=(
            float(getattr(session, "x", 0.0) or 0.0),
            float(getattr(session, "y", 0.0) or 0.0),
            float(getattr(session, "z", 0.0) or 0.0),
            float(getattr(session, "orientation", 0.0) or 0.0),
        ),
        map_id=int(getattr(session, "map_id", 0) or 0),
    )

    target.send_response(responses)

    return _notification_response(f"[Fetch] {target_name} -> you")

_DEFAULT_MOTD = "Welcome to PyPandaria!"
_MOTD = _DEFAULT_MOTD
_DEFAULT_CONFIG_MOTD_PATH = Path(__file__).resolve().parents[5] / "config" / "default.yaml"


def _load_motd_from_config() -> str:
    """Read MOTD from merged config."""
    cfg = ConfigLoader.get_config() or {}
    motd = str((cfg.get("worldserver", {}) or {}).get("motd", "") or "").strip()
    return motd or _DEFAULT_MOTD


def _load_motd_from_database() -> str:
    try:
        from server.modules.database.DatabaseConnection import DatabaseConnection

        return str(DatabaseConnection.get_server_motd() or "").strip()
    except Exception:
        return ""


def _persist_motd_to_database(message: str) -> str:
    normalized = str(message or "").strip() or _DEFAULT_MOTD
    try:
        from server.modules.database.DatabaseConnection import DatabaseConnection

        if DatabaseConnection.set_server_motd(normalized):
            return normalized
    except Exception:
        pass

    return _persist_motd_to_default_config(normalized)


def _persist_motd_to_default_config(message: str) -> str:
    """Persist MOTD to default.yaml so it survives restart."""
    normalized = str(message or "").strip() or _DEFAULT_MOTD
    path = Path(_DEFAULT_CONFIG_MOTD_PATH)
    current = {}

    if path.is_file():
        with path.open("r", encoding="utf-8") as handle:
            current = yaml.safe_load(handle) or {}

    world_cfg = current.setdefault("worldserver", {})
    if not isinstance(world_cfg, dict):
        world_cfg = {}
        current["worldserver"] = world_cfg
    world_cfg["motd"] = normalized

    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(current, handle, sort_keys=False, allow_unicode=True)

    ConfigLoader.reload_config()
    return normalized

def get_motd() -> str:
    """Return current MOTD."""
    motd = _load_motd_from_database()
    if motd:
        return motd
    return _load_motd_from_config()


def _set_runtime_motd(session, message: str) -> str:
    """Update the runtime MOTD for current and future sessions."""
    global _MOTD

    from server.session.world_session import WorldSession

    normalized = _persist_motd_to_database(message)

    _MOTD = normalized
    WorldSession.motd = normalized

    state = getattr(session, "global_state", None)
    for target in list(getattr(state, "sessions", set()) or ()):
        target.motd = normalized
    session.motd = normalized
    return normalized


def _format_duration(seconds: int) -> str:
    total_seconds = max(0, int(seconds))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _server_runtime_snapshot(session) -> dict[str, Any]:
    from server import worldserver

    with worldserver._ACTIVE_CLIENTS_LOCK:
        client_count = len(worldserver._ACTIVE_CLIENTS)

    sessions = list(getattr(getattr(session, "global_state", None), "sessions", set()) or ())
    online_count = sum(1 for target in sessions if int(getattr(target, "char_guid", 0) or 0) > 0)
    in_world_count = sum(1 for target in sessions if str(getattr(target, "login_state", "")) == "IN_WORLD")
    uptime_seconds = int(time.time() - float(getattr(worldserver, "STARTED_AT", time.time()) or time.time()))

    return {
        "running": bool(getattr(worldserver, "running", False)),
        "clients": int(client_count),
        "sessions": int(len(sessions)),
        "online": int(online_count),
        "in_world": int(in_world_count),
        "uptime": _format_duration(uptime_seconds),
        "motd": get_motd(),
    }


def set_motd(message: str) -> None:
    """Set MOTD (stub)."""
    global _MOTD
    _MOTD = message.strip()

def server_info(session, args):
    snapshot = _server_runtime_snapshot(session)
    return _notification_response(
        "Server info: PyPandariaEmu | "
        f"uptime={snapshot['uptime']} | "
        f"clients={snapshot['clients']} | "
        f"online={snapshot['online']} | "
        f"motd={snapshot['motd']}"
    )

def server_status(session, args):
    snapshot = _server_runtime_snapshot(session)
    status = "running" if snapshot["running"] else "stopped"
    return _notification_response(
        f"Server status: {status} | clients={snapshot['clients']} | "
        f"sessions={snapshot['sessions']} | in_world={snapshot['in_world']}"
    )

def server_restart(session, args):
    from server import worldserver

    Logger.info("[SERVER] restart requested by %s", str(getattr(session, "player_name", "") or "unknown"))
    broadcast_system_message("[Server] restart requested", scope="world")
    worldserver.request_restart()
    return _notification_response("Restart scheduled")

def server_motd(session, args):
    if not args:
        return _notification_response(f"MOTD: {get_motd()}")

    if args[0] == "set":
        if len(args) < 2:
            return _notification_response("Usage: .server motd set <message>")
        msg = " ".join(args[1:])
        _set_runtime_motd(session, msg)
        return _notification_response("MOTD updated")

    return _notification_response("Usage: .server motd [set <message>]")


def server_msg(session, args):
    """Broadcast a server system message."""
    message = " ".join(args).strip()
    if not message:
        return _notification_response("Usage: .server msg <message>")
    Logger.info("[ServerMsg] message=%r", message)
    broadcast_system_message(message, scope="world")
    return _notification_response(f"[Server] sent: {message}")

@register_command(
    "server",
    ".server <info|status|restart|motd [set <message>]|msg <message>>"
)
def cmd_server(session, args):
    if not args:
        return _notification_response(
            "Usage: .server <info|status|restart|motd [set <message>]|msg <message>>"
        )

    subcommands = {
        "info": (server_info, False),
        "status": (server_status, False),
        "restart": (server_restart, False),
        "motd": (server_motd, None),  # special case (handles its own args)
        "msg": (server_msg, True),
    }

    sub = args[0].lower()
    if sub not in subcommands:
        return _notification_response(f"Unknown subcommand: {sub}")

    handler, needs_args = subcommands[sub]
    sub_args = args[1:]

    # Only enforce arg rules if explicitly True/False
    if needs_args is True and not sub_args:
        return _notification_response(f"Missing arguments for '{sub}'")

    if needs_args is False and sub_args:
        return _notification_response(f"'{sub}' takes no arguments")

    return handler(session, sub_args)


@register_command("time", ".time")
def cmd_time(session, args: list[str]) -> list[tuple[str, bytes]]:
    unix_ms = int(time.time() * 1000.0)
    monotonic_ms = int(time.monotonic() * 1000.0)

    message = (
        f"unix_ms={unix_ms} "
        f"monotonic_ms={monotonic_ms}"
    )

    broadcast_system_message(
        message,
        scope="world"
    )

    return []


  

# Real commands live here for quick scanning.
PRIMARY_COMMANDS = {
    "achievement": Command(handler=cmd_achievement, usage=".achievement <add|fix> [name]", require_args=True),
    "additem": Command(handler=cmd_additem, usage=".additem <itemEntry> [count]"),
    "addmoney": Command(handler=cmd_addmoney, usage=".addmoney <copper | 10g10s10c>", require_args=False),
    "addtier": Command(handler=cmd_addtier, usage=".addtier <class> <tier>"),
    "castspell": Command(handler=cmd_castspell, usage=".castspell <spell_id>", require_args=True),
    "cheat": Command(handler=cmd_cheat, usage=".cheat", allow_args=False),
    "demorph": Command(handler=cmd_demorph, usage=".demorph", allow_args=False),
    "dismount": Command(handler=cmd_dismount, usage=".dismount", allow_args=False),
    "fetch": Command(handler=cmd_fetch, usage=".fetch <player>", require_args=True),
    # "fixplayer": Command(handler=cmd_fixplayer, usage=".fixplayer [teleport]"),
    # "fixspeed": Command(handler=cmd_fixspeed, usage=".fixspeed", allow_args=False),
    "goto": Command(handler=cmd_goto, usage=".goto <player>", require_args=True),
    "gps": Command(handler=cmd_gps, usage=".gps", allow_args=False),
    "help": Command(handler=cmd_help, usage=".help"),
    "learnspell": Command(handler=cmd_learnspell, usage=".learnspell <spell_id>", require_args=True),
    "level": Command(handler=cmd_level, usage=".level [delta]|set <level>"),
    "mapcheat": Command(handler=cmd_mapcheat, usage=".mapcheat <on|0>"),
    "morph": Command(handler=cmd_morph, usage=".morph <displayId|namel|list>", require_args=True),
    "mount": Command(handler=cmd_mount, usage=".mount", allow_args=False),
    "roll": Command(handler=cmd_roll, usage=".roll"),
    "save": Command(handler=cmd_save, usage=".save", allow_args=False),
    "server": Command(
        handler=cmd_server,
        usage=".server  <info|status|restart|motd [set <message>]|msg <message>>",
    ),
    # "spawngo": Command(handler=cmd_spawngo, usage=".spawngo", allow_args=False),
    "speed": Command(handler=cmd_speed, usage=".speed <multiplier|default>"),
    "system": Command(handler=cmd_system, usage=".system <message>", require_args=True),
    "taxi": Command(handler=cmd_taxi, usage=".taxi <on|off|status>"),
    "time": Command(handler=cmd_time, usage=".time", allow_args=False),
    "title": Command(handler=cmd_title, usage=".title <bitIndex|explorer|off>", require_args=True),
    "world": Command(handler=cmd_world, usage=".world <go|npc|lift|boat> <hide|show|status|on|off|test|clear>"),
    # "telxyz": Command(handler=cmd_telxyz, usage=".telxyz <map> <x> <y> <z> <orientation>"),
    "tel": Command(
        handler=cmd_tel,
        usage=".tel <name> | .tel search <name> | .tel add <name> | .tel rm <name> | .tel coord <map> <x> <y> <z> <orientation>",
    ),
    "time": Command(handler=cmd_time, usage=".time <HH:MM|day|night|dawn|dusk|noon|midnight>"),
    "weather": Command(handler=cmd_weather, usage=".weather <clear|rain|snow|storm|sand|id> [0.0-1.0]"),
}

# Aliases resolve to names in PRIMARY_COMMANDS.
ALIASES = {}


# COMMANDS is the runtime lookup map used by handle_command().
COMMANDS = dict(PRIMARY_COMMANDS)
for alias, name in ALIASES.items():
    COMMANDS[alias] = PRIMARY_COMMANDS[name]
