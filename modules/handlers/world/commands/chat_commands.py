#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
import random
import time
from typing import Any, Callable, Optional

from shared.Logger import Logger
from server.modules.database.DatabaseConnection import DatabaseConnection
from server.modules.game.inventory import (
    add_item_to_character,
)
from server.modules.handlers.world.chat.codec import (
    encode_skyfire_messagechat_system_payload,
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
MORPH_NAME_TO_DISPLAY = {
    "sylvanas": 28213,
    "arthas": 22234,
    "jaina": 30863,
    "deathwing": 32809,
    "illidan": 21137,
    "trall": 4527
}
UNIT_FIELD_DISPLAYID = 69


def configure(**helpers: Any) -> None:
    """Store helper callbacks provided by the chat opcode module."""
    HELPERS.update(helpers)


def _helper(name: str) -> Any:
    """Return a configured helper or fail fast."""
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
    elif head not in {"map"}:
        return None

    return head, parts[1:]


def _is_explicit_command(message: str) -> bool:
    """Treat leading dot as an explicit command attempt."""
    return str(message or "").strip().startswith(".")


def _call_command(name: str, session, args: list[str]) -> list[tuple[str, bytes]]:
    """Call a command from the runtime lookup map."""
    return COMMANDS[name].handler(session, args)


def _gps_strings(session) -> tuple[str, str]:
    """Build chat and log strings for the current position."""
    map_id = int(getattr(session, "map_id", 0) or 0)
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)
    z = float(getattr(session, "z", 0.0) or 0.0)
    orientation = float(getattr(session, "orientation", 0.0) or 0.0)
    feedback = f"[GPS] map={map_id} x={x:.2f} y={y:.2f} z={z:.2f} o={orientation:.2f}"
    telxyz = f".telxyz {map_id} {x:.2f} {y:.2f} {z:.2f} {orientation:.2f}"
    return feedback, telxyz


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
    from server.modules.game.guid import GameObjectGuid
    from server.modules.handlers.world.bootstrap.replay import (
        _build_gameobject_update_payload,
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
        world_guid = GameObjectGuid.from_spawn_guid(int(entry.get("guid", 0) or 0), realm_id)
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
    responses.extend(
        _notification_response(
            f"[Level] {current_level} -> {target_level}"
        )
    )
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


@register_command("fly", ".fly <on|off>")
def cmd_fly(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Toggle self flying in the sandbox."""
    from server.modules.handlers.world.opcodes.movement import (
        build_move_set_can_fly_payload,
        build_move_set_flight_speed_payload,
        resync_movement,
    )

    if len(args) != 1:
        return _notification_response("Usage: .fly <on|off>")

    enabled = str(args[0]).strip().lower()
    if enabled not in {"on", "off"}:
        return _notification_response("Usage: .fly <on|off>")

    fly_enabled = enabled == "on"
    session.can_fly = fly_enabled
    session.is_flying = fly_enabled
    Logger.info(
        "[FLY] enabled=%s guid=0x%X",
        fly_enabled,
        int(getattr(session, "char_guid", 0) or getattr(session, "player_guid", 0) or getattr(session, "world_guid", 0) or 0),
    )

    responses: list[tuple[str, bytes]] = [
        (
            "SMSG_MOVE_SET_CAN_FLY" if fly_enabled else "SMSG_MOVE_UNSET_CAN_FLY",
            build_move_set_can_fly_payload(session, fly_enabled),
        )
    ]
    if fly_enabled:
        responses.append(
            ("SMSG_MOVE_SET_FLIGHT_SPEED", build_move_set_flight_speed_payload(session))
        )
    movement_responses = list(resync_movement(session))
    if movement_responses:
        responses.extend(movement_responses)
        Logger.info("[FLY] movement resync sent guid=0x%X", int(getattr(session, "char_guid", 0) or getattr(session, "player_guid", 0) or getattr(session, "world_guid", 0) or 0))
    responses.extend(_notification_response(f"[Fly] {'on' if fly_enabled else 'off'}"))
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
    from server.modules.handlers.world.opcodes.movement import resync_movement

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
    responses.extend(resync_movement(session))
    responses.extend(_notification_response(f"Casted spell {int(spell_id)}"))
    return responses


@register_command("mount", ".mount", allow_args=False)
def cmd_mount(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Apply the debug mount display."""
    from server.modules.handlers.world.opcodes.movement import resync_movement

    mount_spell_id = int(_helper("chat_mount_spell_id"))
    Logger.info(
        "[Mount][Debug] chat .mount received char=%s mounted=%s mount_spell=%s debug_spell=%s",
        int(getattr(session, "char_guid", 0) or 0),
        bool(getattr(session, "is_mounted", False)),
        int(getattr(session, "mount_spell", 0) or 0),
        mount_spell_id,
    )
    Logger.info("[Mount] spell_id=%s", mount_spell_id)
    responses = list(spells_handlers.handle_mount(session, int(mount_spell_id)))
    Logger.info(
        "[Mount] spell_id=%s speed=%.2f",
        mount_spell_id,
        float(getattr(session, "run_speed", 0.0) or 0.0),
    )
    responses.extend(resync_movement(session))
    Logger.info("[Mount] aura applied")
    Logger.info("[Mount] committed")
    Logger.info("[Mount][Debug] chat .mount returning responses=%s", len(responses))
    return _append_feedback_response(responses, "[Mount] mount requested")


@register_command("dismount", ".dismount", allow_args=False)
def cmd_dismount(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Clear the debug mount display."""
    from server.modules.handlers.world.opcodes.movement import resync_movement

    Logger.info("[Mount] .dismount -> clear display")
    responses = list(spells_handlers.dismount(session))
    Logger.info(
        "[Mount] spell_id=%s speed=%.2f",
        int(getattr(session, "mount_spell", 0) or 0),
        float(getattr(session, "run_speed", 0.0) or 0.0),
    )
    responses.extend(resync_movement(session))
    Logger.info("[Mount] committed")
    Logger.info("[Mount][Debug] chat .dismount responses=%s", len(responses))
    return _append_feedback_response(responses, "[Mount] dismount requested")


@register_command("morph", ".morph <displayId|name>", require_args=True)
def cmd_morph(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Morph the player into a target display id."""
    if len(args) != 1:
        return _notification_response("Usage: .morph <displayId|name>")

    display_id = _resolve_morph_display_id(args[0])
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


@register_command("addtier", ".addtier <class> <tier>")
def cmd_addtier(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Add a predefined tier set by reusing additem."""
    if len(args) != 2:
        return _notification_response("Usage: .addtier <class> <tier>")

    class_name = str(args[0]).strip().lower()
    try:
        tier = int(args[1], 0)
    except ValueError:
        return _notification_response("Usage: .addtier <class> <tier>")

    tier_set_items = _helper("tier_set_items")
    item_entries = tier_set_items.get((class_name, int(tier)))
    if not item_entries:
        return _notification_response(f"[AddTier] unsupported class/tier: {class_name} {tier}")

    Logger.info(
        "[ADDTIER] class=%s tier=%s items=%s",
        class_name,
        int(tier),
        len(item_entries),
    )

    responses: list[tuple[str, bytes]] = []
    for item_entry in item_entries:
        responses.extend(_call_command("additem", session, [str(int(item_entry)), "1"]))

    responses.extend(_build_login_inventory_sync(session))
    responses.extend(
        _notification_response(f"[AddTier] {class_name} T{int(tier)} items={len(item_entries)}")
    )
    return responses


@register_command("invfix", ".invfix", allow_args=False)
def cmd_invfix(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Force a full inventory resync."""
    Logger.info("[INVFIX] start")
    known_guids = getattr(session, "known_inventory_guids", None)
    if isinstance(known_guids, set):
        known_guids.clear()
    else:
        session.known_inventory_guids = set()
    Logger.info("[INVFIX] cleared known guids")
    session.inventory_activated = False
    responses = _build_login_inventory_sync(session)
    Logger.info("[INVFIX] responses=%s", len(responses))
    return _append_feedback_response(responses, "[InvFix] full inventory resync sent")


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


@register_command("telxyz", ".telxyz <map> <x> <y> <z> <orientation>")
def cmd_telxyz(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Teleport to explicit coordinates."""
    player_name = (
        str(getattr(session, "player_name", "") or "").strip()
        or f"Player{int(getattr(session, 'char_guid', 0) or 0)}"
    )
    if len(args) != 5:
        Logger.info("[Teleport] Invalid .telxyz syntax command=%r", args)
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
        map_id = int(args[0])
        x = float(args[1])
        y = float(args[2])
        z = float(args[3])
        orientation = float(args[4])
    except (TypeError, ValueError):
        Logger.info("[Teleport] Invalid .telxyz args command=%r", args)
        return []

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


@register_command("tel", ".tel <name> | .tel search <name> | .tel add <name> | .tel rm <name> | .tel nearest")
def cmd_tel(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Handle named teleport commands."""
    if not args:
        return _notification_response(
            "Usage: .tel <name> | .tel search <name> | .tel add <name> | .tel rm <name> | .tel nearest"
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

    if action == "nearest":
        nearest = nearest_teleport(
            int(getattr(session, "map_id", 0) or 0),
            float(getattr(session, "x", 0.0) or 0.0),
            float(getattr(session, "y", 0.0) or 0.0),
        )
        if nearest is None:
            return _notification_response("Nearest: none")
        return _notification_response(f"Nearest: {nearest['name']}")

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


@register_command("map", ".map <on|0>")
def cmd_map(session, args: list[str]) -> list[tuple[str, bytes]]:
    """Toggle explored zones for the current player."""
    argument = str(args[0]).strip().lower() if args else ""
    if argument in {"on", "1", "all"}:
        return [
            _helper("build_map_exploration_update_response")(session, True),
            _notification_response("[Map] all explored")[0],
        ]
    if argument in {"0", "off", "reset", "none"}:
        return [
            _helper("build_map_exploration_update_response")(session, False),
            _notification_response("[Map] exploration reset")[0],
        ]
    return _notification_response("Usage: map <on|0>")


# Real commands live here for quick scanning.
PRIMARY_COMMANDS = {
    "help": Command(handler=cmd_help, usage=".help"),
    "roll": Command(handler=cmd_roll, usage=".roll"),
    "gps": Command(handler=cmd_gps, usage=".gps", allow_args=False),
    "spawngo": Command(handler=cmd_spawngo, usage=".spawngo", allow_args=False),
    "level": Command(handler=cmd_level, usage=".level [delta]|set <level>"),
    "speed": Command(handler=cmd_speed, usage=".speed <multiplier|default>"),
    "fly": Command(handler=cmd_fly, usage=".fly <on|off>"),
    "weather": Command(handler=cmd_weather, usage=".weather <clear|rain|snow|storm|sand|id> [0.0-1.0]"),
    "time": Command(handler=cmd_time, usage=".time <HH:MM|day|night|dawn|dusk|noon|midnight>"),
    "system": Command(handler=cmd_system, usage=".system <message>", require_args=True),
    "learnspell": Command(handler=cmd_learnspell, usage=".learnspell <spell_id>", require_args=True),
    "castspell": Command(handler=cmd_castspell, usage=".castspell <spell_id>", require_args=True),
    "mount": Command(handler=cmd_mount, usage=".mount", allow_args=False),
    "dismount": Command(handler=cmd_dismount, usage=".dismount", allow_args=False),
    "morph": Command(handler=cmd_morph, usage=".morph <displayId|name>", require_args=True),
    "demorph": Command(handler=cmd_demorph, usage=".demorph", allow_args=False),
    "additem": Command(handler=cmd_additem, usage=".additem <itemEntry> [count]"),
    "addtier": Command(handler=cmd_addtier, usage=".addtier <class> <tier>"),
    "invfix": Command(handler=cmd_invfix, usage=".invfix", allow_args=False),
    "fixplayer": Command(handler=cmd_fixplayer, usage=".fixplayer [teleport]"),
    "fixspeed": Command(handler=cmd_fixspeed, usage=".fixspeed", allow_args=False),
    "save": Command(handler=cmd_save, usage=".save", allow_args=False),
    "telxyz": Command(handler=cmd_telxyz, usage=".telxyz <map> <x> <y> <z> <orientation>"),
    "tel": Command(
        handler=cmd_tel,
        usage=".tel <name> | .tel search <name> | .tel add <name> | .tel rm <name> | .tel nearest",
    ),
    "map": Command(handler=cmd_map, usage=".map <on|0>"),
}


# Aliases resolve to names in PRIMARY_COMMANDS.
ALIASES = {}


# COMMANDS is the runtime lookup map used by handle_command().
COMMANDS = dict(PRIMARY_COMMANDS)
for alias, name in ALIASES.items():
    COMMANDS[alias] = PRIMARY_COMMANDS[name]
