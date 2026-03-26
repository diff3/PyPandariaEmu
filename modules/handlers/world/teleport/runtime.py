from __future__ import annotations

from typing import Optional

from shared.Logger import Logger
from shared.PathUtils import get_dbc_root
from server.modules.dbc import read_dbc
from server.modules.handlers.world.login.packets import build_login_packet
from server.modules.handlers.world.opcodes.movement import (
    _capture_persist_position_from_session as capture_persist_position_from_session,
    _mark_position_dirty as mark_position_dirty,
)

_AREA_TABLE: Optional[list[tuple[int, int, float, float, float, float]]] = None

def _load_area_table() -> list[tuple[int, int, float, float, float, float]]:
    global _AREA_TABLE
    if _AREA_TABLE is not None:
        return _AREA_TABLE

    _AREA_TABLE = []
    dbc_root = get_dbc_root()
    path = dbc_root / "AreaTable.dbc"
    if not path.exists():
        Logger.warning("[AreaTable] missing")
        return _AREA_TABLE

    try:
        rows = read_dbc(path, "iIIffff")
    except Exception as exc:
        Logger.warning(f"[AreaTable] failed: {exc}")
        return _AREA_TABLE

    for row in rows:
        area_id = int(row[0])
        map_id = int(row[1])
        x1, x2, y1, y2 = float(row[2]), float(row[3]), float(row[4]), float(row[5])
        _AREA_TABLE.append((map_id, area_id, x1, x2, y1, y2))

    return _AREA_TABLE


def resolve_zone_from_position(map_id: int, x: float, y: float) -> int:
    for candidate_map_id, area_id, x1, x2, y1, y2 in _load_area_table():
        if candidate_map_id != map_id:
            continue
        if min(x1, x2) <= x <= max(x1, x2) and min(y1, y2) <= y <= max(y1, y2):
            return area_id
    return 0


def teleport_player(
    player,
    map_id: int,
    x: float,
    y: float,
    z: float,
    orientation: float,
    *,
    destination_name: str,
) -> list[tuple[str, bytes]]:
    """
    Apply teleport runtime state and build the world transfer packets.

    Behavior is preserved from the legacy implementation; only the module
    placement changes so teleport concerns live under world/teleport.
    """
    same_map = int(getattr(player, "map_id", 0) or 0) == int(map_id)

    player.x = float(x)
    player.y = float(y)
    player.z = float(z)
    player.orientation = float(orientation)
    player.map_id = int(map_id)
    player.zone = resolve_zone_from_position(int(map_id), float(x), float(y)) or int(
        getattr(player, "zone", 0) or 0
    )
    player.instance_id = 0
    player.teleport_pending = True
    player.teleport_destination = str(destination_name or "").strip() or None
    capture_persist_position_from_session(player)
    mark_position_dirty(player)

    if same_map:
        Logger.info(
            "[Teleport] same-map teleport map=%s destination=%s; completing without loading screen",
            int(map_id),
            player.teleport_destination,
        )
        from server.modules.handlers.world.opcodes import login as login_handlers

        responses = [
            (
                "SMSG_NEW_WORLD",
                build_login_packet(
                    "SMSG_NEW_WORLD",
                    type(
                        "Ctx",
                        (),
                        {
                            "map_id": int(map_id),
                            "x": float(x),
                            "y": float(y),
                            "z": float(z),
                            "orientation": float(orientation),
                        },
                    )(),
                ),
            ),
        ]
        responses.extend(
            login_handlers._queue_teleport_world_transition(
                player,
                login_handlers._build_world_login_context(player),
            )
        )
        return responses

    return [
        (
            "SMSG_TRANSFER_PENDING",
            build_login_packet(
                "SMSG_TRANSFER_PENDING",
                type("Ctx", (), {"map_id": int(map_id)})(),
            ),
        ),
        (
            "SMSG_NEW_WORLD",
            build_login_packet(
                "SMSG_NEW_WORLD",
                type(
                    "Ctx",
                    (),
                    {
                        "map_id": int(map_id),
                        "x": float(x),
                        "y": float(y),
                        "z": float(z),
                        "orientation": float(orientation),
                    },
                )(),
            ),
        ),
    ]
