from __future__ import annotations

from typing import Optional

from shared.Logger import Logger
from server.modules.handlers.world.chat.codec import encode_skyfire_messagechat_system_payload
from server.modules.handlers.world.login.packets import build_login_packet
from server.modules.handlers.world.opcodes.movement import (
    build_same_map_teleport_payload,
    _capture_persist_position_from_session as capture_persist_position_from_session,
    _mark_position_dirty as mark_position_dirty,
)
from server.modules.handlers.world.position.area_service import resolve_zone_from_position


def _feedback(message: str) -> tuple[str, bytes]:
    return ("SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(message))

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
        player.teleport_pending = False
        player.near_teleport_pending = True
        Logger.info(
            "[Teleport] queued same-map near teleport map=%s destination=%s",
            int(map_id),
            player.teleport_destination,
        )
        return [
            _feedback(
                f"[Teleport] near start -> {player.teleport_destination or map_id} "
                f"({float(x):.1f} {float(y):.1f} {float(z):.1f})"
            ),
            ("SMSG_MOVE_TELEPORT", build_same_map_teleport_payload(player)),
        ]

    Logger.info(
        "[Teleport] queued transfer map=%s same_map=%s destination=%s",
        int(map_id),
        same_map,
        player.teleport_destination,
    )

    return [
        _feedback(
            f"[Teleport] transfer start -> {player.teleport_destination or map_id} "
            f"map={int(map_id)} ({float(x):.1f} {float(y):.1f} {float(z):.1f})"
        ),
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
