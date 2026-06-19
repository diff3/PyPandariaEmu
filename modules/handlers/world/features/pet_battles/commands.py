#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from server.modules.handlers.world.features.pet_battles import get_pet_battle_manager


def handle_petbattle_command(session, args: list[str]) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.commands.chat_commands import _notification_response

    manager = get_pet_battle_manager()
    if not args:
        return _notification_response(".petbattle <start|stop|status>")

    action = str(args[0]).strip().lower()
    if action == "start":
        responses = manager.start_session(session)
        if responses is None:
            return _notification_response("[PetBattle] session already active or unavailable")
        return list(responses) + _notification_response(
            "[PetBattle] start sent; client still needs SMSG_BATTLE_PET_UPDATE_INIT for full UI activation"
        )

    if action == "stop":
        responses = manager.stop_session(session, reason="command-stop")
        if responses is None:
            return _notification_response("[PetBattle] no active session")
        return list(responses) + _notification_response("[PetBattle] stop")

    if action == "status":
        active = manager.active_session(session)
        if active is None:
            return _notification_response("[PetBattle] inactive")
        return _notification_response(
            f"[PetBattle] active battle_id={int(active.battle_id)} player={int(active.player_guid)}"
        )

    return _notification_response(".petbattle <start|stop|status>")
