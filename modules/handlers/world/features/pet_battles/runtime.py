#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import time

from shared.Logger import Logger
from server.modules.handlers.world.features.pet_battles.packets import (
    build_battle_pet_location_finalize_payload,
    build_pet_battle_queue_status_payload,
)
from server.modules.handlers.world.features.pet_battles.state import PetBattleSession


class PetBattleManager:
    def __init__(self) -> None:
        self._sessions: dict[int, PetBattleSession] = {}
        self._next_battle_id = 1

    def start_session(self, session) -> list[tuple[str, bytes]] | None:
        player_guid = self._player_guid(session)
        if player_guid <= 0:
            return None
        if self._sessions.get(player_guid) is not None:
            Logger.info("[PetBattle] session duplicate_start player=%s", player_guid)
            return None

        battle = PetBattleSession(
            battle_id=self._next_battle_id,
            player_guid=player_guid,
            started_at=float(time.monotonic()),
            active=True,
        )
        self._next_battle_id += 1
        self._sessions[player_guid] = battle
        session.pet_battle_session = battle

        Logger.info(
            "[PetBattle] start player=%s battle_id=%s active=%s",
            player_guid,
            battle.battle_id,
            int(battle.active),
        )
        Logger.info(
            "[PetBattle] session player=%s battle_id=%s started_at=%.6f",
            player_guid,
            battle.battle_id,
            battle.started_at,
        )

        responses = [
            self._packet(
                "SMSG_PET_BATTLE_QUEUE_STATUS",
                build_pet_battle_queue_status_payload(session, status=1),
            ),
            self._packet(
                "SMSG_BATTLE_PET_LOCATION_FINALIZE",
                build_battle_pet_location_finalize_payload(session),
            ),
        ]

        Logger.info(
            "[PetBattle] packet missing opcode=%s reason=%s",
            "SMSG_BATTLE_PET_UPDATE_INIT",
            "client battle mode still requires a valid init payload",
        )
        return responses

    def stop_session(
        self,
        session,
        *,
        reason: str = "command-stop",
        send_packets: bool = True,
    ) -> list[tuple[str, bytes]] | None:
        player_guid = self._player_guid(session)
        battle = self._sessions.pop(player_guid, None)
        if battle is None:
            return None

        battle.active = False
        session.pet_battle_session = None
        Logger.info(
            "[PetBattle] stop player=%s battle_id=%s reason=%s",
            player_guid,
            battle.battle_id,
            str(reason),
        )

        if not send_packets:
            return []

        return [
            self._packet(
                "SMSG_PET_BATTLE_QUEUE_STATUS",
                build_pet_battle_queue_status_payload(session, status=0),
            ),
        ]

    def active_session(self, session) -> PetBattleSession | None:
        return self._sessions.get(self._player_guid(session))

    def handle_logout(self, session) -> None:
        self.stop_session(session, reason="logout", send_packets=False)

    def handle_map_transfer(self, session) -> None:
        self.stop_session(session, reason="map-transfer", send_packets=False)

    def handle_disconnect(self, session) -> None:
        self.stop_session(session, reason="disconnect", send_packets=False)

    def reset_for_tests(self) -> None:
        self._sessions.clear()
        self._next_battle_id = 1

    @staticmethod
    def _player_guid(session) -> int:
        return int(
            getattr(session, "char_guid", 0)
            or getattr(session, "world_guid", 0)
            or getattr(session, "player_guid", 0)
            or 0
        )

    @staticmethod
    def _packet(opcode: str, payload: bytes) -> tuple[str, bytes]:
        Logger.info("[PetBattle] packet opcode=%s size=%s", str(opcode), len(payload))
        return str(opcode), bytes(payload or b"")
