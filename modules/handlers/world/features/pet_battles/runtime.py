#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import time

from shared.Logger import Logger
from server.modules.handlers.world.features.pet_battles.packets import (
    build_battle_pet_location_finalize_payload,
    build_battle_pet_update_init_payload,
    resolve_init_pet_debug_info,
)
from server.modules.handlers.world.features.pet_battles.state import PetBattleSession


class PetBattleManager:
    TRACE_WINDOW_SECONDS = 10.0

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

        init_debug = resolve_init_pet_debug_info()
        battle = PetBattleSession(
            battle_id=self._next_battle_id,
            player_guid=player_guid,
            started_at=float(time.monotonic()),
            active=True,
            player_pet_guid=int(init_debug.get("player_pet_guid", 0) or 0),
            enemy_pet_guid=int(init_debug.get("enemy_pet_guid", 0) or 0),
            player_species_id=int(init_debug.get("player_species_id", 0) or 0),
            enemy_species_id=int(init_debug.get("enemy_species_id", 0) or 0),
        )
        self._next_battle_id += 1
        self._sessions[player_guid] = battle
        session.pet_battle_session = battle
        setattr(session, "pet_battle_trace_started_at", float(time.monotonic()))
        setattr(session, "pet_battle_trace_battle_id", int(battle.battle_id))
        setattr(session, "pet_battle_trace_active", True)
        setattr(session, "pet_battle_trace_until", float(time.monotonic()) + self.TRACE_WINDOW_SECONDS)

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
        self._log_battle_objects("start", session, battle)
        Logger.info(
            "[PetBattle] init_debug battle_id=%s player_pet_guid=0x%016X player_species=%s "
            "enemy_pet_guid=0x%016X enemy_species=%s",
            int(battle.battle_id),
            int(battle.player_pet_guid) & 0xFFFFFFFFFFFFFFFF,
            int(battle.player_species_id),
            int(battle.enemy_pet_guid) & 0xFFFFFFFFFFFFFFFF,
            int(battle.enemy_species_id),
        )

        responses = [
            self._packet(
                "SMSG_BATTLE_PET_UPDATE_INIT",
                build_battle_pet_update_init_payload(session, battle_id=int(battle.battle_id)),
            ),
            self._packet(
                "SMSG_BATTLE_PET_LOCATION_FINALIZE",
                build_battle_pet_location_finalize_payload(session),
            ),
        ]
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
        setattr(session, "pet_battle_trace_battle_id", int(battle.battle_id))
        setattr(session, "pet_battle_trace_active", False)
        setattr(session, "pet_battle_trace_until", float(time.monotonic()) + self.TRACE_WINDOW_SECONDS)
        Logger.info(
            "[PetBattle] stop player=%s battle_id=%s reason=%s",
            player_guid,
            battle.battle_id,
            str(reason),
        )
        self._log_battle_objects("stop", session, battle)

        if not send_packets:
            return []
        return []

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

    @staticmethod
    def _log_battle_objects(stage: str, session, battle: PetBattleSession) -> None:
        loaded_npcs = len(getattr(session, "loaded_npcs", set()) or ())
        loaded_gameobjects = len(getattr(session, "loaded_gameobjects", set()) or ())
        Logger.info(
            "[PetBattle] objects stage=%s battle_id=%s player=%s active=%s "
            "player_pet_guid=0x%016X enemy_pet_guid=0x%016X "
            "spawned_units=%s spawned_world_objects=%s session_loaded_npcs=%s session_loaded_gameobjects=%s",
            str(stage),
            int(battle.battle_id),
            int(battle.player_guid),
            int(bool(getattr(battle, "active", False))),
            int(getattr(battle, "player_pet_guid", 0) or 0) & 0xFFFFFFFFFFFFFFFF,
            int(getattr(battle, "enemy_pet_guid", 0) or 0) & 0xFFFFFFFFFFFFFFFF,
            [f"0x{int(guid) & 0xFFFFFFFFFFFFFFFF:016X}" for guid in tuple(getattr(battle, "spawned_unit_guids", ()) or ())],
            [f"0x{int(guid) & 0xFFFFFFFFFFFFFFFF:016X}" for guid in tuple(getattr(battle, "spawned_world_object_guids", ()) or ())],
            int(loaded_npcs),
            int(loaded_gameobjects),
        )
