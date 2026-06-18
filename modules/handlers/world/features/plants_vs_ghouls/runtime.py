from __future__ import annotations

import threading
import time

from shared.Logger import Logger
from server.modules.handlers.world.features.plants_vs_ghouls import cleanup, spawning
from server.modules.handlers.world.features.plants_vs_ghouls.definitions import (
    GOAL_PROGRESS,
    LANE_CENTER_INDEX,
    LANE_COUNT,
    LANE_SPACING,
    MOVE_SPLINE_DURATION_MS,
    PLANT_DEFINITIONS,
    PLANT_SLOTS,
    TICK_SECONDS,
    WAVE_DEFINITIONS,
    WAVE_INTERMISSION_SECONDS,
    ZOMBIE_DEFINITION,
    ZOMBIE_SPAWN_PROGRESS,
)
from server.modules.handlers.world.features.plants_vs_ghouls.state import (
    LaneState,
    PlantState,
    PlantsVsGhoulsMatch,
    ZombieState,
)


class PlantsVsGhoulsManager:
    def __init__(self, *, auto_start_thread: bool = True) -> None:
        self._matches: dict[int, tuple[object, PlantsVsGhoulsMatch]] = {}
        self._lock = threading.RLock()
        self._auto_start_thread = bool(auto_start_thread)
        self._thread: threading.Thread | None = None
        self._running = False

    def start_match(self, session) -> bool:
        player_guid = int(getattr(session, "char_guid", 0) or 0)
        if player_guid <= 0:
            return False

        with self._lock:
            existing = self._matches.get(player_guid)
            if existing is not None:
                self._clear_match_locked(existing[0], existing[1], reason="restart")

            match = PlantsVsGhoulsMatch(
                player_guid=player_guid,
                map_id=int(getattr(session, "map_id", 0) or 0),
                anchor_x=float(getattr(session, "x", 0.0) or 0.0),
                anchor_y=float(getattr(session, "y", 0.0) or 0.0),
                anchor_z=float(getattr(session, "z", 0.0) or 0.0),
                anchor_orientation=float(getattr(session, "orientation", 0.0) or 0.0),
                lanes=[LaneState(lane_index=index) for index in range(LANE_COUNT)],
            )
            self._matches[player_guid] = (session, match)
            setattr(session, "plants_vs_ghouls_active", True)
            setattr(session, "plants_vs_ghouls_outcome", None)
            self._spawn_next_wave_locked(session, match)
            self._ensure_thread_locked()

        Logger.info(
            "[PvG] start player=%s map=%s anchor=(%.2f %.2f %.2f)",
            player_guid,
            int(getattr(session, "map_id", 0) or 0),
            float(getattr(session, "x", 0.0) or 0.0),
            float(getattr(session, "y", 0.0) or 0.0),
            float(getattr(session, "z", 0.0) or 0.0),
        )
        return True

    def stop_match(self, session, *, reason: str = "stop") -> bool:
        player_guid = int(getattr(session, "char_guid", 0) or 0)
        with self._lock:
            entry = self._matches.get(player_guid)
            if entry is None:
                return False
            self._clear_match_locked(entry[0], entry[1], reason=reason)
            return True

    def status_text(self, session) -> str:
        player_guid = int(getattr(session, "char_guid", 0) or 0)
        with self._lock:
            entry = self._matches.get(player_guid)
            if entry is None:
                return "[PvG] inactive"
            _session, match = entry
            zombies = sum(len(lane.zombies) for lane in match.lanes)
            plants = sum(len(lane.plants) for lane in match.lanes)
            return (
                f"[PvG] active wave={match.wave_index}/{len(WAVE_DEFINITIONS)} "
                f"plants={plants} zombies={zombies} map={match.map_id}"
            )

    def place_plant(self, session, *, lane_number: int, kind: str) -> tuple[bool, str]:
        normalized_kind = str(kind or "").strip().lower()
        definition = PLANT_DEFINITIONS.get(normalized_kind)
        if definition is None:
            return False, "Usage: .pvg plant <lane 1-5> <spitter|rocknut>"

        player_guid = int(getattr(session, "char_guid", 0) or 0)
        with self._lock:
            entry = self._matches.get(player_guid)
            if entry is None:
                return False, "[PvG] no active match"
            _session, match = entry
            lane_index = int(lane_number) - 1
            if lane_index < 0 or lane_index >= LANE_COUNT:
                return False, "Usage: .pvg plant <lane 1-5> <spitter|rocknut>"
            lane = match.lanes[lane_index]
            used_slots = {int(plant.slot_index) for plant in lane.plants}
            slot_index = next((index for index in range(len(PLANT_SLOTS)) if index not in used_slots), None)
            if slot_index is None:
                return False, f"[PvG] lane {lane_number} is full"

            world_guid = self._allocate_world_guid_locked(session, match)
            progress = float(PLANT_SLOTS[int(slot_index)])
            x, y, z = self._world_position(match, lane_index=lane_index, progress=progress)
            plant = PlantState(
                plant_id=match.next_plant_id,
                kind=definition.kind,
                lane_index=lane_index,
                slot_index=int(slot_index),
                progress=progress,
                hp=int(definition.max_hp),
                max_hp=int(definition.max_hp),
                attack_damage=int(definition.attack_damage),
                attack_range=float(definition.attack_range),
                attack_cooldown=float(definition.attack_cooldown),
                cooldown_remaining=0.0,
                world_guid=world_guid,
                entry=int(definition.entry),
            )
            match.next_plant_id += 1
            lane.plants.append(plant)
            responses = [
                spawning.build_creature_spawn_response(
                    session,
                    world_guid=world_guid,
                    entry_id=int(definition.entry),
                    x=x,
                    y=y,
                    z=z,
                )
            ]

        spawning.dispatch_responses(session, responses)
        return True, f"[PvG] planted kind={normalized_kind} lane={lane_number}"

    def tick_once(self, *, dt_seconds: float | None = None) -> None:
        with self._lock:
            snapshots = list(self._matches.items())
        for player_guid, (session, _match) in snapshots:
            self._tick_player(player_guid, session, dt_seconds=float(dt_seconds) if dt_seconds is not None else TICK_SECONDS)

    def handle_disconnect(self, session) -> None:
        self.stop_match(session, reason="disconnect")

    def handle_map_change(self, session, destination_map_id: int) -> None:
        player_guid = int(getattr(session, "char_guid", 0) or 0)
        with self._lock:
            entry = self._matches.get(player_guid)
            if entry is None:
                return
            _tracked_session, match = entry
            if int(match.map_id) == int(destination_map_id):
                return
            self._clear_match_locked(session, match, reason=f"map-change:{int(destination_map_id)}")

    def reset_for_tests(self) -> None:
        with self._lock:
            self._running = False
            self._thread = None
            self._matches.clear()

    def _ensure_thread_locked(self) -> None:
        if not self._auto_start_thread:
            return
        if self._thread is not None and self._thread.is_alive():
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop,
            name="plants-vs-ghouls",
            daemon=True,
        )
        self._thread.start()

    def _run_loop(self) -> None:
        while self._running:
            self.tick_once(dt_seconds=TICK_SECONDS)
            time.sleep(TICK_SECONDS)

    def _tick_player(self, player_guid: int, session, dt_seconds: float) -> None:
        responses: list[tuple[str, bytes]] = []
        finished_reason: str | None = None
        with self._lock:
            entry = self._matches.get(player_guid)
            if entry is None:
                return
            _session, match = entry
            if not match.active:
                return
            self._update_match_locked(session, match, max(0.0, float(dt_seconds)), responses)
            if match.outcome in {"win", "loss"}:
                finished_reason = str(match.outcome)
                responses.extend(cleanup.build_cleanup_responses(session, match.temporary_guids))
                cleanup.clear_session_match_markers(session)
                setattr(session, "plants_vs_ghouls_outcome", str(match.outcome))
                self._matches.pop(player_guid, None)

        spawning.dispatch_responses(session, responses)
        if finished_reason == "win":
            Logger.info("[PvG] win player=%s", player_guid)
        elif finished_reason == "loss":
            Logger.info("[PvG] loss player=%s", player_guid)

    def _update_match_locked(
        self,
        session,
        match: PlantsVsGhoulsMatch,
        dt_seconds: float,
        responses: list[tuple[str, bytes]],
    ) -> None:
        if match.wave_index < len(WAVE_DEFINITIONS) and not self._has_zombies(match):
            if match.intermission_remaining <= 0.0 and match.wave_index > 0:
                match.intermission_remaining = WAVE_INTERMISSION_SECONDS
            elif match.intermission_remaining > 0.0:
                match.intermission_remaining = max(0.0, match.intermission_remaining - dt_seconds)
                if match.intermission_remaining <= 0.0:
                    self._spawn_next_wave_locked(session, match, responses)

        for lane in match.lanes:
            for plant in list(lane.plants):
                if plant.attack_damage <= 0:
                    continue
                plant.cooldown_remaining = max(0.0, float(plant.cooldown_remaining) - dt_seconds)
                if plant.cooldown_remaining > 0.0:
                    continue
                target = next(
                    (
                        zombie
                        for zombie in sorted(lane.zombies, key=lambda item: item.progress)
                        if zombie.progress >= plant.progress
                        and (zombie.progress - plant.progress) <= plant.attack_range
                    ),
                    None,
                )
                if target is None:
                    continue
                target.hp -= int(plant.attack_damage)
                plant.cooldown_remaining = float(plant.attack_cooldown)
                Logger.info(
                    "[PvG] plant_attack player=%s lane=%s plant=%s zombie=%s damage=%s hp=%s",
                    match.player_guid,
                    int(plant.lane_index) + 1,
                    str(plant.kind),
                    int(target.zombie_id),
                    int(plant.attack_damage),
                    int(max(0, target.hp)),
                )
                if target.hp <= 0:
                    responses.append(
                        spawning.build_creature_despawn_response(session, world_guid=target.world_guid)
                    )
                    lane.zombies = [zombie for zombie in lane.zombies if zombie.zombie_id != target.zombie_id]
                    match.temporary_guids.discard(int(target.world_guid))
                    Logger.info(
                        "[PvG] zombie_dead player=%s lane=%s zombie=%s",
                        match.player_guid,
                        int(target.lane_index) + 1,
                        int(target.zombie_id),
                    )

        for lane in match.lanes:
            updated_zombies: list[ZombieState] = []
            updated_plants = list(lane.plants)
            for zombie in lane.zombies:
                contact_plant = self._find_contact_plant(updated_plants, zombie)
                if contact_plant is not None:
                    zombie.attack_cooldown_remaining = max(0.0, zombie.attack_cooldown_remaining - dt_seconds)
                    if zombie.attack_cooldown_remaining <= 0.0:
                        contact_plant.hp -= int(zombie.attack_damage)
                        zombie.attack_cooldown_remaining = float(zombie.attack_cooldown)
                        if contact_plant.hp <= 0:
                            updated_plants = [plant for plant in updated_plants if plant.plant_id != contact_plant.plant_id]
                            responses.append(
                                spawning.build_creature_despawn_response(
                                    session,
                                    world_guid=contact_plant.world_guid,
                                )
                            )
                            match.temporary_guids.discard(int(contact_plant.world_guid))
                    updated_zombies.append(zombie)
                    continue

                old_progress = float(zombie.progress)
                zombie.progress = max(GOAL_PROGRESS, float(zombie.progress) - (float(zombie.speed) * dt_seconds))
                if zombie.progress <= GOAL_PROGRESS:
                    match.outcome = "loss"
                    return
                if zombie.progress != old_progress:
                    start_x, start_y, start_z = self._world_position(
                        match,
                        lane_index=zombie.lane_index,
                        progress=old_progress,
                    )
                    end_x, end_y, end_z = self._world_position(
                        match,
                        lane_index=zombie.lane_index,
                        progress=zombie.progress,
                    )
                    responses.append(
                        spawning.build_creature_move_response(
                            session,
                            world_guid=zombie.world_guid,
                            start_x=start_x,
                            start_y=start_y,
                            start_z=start_z,
                            end_x=end_x,
                            end_y=end_y,
                            end_z=end_z,
                            duration_ms=MOVE_SPLINE_DURATION_MS,
                            spline_id=match.next_spline_id,
                        )
                    )
                    match.next_spline_id += 1
                updated_zombies.append(zombie)
            lane.plants = updated_plants
            lane.zombies = updated_zombies

        if match.wave_index >= len(WAVE_DEFINITIONS) and not self._has_zombies(match):
            match.outcome = "win"

    def _spawn_next_wave_locked(
        self,
        session,
        match: PlantsVsGhoulsMatch,
        responses: list[tuple[str, bytes]] | None = None,
    ) -> None:
        if match.wave_index >= len(WAVE_DEFINITIONS):
            return
        target_responses = responses if responses is not None else []
        wave_number = int(match.wave_index) + 1
        wave = WAVE_DEFINITIONS[int(match.wave_index)]
        for lane_index in wave.lane_indexes:
            lane = match.lanes[int(lane_index)]
            world_guid = self._allocate_world_guid_locked(session, match)
            x, y, z = self._world_position(match, lane_index=int(lane_index), progress=ZOMBIE_SPAWN_PROGRESS)
            zombie = ZombieState(
                zombie_id=match.next_zombie_id,
                lane_index=int(lane_index),
                progress=float(ZOMBIE_SPAWN_PROGRESS),
                hp=int(ZOMBIE_DEFINITION.max_hp),
                max_hp=int(ZOMBIE_DEFINITION.max_hp),
                speed=float(ZOMBIE_DEFINITION.speed),
                attack_damage=int(ZOMBIE_DEFINITION.attack_damage),
                attack_cooldown=float(ZOMBIE_DEFINITION.attack_cooldown),
                attack_cooldown_remaining=0.0,
                contact_range=float(ZOMBIE_DEFINITION.contact_range),
                world_guid=world_guid,
                entry=int(ZOMBIE_DEFINITION.entry),
            )
            match.next_zombie_id += 1
            lane.zombies.append(zombie)
            target_responses.append(
                spawning.build_creature_spawn_response(
                    session,
                    world_guid=world_guid,
                    entry_id=int(ZOMBIE_DEFINITION.entry),
                    x=x,
                    y=y,
                    z=z,
                )
            )

        match.wave_index += 1
        match.intermission_remaining = 0.0
        Logger.info(
            "[PvG] wave player=%s wave=%s zombies=%s",
            match.player_guid,
            wave_number,
            len(wave.lane_indexes),
        )
        if responses is None:
            spawning.dispatch_responses(session, target_responses)

    def _clear_match_locked(self, session, match: PlantsVsGhoulsMatch, *, reason: str) -> None:
        responses = cleanup.build_cleanup_responses(session, match.temporary_guids)
        cleanup.clear_session_match_markers(session)
        self._matches.pop(int(match.player_guid), None)
        match.active = False
        spawning.dispatch_responses(session, responses)
        Logger.info(
            "[PvG] cleanup player=%s reason=%s entities=%s",
            match.player_guid,
            str(reason),
            len(match.temporary_guids),
        )

    def _allocate_world_guid_locked(self, session, match: PlantsVsGhoulsMatch) -> int:
        low_guid = int(match.next_local_guid)
        match.next_local_guid += 1
        world_guid = spawning.make_creature_world_guid(
            int(getattr(session, "realm_id", 1) or 1),
            low_guid,
        )
        match.temporary_guids.add(int(world_guid))
        return world_guid

    def _has_zombies(self, match: PlantsVsGhoulsMatch) -> bool:
        return any(lane.zombies for lane in match.lanes)

    def _find_contact_plant(self, plants: list[PlantState], zombie: ZombieState) -> PlantState | None:
        for plant in sorted(plants, key=lambda item: item.progress, reverse=True):
            if zombie.progress < plant.progress:
                continue
            if (zombie.progress - plant.progress) <= float(zombie.contact_range):
                return plant
        return None

    def _world_position(self, match: PlantsVsGhoulsMatch, *, lane_index: int, progress: float) -> tuple[float, float, float]:
        lane_offset = (int(lane_index) - LANE_CENTER_INDEX) * float(LANE_SPACING)
        return (
            float(match.anchor_x) + float(progress),
            float(match.anchor_y) + lane_offset,
            float(match.anchor_z),
        )
