from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PlantState:
    plant_id: int
    kind: str
    lane_index: int
    slot_index: int
    progress: float
    hp: int
    max_hp: int
    attack_damage: int
    attack_range: float
    attack_cooldown: float
    cooldown_remaining: float
    world_guid: int
    entry: int


@dataclass
class ZombieState:
    zombie_id: int
    lane_index: int
    progress: float
    hp: int
    max_hp: int
    speed: float
    attack_damage: int
    attack_cooldown: float
    attack_cooldown_remaining: float
    contact_range: float
    world_guid: int
    entry: int


@dataclass
class LaneState:
    lane_index: int
    plants: list[PlantState] = field(default_factory=list)
    zombies: list[ZombieState] = field(default_factory=list)


@dataclass
class PlantsVsGhoulsMatch:
    player_guid: int
    map_id: int
    anchor_x: float
    anchor_y: float
    anchor_z: float
    anchor_orientation: float
    lanes: list[LaneState]
    wave_index: int = 0
    intermission_remaining: float = 0.0
    active: bool = True
    outcome: str | None = None
    next_local_guid: int = 9_000_000
    next_plant_id: int = 1
    next_zombie_id: int = 1
    next_spline_id: int = 1
    temporary_guids: set[int] = field(default_factory=set)
