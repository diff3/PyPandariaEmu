from __future__ import annotations

from dataclasses import dataclass


BRAZIE_ENTRY = 49687
SUNFLOWER_ENTRY = 49692
SPITTER_ENTRY = 49697
ROCKNUT_ENTRY = 49693
ZOMBIE_ENTRY = 49209

LANE_COUNT = 5
LANE_SPACING = 4.0
LANE_CENTER_INDEX = 2
PLANT_SLOTS = (6.0, 12.0, 18.0)
ZOMBIE_SPAWN_PROGRESS = 28.0
GOAL_PROGRESS = 0.0

TICK_SECONDS = 0.25
WAVE_INTERMISSION_SECONDS = 2.0
MOVE_SPLINE_DURATION_MS = int(TICK_SECONDS * 1000.0)


@dataclass(frozen=True)
class PlantDefinition:
    kind: str
    entry: int
    max_hp: int
    attack_damage: int
    attack_range: float
    attack_cooldown: float


@dataclass(frozen=True)
class ZombieDefinition:
    entry: int
    max_hp: int
    speed: float
    attack_damage: int
    attack_cooldown: float
    contact_range: float


@dataclass(frozen=True)
class WaveDefinition:
    lane_indexes: tuple[int, ...]


PLANT_DEFINITIONS = {
    "spitter": PlantDefinition(
        kind="spitter",
        entry=SPITTER_ENTRY,
        max_hp=12,
        attack_damage=4,
        attack_range=9.0,
        attack_cooldown=1.0,
    ),
    "rocknut": PlantDefinition(
        kind="rocknut",
        entry=ROCKNUT_ENTRY,
        max_hp=40,
        attack_damage=0,
        attack_range=0.0,
        attack_cooldown=0.0,
    ),
}

ZOMBIE_DEFINITION = ZombieDefinition(
    entry=ZOMBIE_ENTRY,
    max_hp=16,
    speed=1.75,
    attack_damage=3,
    attack_cooldown=1.0,
    contact_range=0.9,
)

WAVE_DEFINITIONS = (
    WaveDefinition(lane_indexes=(0, 2)),
    WaveDefinition(lane_indexes=(1, 3, 0)),
    WaveDefinition(lane_indexes=(4, 2, 1, 3)),
)
