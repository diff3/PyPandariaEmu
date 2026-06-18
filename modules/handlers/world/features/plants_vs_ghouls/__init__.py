from __future__ import annotations

from server.modules.handlers.world.features.plants_vs_ghouls.runtime import (
    PlantsVsGhoulsManager,
)


_MANAGER = PlantsVsGhoulsManager()


def get_plants_vs_ghouls_manager() -> PlantsVsGhoulsManager:
    return _MANAGER
