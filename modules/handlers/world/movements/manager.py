#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Single owner for DBC movement templates and instances."""

from __future__ import annotations

import time

from shared.Logger import Logger

from .cache import get_movement_cache
from .evaluator import evaluate_template
from .types import MovementInstance, MovementTemplate, MovementTransform


class MovementManager:
    def __init__(self) -> None:
        self.instances: dict[int, MovementInstance] = {}

    def load_templates(self) -> None:
        get_movement_cache().load()

    def register_instance(
        self,
        instance_id: int,
        template: MovementTemplate,
        *,
        phase_offset_ms: int = 0,
    ) -> MovementInstance | None:
        instance_key = int(instance_id)
        if instance_key in self.instances:
            Logger.info("[MovementManager] duplicate instance rejected id=0x%016X", instance_key)
            return self.instances.get(instance_key)
        instance = MovementInstance(
            instance_id=instance_key,
            template_id=str(template.template_id),
            started_at_ms=int(time.monotonic() * 1000.0),
            phase_offset_ms=int(phase_offset_ms),
        )
        self.instances[instance_key] = instance
        Logger.info(
            "[MovementManager] instance registered id=0x%016X template=%s",
            instance_key,
            template.template_id,
        )
        return instance

    def evaluate(self, template: MovementTemplate, *, server_time_ms: int | None = None, phase_offset_ms: int = 0) -> MovementTransform:
        now = int(time.monotonic() * 1000.0) if server_time_ms is None else int(server_time_ms)
        return evaluate_template(template, now, phase_offset_ms=int(phase_offset_ms))

    def stats(self) -> dict[str, int]:
        cache = get_movement_cache()
        cache.load()
        return {
            "instances": len(self.instances),
            "transport_templates": len(cache.transport_animation),
            "taxi_templates": len(cache.taxi_paths),
        }


_MANAGER = MovementManager()


def get_movement_manager() -> MovementManager:
    return _MANAGER
