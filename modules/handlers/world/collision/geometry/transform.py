from __future__ import annotations

from dataclasses import dataclass
import math

from .vector import Vec3


@dataclass(frozen=True)
class Transform:
    translation: Vec3 = Vec3(0.0, 0.0, 0.0)
    rotation_yaw: float = 0.0
    scale: float = 1.0

    def local_to_world_position(self, point: Vec3) -> Vec3:
        scaled = point * float(self.scale)
        rotated = self._rotate_local_to_world(scaled)
        return rotated + self.translation

    def world_to_local_position(self, point: Vec3) -> Vec3:
        translated = point - self.translation
        rotated = self._rotate_world_to_local(translated)
        scale = float(self.scale)
        if abs(scale) <= 1e-12:
            return Vec3(0.0, 0.0, 0.0)
        return rotated * (1.0 / scale)

    def local_to_world_direction(self, direction: Vec3) -> Vec3:
        return self._rotate_local_to_world(direction * float(self.scale))

    def world_to_local_direction(self, direction: Vec3) -> Vec3:
        rotated = self._rotate_world_to_local(direction)
        scale = float(self.scale)
        if abs(scale) <= 1e-12:
            return Vec3(0.0, 0.0, 0.0)
        return rotated * (1.0 / scale)

    def local_to_world_normal(self, normal: Vec3) -> Vec3:
        return self._rotate_local_to_world(normal).normalize()

    def world_to_local_normal(self, normal: Vec3) -> Vec3:
        return self._rotate_world_to_local(normal).normalize()

    def _rotate_local_to_world(self, vector: Vec3) -> Vec3:
        cosine = math.cos(float(self.rotation_yaw))
        sine = math.sin(float(self.rotation_yaw))
        return Vec3(
            (cosine * vector.x) - (sine * vector.y),
            (sine * vector.x) + (cosine * vector.y),
            vector.z,
        )

    def _rotate_world_to_local(self, vector: Vec3) -> Vec3:
        cosine = math.cos(float(self.rotation_yaw))
        sine = math.sin(float(self.rotation_yaw))
        return Vec3(
            (cosine * vector.x) + (sine * vector.y),
            (-sine * vector.x) + (cosine * vector.y),
            vector.z,
        )
