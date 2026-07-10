from __future__ import annotations

from dataclasses import dataclass
import math


@dataclass(frozen=True)
class Vec3:
    x: float
    y: float
    z: float

    def __add__(self, other: "Vec3") -> "Vec3":
        return Vec3(self.x + other.x, self.y + other.y, self.z + other.z)

    def __sub__(self, other: "Vec3") -> "Vec3":
        return Vec3(self.x - other.x, self.y - other.y, self.z - other.z)

    def __mul__(self, scalar: float) -> "Vec3":
        return Vec3(self.x * float(scalar), self.y * float(scalar), self.z * float(scalar))

    __rmul__ = __mul__

    def dot(self, other: "Vec3") -> float:
        return (self.x * other.x) + (self.y * other.y) + (self.z * other.z)

    def cross(self, other: "Vec3") -> "Vec3":
        return Vec3(
            (self.y * other.z) - (self.z * other.y),
            (self.z * other.x) - (self.x * other.z),
            (self.x * other.y) - (self.y * other.x),
        )

    def length(self) -> float:
        return math.sqrt(self.dot(self))

    def normalize(self) -> "Vec3":
        magnitude = self.length()
        if magnitude <= 1e-30:
            return Vec3(0.0, 0.0, 0.0)
        return self * (1.0 / magnitude)

    def min_components(self, other: "Vec3") -> "Vec3":
        return Vec3(min(self.x, other.x), min(self.y, other.y), min(self.z, other.z))

    def max_components(self, other: "Vec3") -> "Vec3":
        return Vec3(max(self.x, other.x), max(self.y, other.y), max(self.z, other.z))

    def to_tuple(self) -> tuple[float, float, float]:
        return (self.x, self.y, self.z)
