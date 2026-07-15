from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CastStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    INTERRUPT = "interrupt"


@dataclass(slots=True)
class SpellEffectResult:
    status: CastStatus
    responses: Any = field(default_factory=list)
    reason: int = 0

    @classmethod
    def success(cls, responses=None):
        return cls(CastStatus.SUCCESS, responses if responses is not None else [])

    @classmethod
    def failure(cls, reason: int):
        return cls(CastStatus.FAILURE, reason=int(reason))

    @classmethod
    def interrupt(cls, responses=None, reason: int = 0):
        return cls(CastStatus.INTERRUPT, responses if responses is not None else [], int(reason))


@dataclass(slots=True)
class SpellCastContext:
    session: Any
    spell_id: int
    cast_count: int
    caster_guid: int
    target_guid: int
    source: Any
    source_item_entry: int = 0
