from __future__ import annotations

from typing import Callable, Protocol

from .model import SpellCastContext, SpellEffectResult


class SpellEffect(Protocol):
    def execute(self, context: SpellCastContext) -> SpellEffectResult: ...


Predicate = Callable[[SpellCastContext], bool]


class SpellEffectRegistry:
    def __init__(self) -> None:
        self._entries: list[tuple[Predicate, SpellEffect]] = []

    def register(self, predicate: Predicate, effect: SpellEffect) -> None:
        self._entries.append((predicate, effect))

    def resolve(self, context: SpellCastContext) -> SpellEffect | None:
        return next((effect for predicate, effect in self._entries if predicate(context)), None)
