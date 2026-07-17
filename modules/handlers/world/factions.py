#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Canonical faction-template relations backed by FactionTemplate.dbc."""

from __future__ import annotations

from dataclasses import dataclass

from shared.Logger import Logger
from shared.PathUtils import get_dbc_root
from server.modules.dbc.DBCReader import read_dbc


_FACTION_TEMPLATE_FMT = "niiiiiiiiiiiii"
_FACTION_MASK_ALLIANCE = 0x02
_FACTION_MASK_HORDE = 0x04
_templates: dict[int, "FactionTemplate"] | None = None


@dataclass(frozen=True, slots=True)
class FactionTemplate:
    template_id: int
    faction_id: int
    flags: int
    our_mask: int
    friendly_mask: int
    hostile_mask: int
    enemy_factions: tuple[int, int, int, int]
    friend_factions: tuple[int, int, int, int]

    def is_friendly_to(self, other: "FactionTemplate") -> bool:
        """Match SkyFire 5.4.8 FactionTemplateEntry::IsFriendlyTo."""
        if self.template_id == other.template_id:
            return True
        if other.faction_id:
            if other.faction_id in self.enemy_factions:
                return False
            if other.faction_id in self.friend_factions:
                return True
        return bool(
            (self.friendly_mask & other.our_mask)
            or (self.our_mask & other.friendly_mask)
        )


def faction_templates() -> dict[int, FactionTemplate]:
    global _templates
    if _templates is not None:
        return _templates

    loaded: dict[int, FactionTemplate] = {}
    try:
        rows = read_dbc(
            f"{get_dbc_root()}/FactionTemplate.dbc",
            _FACTION_TEMPLATE_FMT,
        )
        for row in rows:
            template_id = int(row[0])
            loaded[template_id] = FactionTemplate(
                template_id=template_id,
                faction_id=int(row[1]),
                flags=int(row[2]),
                our_mask=int(row[3]),
                friendly_mask=int(row[4]),
                hostile_mask=int(row[5]),
                enemy_factions=tuple(int(value) for value in row[6:10]),
                friend_factions=tuple(int(value) for value in row[10:14]),
            )
    except Exception as exc:
        Logger.warning("[Faction] failed to load FactionTemplate.dbc: %s", exc)
    _templates = loaded
    return loaded


def creature_faction_for_player(
    *,
    faction_a: int,
    faction_h: int,
    player_faction_template: int,
) -> int:
    """Select the creature template faction as SkyFire does for player team."""
    player = faction_templates().get(int(player_faction_template))
    if player is not None and player.our_mask & _FACTION_MASK_HORDE:
        return int(faction_h)
    if player is not None and player.our_mask & _FACTION_MASK_ALLIANCE:
        return int(faction_a)
    return 0


def is_friendly_faction(source_template_id: int, target_template_id: int) -> bool:
    templates = faction_templates()
    source = templates.get(int(source_template_id))
    target = templates.get(int(target_template_id))
    return bool(source is not None and target is not None and source.is_friendly_to(target))
