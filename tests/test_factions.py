from server.modules.handlers.world import factions
from server.modules.handlers.world.factions import FactionTemplate


def _template(
    template_id: int,
    faction_id: int,
    our_mask: int,
    *,
    friendly_mask: int = 0,
    hostile_mask: int = 0,
) -> FactionTemplate:
    return FactionTemplate(
        template_id=template_id,
        faction_id=faction_id,
        flags=0,
        our_mask=our_mask,
        friendly_mask=friendly_mask,
        hostile_mask=hostile_mask,
        enemy_factions=(0, 0, 0, 0),
        friend_factions=(0, 0, 0, 0),
    )


def test_neutral_faction_is_neither_friendly_nor_hostile(monkeypatch):
    alliance = _template(1, 1, 0x02, friendly_mask=0x02, hostile_mask=0x04)
    neutral = _template(35, 0, 0)
    monkeypatch.setattr(factions, "_templates", {1: alliance, 35: neutral})

    assert factions.is_friendly_faction(35, 1) is False
    assert factions.is_hostile_faction(35, 1) is False


def test_neutral_to_all_faction_is_usable_even_without_friendly_mask(monkeypatch):
    alliance = _template(1, 1, 0x02, friendly_mask=0x02, hostile_mask=0x04)
    neutral_to_all = _template(474, 369, 0)
    monkeypatch.setattr(factions, "_templates", {1: alliance, 474: neutral_to_all})

    assert factions.is_friendly_faction(474, 1) is False
    assert factions.is_hostile_faction(474, 1) is False


def test_opposing_faction_is_hostile(monkeypatch):
    alliance = _template(1, 1, 0x02, friendly_mask=0x02, hostile_mask=0x04)
    horde = _template(2, 2, 0x04, friendly_mask=0x04, hostile_mask=0x02)
    monkeypatch.setattr(factions, "_templates", {1: alliance, 2: horde})

    assert factions.is_hostile_faction(1, 2) is True
    assert factions.is_hostile_faction(2, 1) is True
