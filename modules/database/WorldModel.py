#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sqlalchemy import Column, Float, String, Integer, Text
from sqlalchemy.dialects.mysql import TINYINT, SMALLINT, MEDIUMINT, INTEGER

from server.modules.database.Base import Base


class ItemTemplate(Base):
    __tablename__ = "item_template"

    entry = Column(MEDIUMINT(unsigned=True), primary_key=True, default=0)
    displayid = Column(Integer, nullable=False, default=0)
    inventory_type = Column("InventoryType", TINYINT(unsigned=True), nullable=False, default=0)


class PlayerFactionchangeAchievement(Base):
    __tablename__ = "player_factionchange_achievement"

    alliance_id = Column(INTEGER(unsigned=True), primary_key=True, default=0)
    horde_id = Column(INTEGER(unsigned=True), primary_key=True, default=0)


class PlayerFactionchangeItems(Base):
    __tablename__ = "player_factionchange_items"

    race_A = Column(INTEGER(unsigned=True), nullable=False, default=0)
    alliance_id = Column(INTEGER(unsigned=True), primary_key=True, default=0)
    commentA = Column(Text)
    race_H = Column(INTEGER(unsigned=True), nullable=False, default=0)
    horde_id = Column(INTEGER(unsigned=True), primary_key=True, default=0)
    commentH = Column(Text)


class PlayerFactionchangeQuests(Base):
    __tablename__ = "player_factionchange_quests"

    alliance_id = Column(INTEGER(unsigned=True), primary_key=True, default=0)
    horde_id = Column(INTEGER(unsigned=True), primary_key=True, default=0)


class PlayerFactionchangeReputations(Base):
    __tablename__ = "player_factionchange_reputations"

    alliance_id = Column(INTEGER(unsigned=True), primary_key=True, default=0)
    horde_id = Column(INTEGER(unsigned=True), primary_key=True, default=0)


class PlayerFactionchangeSpells(Base):
    __tablename__ = "player_factionchange_spells"

    alliance_id = Column(INTEGER(unsigned=True), primary_key=True, default=0)
    horde_id = Column(INTEGER(unsigned=True), primary_key=True, default=0)


class PlayerFactionchangeTitles(Base):
    __tablename__ = "player_factionchange_titles"

    alliance_id = Column(Integer, primary_key=True, default=0)
    horde_id = Column(Integer, primary_key=True, default=0)


class PlayerLevelStats(Base):
    __tablename__ = "player_levelstats"

    race = Column(TINYINT(unsigned=True), primary_key=True, default=0)
    class_ = Column("class", TINYINT(unsigned=True), primary_key=True, default=0)
    level = Column(TINYINT(unsigned=True), primary_key=True, default=0)
    str = Column(SMALLINT(unsigned=True), nullable=False, default=0)
    agi = Column(SMALLINT(unsigned=True), nullable=False, default=0)
    sta = Column(SMALLINT(unsigned=True), nullable=False, default=0)
    inte = Column(SMALLINT(unsigned=True), nullable=False, default=0)
    spi = Column(SMALLINT(unsigned=True), nullable=False, default=0)


class PlayerXpForLevel(Base):
    __tablename__ = "player_xp_for_level"

    lvl = Column(TINYINT(unsigned=True), primary_key=True, default=0)
    xp_for_next_level = Column(INTEGER(unsigned=True), nullable=False, default=0)


class PlayerCreateInfo(Base):
    __tablename__ = "playercreateinfo"

    race = Column(TINYINT(unsigned=True), primary_key=True, default=0)
    class_ = Column("class", TINYINT(unsigned=True), primary_key=True, default=0)
    map = Column(SMALLINT(unsigned=True), nullable=False, default=0)
    zone = Column(MEDIUMINT(unsigned=True), nullable=False, default=0)
    position_x = Column(Float, nullable=False, default=0.0)
    position_y = Column(Float, nullable=False, default=0.0)
    position_z = Column(Float, nullable=False, default=0.0)
    orientation = Column(Float, nullable=False, default=0.0)


class PlayerCreateInfoAction(Base):
    __tablename__ = "playercreateinfo_action"

    race = Column(TINYINT(unsigned=True), primary_key=True, default=0)
    class_ = Column("class", TINYINT(unsigned=True), primary_key=True, default=0)
    button = Column(SMALLINT(unsigned=True), primary_key=True, default=0)
    action = Column(Integer, nullable=False, default=0)
    type = Column(SMALLINT(unsigned=True), nullable=False, default=0)


class PlayerCreateInfoItem(Base):
    __tablename__ = "playercreateinfo_item"

    race = Column(TINYINT(unsigned=True), primary_key=True, default=0)
    class_ = Column("class", TINYINT(unsigned=True), primary_key=True, default=0)
    itemid = Column(MEDIUMINT(unsigned=True), primary_key=True, default=0)
    amount = Column(TINYINT(unsigned=True), nullable=False, default=1)


class PlayerCreateInfoSpell(Base):
    __tablename__ = "playercreateinfo_spell"

    racemask = Column(Integer, primary_key=True, default=0)
    classmask = Column(Integer, primary_key=True, default=0)
    spell = Column("Spell", MEDIUMINT(unsigned=True), primary_key=True, default=0)
    note = Column("Note", String(255))


class PlayerCreateInfoSpellCast(Base):
    __tablename__ = "playercreateinfo_spell_cast"

    racemask = Column(Integer, primary_key=True, default=0)
    classmask = Column(Integer, primary_key=True, default=0)
    spell = Column("Spell", MEDIUMINT(unsigned=True), primary_key=True, default=0)
    note = Column("Note", String(255))


class PlayerCreateInfoSpellCustom(Base):
    __tablename__ = "playercreateinfo_spell_custom"

    racemask = Column(Integer, primary_key=True, default=0)
    classmask = Column(Integer, primary_key=True, default=0)
    spell = Column("Spell", MEDIUMINT(unsigned=True), primary_key=True, default=0)
    note = Column("Note", String(255))
