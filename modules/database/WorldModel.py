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
    stackable = Column(Integer, nullable=False, default=1)
    buy_count = Column("BuyCount", TINYINT(unsigned=True), nullable=False, default=1)
    bag_family = Column("BagFamily", Integer, nullable=False, default=0)
    class_ = Column("class", TINYINT(unsigned=True), nullable=False, default=0)
    subclass = Column("subclass", TINYINT(unsigned=True), nullable=False, default=0)
    container_slots = Column("ContainerSlots", TINYINT(unsigned=True), nullable=False, default=0)


class WorldGameObject(Base):
    __tablename__ = "gameobject"

    guid = Column(INTEGER(unsigned=True), primary_key=True, default=0)
    id = Column(MEDIUMINT(unsigned=True), nullable=False, default=0)
    map = Column(SMALLINT(unsigned=True), nullable=False, default=0)
    spawnMask = Column(Integer, nullable=False, default=1)
    phaseId = Column(Integer, nullable=False, default=0)
    phaseGroup = Column(Integer, nullable=False, default=0)
    position_x = Column(Float, nullable=False, default=0.0)
    position_y = Column(Float, nullable=False, default=0.0)
    position_z = Column(Float, nullable=False, default=0.0)
    orientation = Column(Float, nullable=False, default=0.0)
    scale = Column(Float, nullable=False, default=1.0)
    rotation0 = Column(Float, nullable=False, default=0.0)
    rotation1 = Column(Float, nullable=False, default=0.0)
    rotation2 = Column(Float, nullable=False, default=0.0)
    rotation3 = Column(Float, nullable=False, default=0.0)
    spawntimesecs = Column(Integer, nullable=False, default=0)
    animprogress = Column(TINYINT(unsigned=True), nullable=False, default=0)
    state = Column(TINYINT(unsigned=True), nullable=False, default=0)


class WorldGameObjectTemplate(Base):
    __tablename__ = "gameobject_template"

    entry = Column(MEDIUMINT(unsigned=True), primary_key=True, default=0)
    type = Column(TINYINT(unsigned=True), nullable=False, default=0)
    displayId = Column(MEDIUMINT(unsigned=True), nullable=False, default=0)
    name = Column(String(100), nullable=False, default="")
    faction = Column(SMALLINT(unsigned=True), nullable=False, default=0)
    flags = Column(Integer, nullable=False, default=0)
    size = Column(Float, nullable=False, default=1.0)
    data0 = Column(Integer, nullable=False, default=0)
    data1 = Column(Integer, nullable=False, default=0)
    data2 = Column(Integer, nullable=False, default=0)
    data3 = Column(Integer, nullable=False, default=0)
    data4 = Column(Integer, nullable=False, default=0)
    data5 = Column(Integer, nullable=False, default=0)
    data6 = Column(Integer, nullable=False, default=0)
    data7 = Column(Integer, nullable=False, default=0)
    data8 = Column(Integer, nullable=False, default=0)
    data9 = Column(Integer, nullable=False, default=0)
    data10 = Column(Integer, nullable=False, default=0)
    data11 = Column(Integer, nullable=False, default=0)
    data12 = Column(Integer, nullable=False, default=0)
    data13 = Column(Integer, nullable=False, default=0)
    data14 = Column(Integer, nullable=False, default=0)
    data15 = Column(Integer, nullable=False, default=0)
    data16 = Column(Integer, nullable=False, default=0)
    data17 = Column(Integer, nullable=False, default=0)
    data18 = Column(Integer, nullable=False, default=0)
    data19 = Column(Integer, nullable=False, default=0)
    data20 = Column(Integer, nullable=False, default=0)
    data21 = Column(Integer, nullable=False, default=0)
    data22 = Column(Integer, nullable=False, default=0)
    data23 = Column(Integer, nullable=False, default=0)


class WorldCreature(Base):
    __tablename__ = "creature"

    guid = Column(INTEGER(unsigned=True), primary_key=True, default=0)
    id = Column(MEDIUMINT(unsigned=True), nullable=False, default=0)
    map = Column(SMALLINT(unsigned=True), nullable=False, default=0)
    spawnMask = Column(Integer, nullable=False, default=1)
    phaseId = Column(Integer, nullable=False, default=0)
    phaseGroup = Column(Integer, nullable=False, default=0)
    modelid = Column(MEDIUMINT(unsigned=True), nullable=False, default=0)
    equipment_id = Column(TINYINT(), nullable=False, default=0)
    position_x = Column(Float, nullable=False, default=0.0)
    position_y = Column(Float, nullable=False, default=0.0)
    position_z = Column(Float, nullable=False, default=0.0)
    orientation = Column(Float, nullable=False, default=0.0)
    spawntimesecs = Column(Integer, nullable=False, default=0)
    spawndist = Column(Float, nullable=False, default=0.0)
    currentwaypoint = Column(MEDIUMINT(unsigned=True), nullable=False, default=0)
    curhealth = Column(Integer, nullable=False, default=1)
    curmana = Column(Integer, nullable=False, default=0)
    MovementType = Column(TINYINT(unsigned=True), nullable=False, default=0)
    npcflag = Column(Integer, nullable=False, default=0)
    unit_flags = Column(Integer, nullable=False, default=0)
    dynamicflags = Column(Integer, nullable=False, default=0)


class WorldCreatureTemplate(Base):
    __tablename__ = "creature_template"

    entry = Column(MEDIUMINT(unsigned=True), primary_key=True, default=0)
    KillCredit1 = Column(INTEGER(unsigned=True), nullable=False, default=0)
    KillCredit2 = Column(INTEGER(unsigned=True), nullable=False, default=0)
    modelid1 = Column(MEDIUMINT(unsigned=True), nullable=False, default=0)
    modelid2 = Column(MEDIUMINT(unsigned=True), nullable=False, default=0)
    modelid3 = Column(MEDIUMINT(unsigned=True), nullable=False, default=0)
    modelid4 = Column(MEDIUMINT(unsigned=True), nullable=False, default=0)
    name = Column(String(100), nullable=False, default="")
    subname = Column(String(100))
    IconName = Column(String(100))
    exp = Column(SMALLINT(), nullable=False, default=0)
    faction_A = Column(SMALLINT(unsigned=True), nullable=False, default=0)
    faction_H = Column(SMALLINT(unsigned=True), nullable=False, default=0)
    npcflag = Column(Integer, nullable=False, default=0)
    npc_rank = Column(TINYINT(unsigned=True), nullable=False, default=0)
    type = Column(TINYINT(unsigned=True), nullable=False, default=0)
    type_flags = Column(Integer, nullable=False, default=0)
    type_flags2 = Column(Integer, nullable=False, default=0)
    family = Column(TINYINT(unsigned=True), nullable=False, default=0)
    movementId = Column(INTEGER(unsigned=True), nullable=False, default=0)
    Health_mod = Column(Float, nullable=False, default=1.0)
    Mana_mod = Column(Float, nullable=False, default=1.0)
    RacialLeader = Column(TINYINT(unsigned=True), nullable=False, default=0)
    questItem1 = Column(INTEGER(unsigned=True), nullable=False, default=0)
    questItem2 = Column(INTEGER(unsigned=True), nullable=False, default=0)
    questItem3 = Column(INTEGER(unsigned=True), nullable=False, default=0)
    questItem4 = Column(INTEGER(unsigned=True), nullable=False, default=0)
    questItem5 = Column(INTEGER(unsigned=True), nullable=False, default=0)
    questItem6 = Column(INTEGER(unsigned=True), nullable=False, default=0)


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

class GameEventGameObject(Base):
    __tablename__ = "game_event_gameobject"

    guid = Column(Integer, primary_key=True)
    eventEntry = Column(Integer)


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
