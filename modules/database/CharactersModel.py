# -*- coding: utf-8 -*-

from sqlalchemy import Column, Integer, BigInteger, SmallInteger, String, Text, Float
from sqlalchemy.dialects.mysql import TINYINT, SMALLINT, INTEGER, MEDIUMINT

from server.modules.database.Base import Base


class Characters(Base):
    __tablename__ = "characters"

    guid = Column(Integer, primary_key=True, autoincrement=False)             # int(10) unsigned
    realm = Column(Integer, nullable=False, default=0)
    account = Column(Integer, nullable=False)
    name = Column(String(12, collation="utf8mb3_bin"), nullable=False)
    slot = Column(SmallInteger, nullable=False, default=0)
    race = Column(SmallInteger, nullable=False, default=0)
    class_ = Column("class", SmallInteger, nullable=False, default=0)
    gender = Column(SmallInteger, nullable=False, default=0)
    level = Column(SmallInteger, nullable=False, default=0)
    xp = Column(Integer, nullable=False, default=0)
    money = Column(BigInteger, nullable=False, default=0)
    playerBytes = Column(Integer, nullable=False, default=0)
    playerBytes2 = Column(Integer, nullable=False, default=0)
    playerFlags = Column(Integer, nullable=False, default=0)
    position_x = Column(Float, nullable=False, default=0.0)
    position_y = Column(Float, nullable=False, default=0.0)
    position_z = Column(Float, nullable=False, default=0.0)
    map = Column(SmallInteger, nullable=False, default=0)
    instance_id = Column(Integer, nullable=False, default=0)
    dungeonDifficulty = Column(SmallInteger, nullable=False, default=1)
    raidDifficulty = Column(SmallInteger, nullable=False, default=14)
    orientation = Column(Float, nullable=False, default=0.0)
    taximask = Column(Text, nullable=False)
    online = Column(SmallInteger, nullable=False, default=0)
    cinematic = Column(SmallInteger, nullable=False, default=0)
    totaltime = Column(Integer, nullable=False, default=0)
    leveltime = Column(Integer, nullable=False, default=0)
    logout_time = Column(Integer, nullable=False, default=0)
    is_logout_resting = Column(SmallInteger, nullable=False, default=0)
    rest_bonus = Column(Float, nullable=False, default=0.0)
    resettalents_cost = Column(Integer, nullable=False, default=0)
    resettalents_time = Column(Integer, nullable=False, default=0)
    talentTree = Column(String(10), nullable=False, default="0 0")
    trans_x = Column(Float, nullable=False, default=0.0)
    trans_y = Column(Float, nullable=False, default=0.0)
    trans_z = Column(Float, nullable=False, default=0.0)
    trans_o = Column(Float, nullable=False, default=0.0)
    transguid = Column(Integer, nullable=False, default=0)
    extra_flags = Column(SmallInteger, nullable=False, default=0)
    stable_slots = Column(SmallInteger, nullable=False, default=0)
    at_login = Column(SmallInteger, nullable=False, default=0)
    zone = Column(SmallInteger, nullable=False, default=0)
    death_expire_time = Column(Integer, nullable=False, default=0)
    taxi_path = Column(Text)
    totalKills = Column(Integer, nullable=False, default=0)
    todayKills = Column(SmallInteger, nullable=False, default=0)
    yesterdayKills = Column(SmallInteger, nullable=False, default=0)
    chosenTitle = Column(Integer, nullable=False, default=0)
    watchedFaction = Column(Integer, nullable=False, default=0)
    lfgbonusfaction = Column(Integer, nullable=False, default=0)
    drunk = Column(SmallInteger, nullable=False, default=0)
    health = Column(Integer, nullable=False, default=0)
    power1 = Column(Integer, nullable=False, default=0)
    power2 = Column(Integer, nullable=False, default=0)
    power3 = Column(Integer, nullable=False, default=0)
    power4 = Column(Integer, nullable=False, default=0)
    power5 = Column(Integer, nullable=False, default=0)
    latency = Column(Integer, nullable=False, default=0)
    speccount = Column(SmallInteger, nullable=False, default=1)
    activespec = Column(SmallInteger, nullable=False, default=0)
    exploredZones = Column(Text)
    equipmentCache = Column(Text)
    knownTitles = Column(Text)
    actionBars = Column(SmallInteger, nullable=False, default=0)
    grantableLevels = Column(SmallInteger, nullable=False, default=0)
    deleteInfos_Account = Column(Integer)
    deleteInfos_Name = Column(String(12))
    deleteDate = Column(Integer)


class CharacterAction(Base):
    __tablename__ = "character_action"

    guid = Column(Integer, primary_key=True, autoincrement=False)
    spec = Column(TINYINT(unsigned=True), primary_key=True, default=0)
    button = Column(SMALLINT(unsigned=True), primary_key=True, default=0)
    action = Column(Integer, nullable=False, default=0)
    type_ = Column("type", TINYINT(unsigned=True), nullable=False, default=0)


class CharacterSpell(Base):
    __tablename__ = "character_spell"

    guid = Column(Integer, primary_key=True, autoincrement=False)
    spell = Column(MEDIUMINT(unsigned=True), primary_key=True, default=0)
    active = Column(TINYINT(unsigned=True), nullable=False, default=1)
    disabled = Column(TINYINT(unsigned=True), nullable=False, default=0)
    spec = Column(TINYINT(unsigned=True), nullable=False, default=0)
    spec_mask = Column("specMask", SMALLINT(unsigned=True), nullable=False, default=0)


class CharacterInventory(Base):
    __tablename__ = "character_inventory"

    guid = Column(Integer, nullable=False, default=0)
    bag = Column(Integer, nullable=False, default=0)
    slot = Column(TINYINT(unsigned=True), nullable=False, default=0)
    item = Column(Integer, primary_key=True, autoincrement=False, default=0)


class ItemInstance(Base):
    __tablename__ = "item_instance"

    guid = Column(Integer, primary_key=True, autoincrement=False, default=0)
    itemEntry = Column(MEDIUMINT(unsigned=True), nullable=False, default=0)
    owner_guid = Column(Integer, nullable=False, default=0)
    creatorGuid = Column(Integer, nullable=False, default=0)
    giftCreatorGuid = Column(Integer, nullable=False, default=0)
    count = Column(Integer, nullable=False, default=1)
    duration = Column(Integer, nullable=False, default=0)
    charges = Column(Text)
    flags = Column(MEDIUMINT(unsigned=True), nullable=False, default=0)
    enchantments = Column(Text, nullable=False, default="")
    randomPropertyId = Column(SmallInteger, nullable=False, default=0)
    reforgeID = Column(Integer, nullable=False, default=0)
    durability = Column(SMALLINT(unsigned=True), nullable=False, default=0)
    playedTime = Column(Integer, nullable=False, default=0)
    text = Column(Text)
