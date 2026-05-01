#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sqlalchemy import Column, Integer, String, DateTime, Float, BigInteger
from sqlalchemy.dialects.mysql import TINYINT
from sqlalchemy.orm import declarative_base
from datetime import datetime


Base = declarative_base()


# -------------------------------------------------------
# ACCOUNT TABLE (legacy / pandaria)
# -------------------------------------------------------
class Account(Base):
    __tablename__ = "account"

    id = Column(Integer, primary_key=True, autoincrement=True)

    username = Column(String(32), unique=True, nullable=False)
    battlenet_account = Column(String(32), nullable=False, default="")

    # Legacy auth (SHA1)
    sha_pass_hash = Column(String(40), nullable=False, default="")

    # ⚠️ IMPORTANT:
    # Stored as HEX string in DB, but proxy expects bytes
    sessionkey = Column(String(80), nullable=False, default="")
    v = Column(String(64), nullable=False, default="")
    s = Column(String(64), nullable=False, default="")

    token_key = Column(String(100), nullable=False, default="")

    email = Column(String(255), nullable=False, default="")
    reg_mail = Column(String(255), nullable=False, default="")

    joindate = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_ip = Column(String(15), nullable=False, default="127.0.0.1")

    failed_logins = Column(Integer, nullable=False, default=0)

    locked = Column(TINYINT(unsigned=True), nullable=False, default=0)

    last_login = Column(DateTime, nullable=True)
    online = Column(TINYINT(unsigned=True), nullable=False, default=0)

    expansion = Column(TINYINT(unsigned=True), nullable=False, default=4)
    hasBoost = Column(TINYINT, nullable=False, default=0)

    mutetime = Column(BigInteger, nullable=False, default=0)
    mutereason = Column(String(255), nullable=False, default="")
    muteby = Column(String(50), nullable=False, default="")

    locale = Column(TINYINT(unsigned=True), nullable=False, default=0)
    os = Column(String(4), nullable=False, default="")

    recruiter = Column(Integer, nullable=False, default=0)

    # Optional project fields
    project_member_id = Column(Integer, nullable=False, default=0)
    rank = Column(Integer, nullable=True)
    staff_id = Column(Integer, nullable=True)
    vp = Column(Integer, nullable=True)
    dp = Column(Integer, nullable=False, default=0)

    isactive = Column(String(50), nullable=True)
    activation = Column(String(256), nullable=True)

    invited_by = Column(String(32), nullable=False, default="")
    inv_friend_acc = Column(String(32), nullable=False, default="")
    rewarded = Column(Integer, nullable=False, default=0)

    flags = Column(Integer, nullable=False, default=0)

    # ⚠️ legacy often stores gmlevel here too
    gmlevel = Column(TINYINT(unsigned=True), nullable=False, default=0)

    active_realm_id = Column(Integer, nullable=False, default=0)

    online_mute_timer = Column(BigInteger, nullable=False, default=0)
    active_mute_id = Column(Integer, nullable=False, default=0)

    project_verified = Column(TINYINT, nullable=False, default=0)

    cash = Column(Integer, nullable=False, default=0)

    project_is_free = Column(TINYINT, nullable=False, default=0)
    project_is_temp = Column(TINYINT, nullable=False, default=0)
    project_unban_count = Column(TINYINT, nullable=False, default=0)

    project_antierror = Column(Integer, nullable=True)
    project_attached = Column(Integer, nullable=True)

    project_passchange = Column(Integer, nullable=False, default=0)
    project_vote_time = Column(BigInteger, nullable=False, default=0)

    project_hwid = Column(String(40), nullable=False, default="")
    lock_country = Column(String(2), nullable=False, default="")

    # --------------------------------------------------
    # Compatibility helpers (IMPORTANT)
    # --------------------------------------------------

    @property
    def session_key(self):
        """
        Compatibility with SRP6 code.
        Converts HEX string → bytes.
        """
        if not self.sessionkey:
            return None
        try:
            return bytes.fromhex(self.sessionkey)
        except Exception:
            return None

    @session_key.setter
    def session_key(self, value: bytes):
        """
        Accept bytes → store as HEX string.
        """
        if value is None:
            self.sessionkey = ""
        else:
            self.sessionkey = value.hex()

    @property
    def verifier(self):
        if not self.v:
            return None
        try:
            return bytes.fromhex(self.v)
        except Exception:
            return None

    @verifier.setter
    def verifier(self, value: bytes):
        if value is None:
            self.v = ""
        else:
            self.v = bytes(value).hex()

    @property
    def salt(self):
        if not self.s:
            return None
        try:
            return bytes.fromhex(self.s)
        except Exception:
            return None

    @salt.setter
    def salt(self, value: bytes):
        if value is None:
            self.s = ""
        else:
            self.s = bytes(value).hex()


AccountLegacy = Account


# -------------------------------------------------------
# ACCOUNT ACCESS TABLE
# -------------------------------------------------------
class AccountAccess(Base):
    __tablename__ = "account_access"

    id = Column(Integer, primary_key=True)
    RealmID = Column(Integer, primary_key=True, default=-1)

    gmlevel = Column(TINYINT(unsigned=True), nullable=False)
    name = Column(String(255), nullable=True)


# -------------------------------------------------------
# ACCOUNT BANNED TABLE
# -------------------------------------------------------
class AccountBanned(Base):
    __tablename__ = "account_banned"

    id = Column(Integer, primary_key=True)
    bandate = Column(Integer, primary_key=True)

    realm = Column(Integer, nullable=False)
    unbandate = Column(Integer, nullable=False)

    bannedby = Column(String(50), nullable=False)
    banreason = Column(String(255), nullable=False)

    active = Column(TINYINT(unsigned=True), nullable=False, default=1)


# -------------------------------------------------------
# REALMLIST TABLE
# -------------------------------------------------------
class RealmList(Base):
    __tablename__ = "realmlist"

    id = Column(Integer, primary_key=True, autoincrement=True)

    name = Column(String(32), nullable=False, default="")
    project_shortname = Column(String(32), nullable=False)

    address = Column(String(32), nullable=False, default="127.0.0.1")
    port = Column(Integer, nullable=False, default=8085)

    icon = Column(TINYINT(unsigned=True), nullable=False, default=0)
    color = Column(TINYINT(unsigned=True), nullable=False, default=2)
    timezone = Column(TINYINT(unsigned=True), nullable=False, default=0)

    allowedSecurityLevel = Column(TINYINT(unsigned=True), nullable=False, default=0)

    population = Column(Float, nullable=False, default=0)
    gamebuild = Column(Integer, nullable=False, default=12340)

    flag = Column(Integer, nullable=True)

    project_hidden = Column(TINYINT, nullable=False, default=0)
    project_enabled = Column(TINYINT, nullable=False, default=1)

    project_dbname = Column(String(32), nullable=False)
    project_dbworld = Column(String(32), nullable=False)
    project_dbarchive = Column(String(32), nullable=False)
