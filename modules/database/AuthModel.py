#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean,
    Float, LargeBinary
)
from sqlalchemy.dialects.mysql import SMALLINT
from sqlalchemy.orm import declarative_base

# -------------------------------------------------------
# ACCOUNT TABLE (skyfire548_auth.account)
# -------------------------------------------------------
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean,
    LargeBinary, SmallInteger
)
from sqlalchemy.dialects.mysql import TINYINT
from server.modules.database.Base import Base
from datetime import datetime


class Account(Base):
    __tablename__ = "account"

    id = Column(Integer, primary_key=True, autoincrement=True)

    username = Column(String(32), unique=True, nullable=False)

    salt = Column(LargeBinary(32), nullable=False, default=b"")
    verifier = Column(LargeBinary(32), nullable=False, default=b"")

    session_key = Column(LargeBinary(40), nullable=False, default=b"")
    token_key = Column(LargeBinary(100), nullable=False, default=b"")

    email = Column(String(255), nullable=False, default="")
    reg_mail = Column(String(255), nullable=False, default="")

    joindate = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_ip = Column(String(15), nullable=False, default="0.0.0.0")

    failed_logins = Column(Integer, nullable=False, default=0)

    locked = Column(TINYINT, nullable=False, default=0)
    lock_country = Column(String(2), nullable=False, default="00")

    last_login = Column(DateTime, nullable=False, default=datetime.utcnow)
    online = Column(TINYINT, nullable=False, default=0)

    expansion = Column(TINYINT, nullable=False, default=5)

    mutetime = Column(Integer, nullable=False, default=0)
    mutereason = Column(String(255), nullable=False, default="")
    muteby = Column(String(255), nullable=False, default="")

    locale = Column(TINYINT, nullable=False, default=0)
    os = Column(String(10), nullable=False, default="Win")

    recruiter = Column(Integer, nullable=False, default=0)

    hasBoost = Column(TINYINT, nullable=False, default=0)


# -------------------------------------------------------
# ACCOUNT ACCESS TABLE (gm level)
# -------------------------------------------------------
class AccountAccess(Base):
    __tablename__ = "account_access"

    id = Column(Integer, primary_key=True)
    gmlevel = Column(SMALLINT, nullable=False)
    RealmID = Column(Integer, nullable=False, default=-1, primary_key=True)


# -------------------------------------------------------
# ACCOUNT BANNED TABLE
# -------------------------------------------------------
class AccountBanned(Base):
    __tablename__ = "account_banned"
    __table_args__ = {"comment": "Ban list"}

    id = Column(Integer, primary_key=True)
    bandate = Column(Integer, primary_key=True)
    unbandate = Column(Integer)
    bannedby = Column(String(50))
    banreason = Column(String(255))
    active = Column(SMALLINT)


# -------------------------------------------------------
# REALMLIST TABLE
# -------------------------------------------------------
class RealmList(Base):
    __tablename__ = "realmlist"

    id = Column(Integer, primary_key=True)
    name = Column(String(32))
    address = Column(String(255))
    localAddress = Column(String(255))
    localSubnetMask = Column(String(255))
    port = Column(SMALLINT)

    icon = Column(Integer)
    flag = Column(Integer)
    timezone = Column(Integer)
    allowedSecurityLevel = Column(Integer)

    population = Column(Float)
    gamebuild = Column(Integer)
