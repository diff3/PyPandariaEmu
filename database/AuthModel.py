#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Float, SmallInteger
from sqlalchemy.dialects.mysql import SMALLINT as Smallint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


Base = declarative_base()

class Account(Base):
    __tablename__ = 'account'

    id = Column(Integer, primary_key=True)
    username = Column(String(32))
    sha_pass_hash = Column(String(40))
    sessionkey = Column(String(80))
    v = Column(String(64))
    s = Column(String(64))
    token_key = Column(String(100))
    email = Column(String(255))
    reg_mail = Column(String(255))
    joindate = Column(DateTime)
    last_ip = Column(String(15))
    failed_logins = Column(Integer)
    locked = Column(Boolean)
    lock_country = Column(String(2))
    last_login = Column(DateTime)
    online = Column(Boolean)
    expansion = Column(Integer)
    mutetime = Column(Integer)
    mutereason = Column(String(255))
    muteby = Column(String(255))
    locale = Column(String(4))
    os = Column(String(10))
    recruiter = Column(Integer)
    hasBoost = Column(Boolean)


class AccountAccess(Base):
    __tablename__ = 'account_access'

    id = Column(Integer, primary_key=True, nullable=False)
    gmlevel = Column(SmallInteger, nullable=False)
    RealmID = Column(Integer,  primary_key=True, nullable=False, default=-1)


class AccountBanned(Base):
    __tablename__ = 'account_banned'
    __table_args__ = {'comment': 'Ban List'}

    id = Column(Integer, primary_key=True, autoincrement=False, nullable=False, default=0, comment='Account id')
    bandate = Column(Integer, primary_key=True, nullable=False, default=0)
    unbandate = Column(Integer, nullable=False, default=0)
    bannedby = Column(String(50), nullable=False)
    banreason = Column(String(255), nullable=False)
    active = Column(SmallInteger, nullable=False, default=1)


class RealmList(Base):
    __tablename__ = 'realmlist'

    id = Column(Integer, primary_key=True)
    name = Column(String(32), server_default="PyPandaria")
    address = Column(String(255), server_default="127.0.0.1")
    localAddress = Column(String(255), server_default="127.0.0.1")
    localSubnetMask = Column(String(255), server_default="255.255.255.0")
    port = Column(Smallint(5), server_default="8085")
    icon = Column(Boolean, server_default="0")
    flag = Column(Boolean, server_default="0")
    timezone = Column(Boolean, server_default="1")
    allowedSecurityLevel = Column(Boolean, server_default="0")
    population = Column(Float, server_default="0")
    gamebuild = Column(Integer, server_default="18414")