from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
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