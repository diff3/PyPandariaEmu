#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from utils.ConfigLoader import ConfigLoader
from database.AuthModel import Account, AccountAccess, RealmList

class DatabaseConnection:
    """Handles database connection and session management."""

    _engine = None
    _session = None

    @staticmethod
    def get_session():
        """
        Returns a scoped session for database operations.
        Returns:
            Session: A SQLAlchemy scoped session.
        """
        if DatabaseConnection._session is None:
            raise RuntimeError("Database connection has not been initialized.")
        return DatabaseConnection._session

    @staticmethod
    def initialize():
        """
        Initializes the database connection using configuration.
        """
        config = ConfigLoader.load_config()
        db_config = config["database"]
        DatabaseConnection._engine = create_engine(
            f'mysql+pymysql://{db_config["user"]}:{db_config["password"]}@'
            f'{db_config["host"]}:{db_config["port"]}/{db_config["auth"]}'
            f'?charset={db_config["charset"]}',
            pool_pre_ping=True
        )
        DatabaseConnection._session = scoped_session(sessionmaker(bind=DatabaseConnection._engine, autoflush=False))

    @staticmethod
    def get_user_by_username(username):
        """
        Fetches all data for a user by username.
        Args:
            username (str): The username to search for.
        Returns:
            Account: The user's record or None if not found.
        """
        session = DatabaseConnection.get_session()
        return session.query(Account).filter(Account.username == username).first()

    @staticmethod
    def get_mirrored_sessionkey_by_username(username):
        session = DatabaseConnection.get_session()
        account = session.query(Account).filter(Account.username == username).first()
        # return account.sessionkey
        return bytes.fromhex(account.sessionkey)[::-1].hex()

    @staticmethod
    def user_exists(username):
        """
        Checks if a user exists by username.
        Args:
            username (str): The username to check.
        Returns:
            bool: True if the user exists, False otherwise.
        """
        return DatabaseConnection.get_user_by_username(username) is not None

    @staticmethod
    def is_user_online(username):
        """
        Checks if a user is online by username.
        Args:
            username (str): The username to check.
        Returns:
            bool: True if the user is online (1), False otherwise (0).
        """
        user = DatabaseConnection.get_user_by_username(username)
        return user.online == 1 if user else False

    @staticmethod
    def has_boost(username):
        """
        Checks if a user has a boost by username.
        Args:
            username (str): The username to check.
        Returns:
            bool: True if the user has a boost (1), False otherwise (0).
        """
        user = DatabaseConnection.get_user_by_username(username)
        return user.boost == 1 if user else False

    @staticmethod
    def is_user_blocked(username):
        """
        Checks if a user is blocked by username.
        Args:
            username (str): The username to check.
        Returns:
            bool: True if the user is blocked (1), False otherwise (0).
        """
        user = DatabaseConnection.get_user_by_username(username)
        return user.blocked == 1 if user else False

    @staticmethod
    def is_user_locked(username):
        """
        Checks if a user is locked by username.
        Args:
            username (str): The username to check.
        Returns:
            bool: True if the user is locked (1), False otherwise (0).
        """
        user = DatabaseConnection.get_user_by_username(username)
        return user.locked == 1 if user else False

    @staticmethod
    def get_realmlist():
        session = DatabaseConnection.get_session()
        return session.query(RealmList).first()
        
    @staticmethod
    def update_sessionkey(account, key):
        session = DatabaseConnection.get_session()
        account.sessionkey = key
        session.commit()

    @staticmethod
    def update_vhex_and_shex(account, vhex, shex):
        session = DatabaseConnection.get_session()
        account.v = vhex
        account.s = shex
        session.commit()

    @staticmethod
    def create_user(new_account):
        session = DatabaseConnection.get_session() 
        session.add(new_account)
        session.commit()

    @staticmethod
    def create_user_access(new_account_access):
        try:
            session = DatabaseConnection.get_session()
            session.add(new_account_access)
            session.commit()
        except: 
            Logger.warning(f'Could not create user access information')
