#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger


class AuthConnection:
    """Dedicated auth-db access layer for proxy auth lookups."""

    _auth_engine = None
    _auth_session = None
    _repository = None
    _auth_mode = "srp6"
    _config_signature = None

    @staticmethod
    def initialize():
        config = ConfigLoader.load_config()
        db = config["database"]
        mode = AuthConnection._resolve_auth_mode(config)
        signature = (
            str(db.get("host", "")),
            int(db.get("port", 3306) or 3306),
            str(db.get("username", "")),
            str(db.get("password", "")),
            str(db.get("auth_db", "")),
            mode,
        )

        if AuthConnection._auth_session is not None and AuthConnection._config_signature == signature:
            return

        AuthConnection._dispose_existing()

        auth_url = (
            f"mysql+pymysql://{db['username']}:{db['password']}@"
            f"{db['host']}:{db['port']}/{db['auth_db']}?charset=utf8"
        )

        AuthConnection._auth_engine = create_engine(auth_url, pool_pre_ping=True)
        AuthConnection._auth_session = scoped_session(
            sessionmaker(bind=AuthConnection._auth_engine, autoflush=False)
        )
        AuthConnection._auth_mode = mode
        AuthConnection._repository = AuthConnection._build_repository(AuthConnection._auth_mode)
        AuthConnection._config_signature = signature

        Logger.info(f"Auth database initialized (mode={AuthConnection._auth_mode})")

    @staticmethod
    def session():
        if AuthConnection._auth_session is None:
            AuthConnection.initialize()
        return AuthConnection._auth_session

    @staticmethod
    def _dispose_existing() -> None:
        if AuthConnection._auth_session is not None:
            try:
                AuthConnection._auth_session.remove()
            except Exception:
                pass
        if AuthConnection._auth_engine is not None:
            try:
                AuthConnection._auth_engine.dispose()
            except Exception:
                pass

        AuthConnection._auth_engine = None
        AuthConnection._auth_session = None
        AuthConnection._repository = None
        AuthConnection._config_signature = None

    @staticmethod
    def _resolve_auth_mode(config: dict | None = None) -> str:
        cfg = config or ConfigLoader.load_config()
        mode = str(
            ((((cfg.get("proxy") or {}).get("phases") or {}).get("world") or {}).get("mode"))
            or "srp6"
        ).strip().lower()
        if mode == "legacy":
            return "legacy"
        return "srp6"

    @staticmethod
    def _build_repository(mode: str):
        if mode == "legacy":
            from server.modules.database.AuthRepositoryLegacy import AuthRepositoryLegacy

            return AuthRepositoryLegacy(AuthConnection.session)

        from server.modules.database.AuthRepositorySRP6 import AuthRepositorySRP6

        return AuthRepositorySRP6(AuthConnection.session)

    @staticmethod
    def _repo():
        AuthConnection.initialize()
        return AuthConnection._repository

    @staticmethod
    def get_user(username):
        return AuthConnection._repo().get_user_by_username(username)

    @staticmethod
    def get_account_id(username):
        return AuthConnection._repo().get_account_id_by_username(username)

    @staticmethod
    def get_realmlist():
        return AuthConnection._repo().get_realmlist()

    @staticmethod
    def get_all_realms():
        return AuthConnection._repo().get_all_realms()

    @staticmethod
    def update_sessionkey(account, key_bytes):
        return AuthConnection._repo().update_sessionkey(account, key_bytes)

    @staticmethod
    def update_verifier(account, verifier, salt):
        return AuthConnection._repo().update_verifier_and_salt(account, verifier, salt)

    @staticmethod
    def create_or_update_account(username, salt, verifier):
        return AuthConnection._repo().create_or_update_account(username, salt, verifier)

    @staticmethod
    def set_gmlevel(account_id, gmlevel):
        return AuthConnection._repo().set_gmlevel(account_id, gmlevel)
