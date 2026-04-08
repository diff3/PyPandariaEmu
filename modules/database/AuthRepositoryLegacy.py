#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Auth repository (Legacy version)

Same API, different model import.
"""

from server.modules.database.AuthModelLegacy import Account, AccountAccess, RealmList
from shared.Logger import Logger


class AuthRepositoryLegacy:
    def __init__(self, session_factory):
        self._session_factory = session_factory

    def _session(self):
        return self._session_factory()

    # --------------------------------------------------
    # Account
    # --------------------------------------------------

    def get_user_by_username(self, username: str):
        return (
            self._session()
            .query(Account)
            .filter(Account.username == username)
            .first()
        )

    def get_account_id_by_username(self, username: str):
        row = (
            self._session()
            .query(Account.id)
            .filter(Account.username == username)
            .first()
        )
        return row[0] if row else None

    def create_or_update_account(self, username, salt, verifier):
        session = self._session()

        acc = (
            session.query(Account)
            .filter(Account.username == username)
            .first()
        )

        if acc is None:
            acc = Account(username=username)
            acc.salt = salt
            acc.verifier = verifier
            session.add(acc)
            Logger.success(f"[DB] Created account {username}")
        else:
            acc.salt = salt
            acc.verifier = verifier
            Logger.success(f"[DB] Updated account {username}")

        session.commit()
        return acc.id

    def update_sessionkey(self, account, key_bytes):
        session = self._session()
        account.session_key = key_bytes
        session.commit()

    def update_verifier_and_salt(self, account, verifier, salt):
        session = self._session()
        account.verifier = verifier
        account.salt = salt
        session.commit()

    # --------------------------------------------------
    # AccountAccess
    # --------------------------------------------------

    def set_gmlevel(self, account_id, gmlevel):
        session = self._session()

        row = (
            session.query(AccountAccess)
            .filter(AccountAccess.id == account_id)
            .first()
        )

        if row is None:
            row = AccountAccess(id=account_id, gmlevel=gmlevel, RealmID=-1)
            session.add(row)
        else:
            row.gmlevel = gmlevel

        session.commit()
        Logger.success(f"[DB] GM level set to {gmlevel} for account {account_id}")

    # --------------------------------------------------
    # RealmList
    # --------------------------------------------------

    def get_realmlist(self):
        return self._session().query(RealmList).first()

    def get_all_realms(self):
        return self._session().query(RealmList).all()
