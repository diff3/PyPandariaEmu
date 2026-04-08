#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from types import SimpleNamespace

from sqlalchemy import text

from server.modules.database.DatabaseConnection import DatabaseConnection


class AuthRepositorySRP6:
    def __init__(self):
        self._session = DatabaseConnection.auth()

    def get_user_by_username(self, username: str):
        row = (
            self._session.execute(
                text(
                    """
                    SELECT username, v, s, session_key
                    FROM account
                    WHERE username = :username
                    LIMIT 1
                    """
                ),
                {"username": username},
            )
            .mappings()
            .first()
        )
        if row is None:
            return None
        return SimpleNamespace(
            username=str(row.get("username") or ""),
            v=row.get("v"),
            s=row.get("s"),
            session_key=row.get("session_key"),
        )
