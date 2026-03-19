#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import threading
from typing import Any

from server.session.world_session import WorldSession


_LOCAL = threading.local()


def get_world_session() -> WorldSession:
    session = getattr(_LOCAL, "world_session", None)
    if session is None:
        session = WorldSession()
        _LOCAL.world_session = session
    return session


def bind_world_session(session: WorldSession) -> WorldSession:
    _LOCAL.world_session = session
    return session


def clear_world_session() -> None:
    if hasattr(_LOCAL, "world_session"):
        delattr(_LOCAL, "world_session")


class SessionProxy:
    def __getattr__(self, name: str) -> Any:
        return getattr(get_world_session(), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(get_world_session(), name, value)

    def __repr__(self) -> str:
        return repr(get_world_session())


session = SessionProxy()
