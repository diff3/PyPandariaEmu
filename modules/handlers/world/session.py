from __future__ import annotations

from server.session.world_session import WorldSession


class Session(WorldSession):
    """Thin dispatcher-facing alias for the existing world session model."""


__all__ = ["Session"]
