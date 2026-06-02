#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from server.modules.handlers.world.protocol.update_object.gameobject import (
    GAMEOBJECT_TYPE_MO_TRANSPORT,
    GAMEOBJECT_TYPE_TRANSPORT,
    GO_FLAG_TRANSPORT,
)

TRANSPORT_GAMEOBJECT_TYPES = (GAMEOBJECT_TYPE_TRANSPORT, GAMEOBJECT_TYPE_MO_TRANSPORT)

__all__ = [
    "GAMEOBJECT_TYPE_MO_TRANSPORT",
    "GAMEOBJECT_TYPE_TRANSPORT",
    "GO_FLAG_TRANSPORT",
    "TRANSPORT_GAMEOBJECT_TYPES",
]
