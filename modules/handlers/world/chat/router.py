#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class ChatRouter:
    def __init__(self):
        self.chat_scope = {
            "say": "world",
        }

    def get_targets(self, session, channel):
        scope = self.chat_scope.get(channel, "world")

        if scope == "world":
            global_state = getattr(session, "global_state", None)
            if global_state is None:
                return set()
            return global_state.chat_channels.setdefault("world", set())

        if scope == "region":
            region = getattr(session, "region", None)
            if region is None:
                return set()
            return region.players

        return set()


chat_router = ChatRouter()
