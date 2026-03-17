#!/usr/bin/env python3
# -*- coding: utf-8 -*

import time

class SessionManager:
    _instance = None  # Singleton-instans
    timeout = 600

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SessionManager, cls).__new__(cls, *args, **kwargs)
            cls._instance.sessions = {}  # Initiera en tom sessionslista
        return cls._instance

    def add_session(self, client_ip, username, session_key=None):
        self.sessions[client_ip] = {
            "username": username,
            "session_key": session_key,
            "timestamp": time.time()
        }

    def get_session(self, client_ip: str):
        """Return whole session dict or None."""
        return self.sessions.get(client_ip)

    def get_username(self, client_ip: str):
        return self.sessions.get(client_ip, {}).get("username")

    def get_session_key(self, client_ip: str):
        return self.sessions.get(client_ip, {}).get("session_key")

    def remove_session(self, client_ip):
        if client_ip in self.sessions:
            del self.sessions[client_ip]
            return True
        return False