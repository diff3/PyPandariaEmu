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

    def add_session(self, client_ip, username):
        self.sessions[client_ip] = {
            "username": username,
            "timestamp": time.time()
        }

    def get_username(self, client_ip: str) -> bool:
        return self.sessions.get(client_ip, {}).get("username")

    def remove_session(self, client_ip):
        """Removes a session if it exists.

        Args:
            client_ip (str): The IP address of the client.
        """
       
        if client_ip in self.sessions:
            del self.sessions[client_ip]
            return True
        return False
