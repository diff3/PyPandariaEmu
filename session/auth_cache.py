#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading

ACCOUNT_CACHE = {}
ACCOUNT_CACHE_LOCK = threading.RLock()
