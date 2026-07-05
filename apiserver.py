#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from shared.Logger import Logger
from shared.ConfigLoader import ConfigLoader
from server.modules.api.server import run_api_server


def run_api() -> None:
    Logger.configure(scope="apiserver", reset=True)
    ConfigLoader.load_config()
    run_api_server()


if __name__ == "__main__":
    run_api()

