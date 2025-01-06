#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from servers.AuthServer import AuthServer
from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger


if __name__ == "__main__":   
    config = ConfigLoader.load_config()
    Logger.info(f'Mist of Pandaria 5.4.8 AuthServer')
    AuthServer.start(host=config['authserver']['host'], port=config['authserver']['port'])