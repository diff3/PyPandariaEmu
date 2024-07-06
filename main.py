#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-

import yaml

from server.auth.AuthServer import AuthServer
from utils.Logger import Logger


with open("etc/config.yaml", 'r') as file:
    config = yaml.safe_load(file)

if __name__ == "__main__":   
    Logger.info(f'Mist of Pandaria 5.4.8 Authserver')
    AuthServer.start(port=config['authserver']['port'])