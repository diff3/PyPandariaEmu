#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from server.AuthServer import AuthServer
from utils.Logger import Logger
import yaml


with open("etc/config.yaml", 'r') as file:
    config = yaml.safe_load(file)

if __name__ == "__main__":   
    Logger.info(f'Mist of Pandaria 5.4.8 AuthServer')
    AuthServer.start(host=config['authserver']['host'], port=config['authserver']['port'])