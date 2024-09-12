#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from colorama import init
from colorama import Fore, Style
from datetime import datetime
from enum import Enum, IntEnum
# from utils.auth.packets import *
import yaml
# import importlib


with open("etc/config.yaml", 'r') as file:
    config = yaml.safe_load(file)


# plugin = config['authserver']['plugin']
# opcode_handlers = importlib.import_module(f'plugins.{plugin}.AuthHandler')
# opcodes = importlib.import_module(f'plugins.{plugin}.opcodes')


class DebugColorLevel(Enum):
    SUCCESS = Fore.GREEN + Style.BRIGHT
    INFO = Fore.BLUE + Style.BRIGHT
    ANTICHEAT = Fore.LIGHTBLUE_EX + Style.BRIGHT
    WARNING = Fore.YELLOW + Style.BRIGHT
    ERROR = Fore.RED + Style.BRIGHT
    DEBUG = Fore.CYAN + Style.BRIGHT
    SCRIPT = Fore.MAGENTA + Style.BRIGHT


class DebugLevel(IntEnum):
    NONE = 0x00
    SUCCESS = 0x01
    INFO = 0x02
    ANTICHEAT = 0x04
    WARNING = 0x08
    ERROR = 0x10
    DEBUG = 0x20
    SCRIPT = 0x40


class Logger:
    # Initialize colorama.
    init()

    @staticmethod
    def _should_log(log_type: DebugLevel, logging_mask=None):

        if not logging_mask:
            logging_mask = config['Logging']['logging_mask']

        return logging_mask & log_type

    @staticmethod
    def _colorize_message(label, color, msg):
        date = datetime.now().strftime('[%d/%m/%Y %H:%M:%S]')
        return f'{color.value}{label}{Style.RESET_ALL} {date} {msg}'

    @staticmethod
    def add_to_log(msg, debugLevel):
        file = config['Logging']['log_file']

        date = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        formatted_msg = f'[{debugLevel}] [{date}] {msg}'

        with open(f'logs/{file}', 'a') as log_file:
            log_file.write(formatted_msg + '\n')
    
    @staticmethod
    def debug(msg):
        if Logger._should_log(DebugLevel.DEBUG):
            print(Logger._colorize_message('[DEBUG]', DebugColorLevel.DEBUG, msg))
            Logger.add_to_log(msg, 'DEBUG')

    @staticmethod
    def warning(msg):
        if Logger._should_log(DebugLevel.WARNING):
            print(Logger._colorize_message('[WARNING]', DebugColorLevel.WARNING, msg))
            Logger.add_to_log(msg, 'WARNING')

    @staticmethod
    def error(msg):
        if Logger._should_log(DebugLevel.ERROR):
            print(Logger._colorize_message('[ERROR]', DebugColorLevel.ERROR, msg))
            Logger.add_to_log(msg, 'ERROR')

    @staticmethod
    def info(msg, end='\n'):
        if Logger._should_log(DebugLevel.INFO):
            print(Logger._colorize_message('[INFO]', DebugColorLevel.INFO, msg))
            Logger.add_to_log(msg, 'INFO')

    @staticmethod
    def success(msg):
        if Logger._should_log(DebugLevel.SUCCESS):
            print(Logger._colorize_message('[SUCCESS]', DebugColorLevel.SUCCESS, msg))
            Logger.add_to_log(msg, 'SUCCESS')

    @staticmethod
    def anticheat(msg):
        if Logger._should_log(DebugLevel.ANTICHEAT):
            print(Logger._colorize_message('[ANTICHEAT]', DebugColorLevel.ANTICHEAT, msg))
            Logger.add_to_log(msg, 'ANTICHEAT')

    @staticmethod
    def script(msg):
        if Logger._should_log(DebugLevel.SCRIPT):
            print(Logger._colorize_message('[SCRIPT]', DebugColorLevel.SCRIPT, msg))
            Logger.add_to_log(msg, 'SCRIPT')

    @staticmethod
    def package(data_str, logging_mask=None):
        if not logging_mask:
            logging_mask = config["Logging"]["logging_mask"]
    
        if Logger._should_log(DebugLevel.DEBUG, logging_mask):
            data = eval(data_str)    

            class_name = data.__class__.__name__
            formatted_message = f'\n{class_name}(\n'
            for key, value in data.__dict__.items():
                value_str = repr(value)
                formatted_message += f'   {key}={value_str},\n'
            formatted_message = formatted_message.rstrip(',\n') + '\n)'
            print(Logger._colorize_message('[PACKAGE]', DebugColorLevel.DEBUG, formatted_message))
            Logger.add_to_log(formatted_message, 'PACKAGE')

    # Additional methods

    @staticmethod
    def progress(msg, current, total, divisions=20):
        msg = f'{msg} [{current}/{total}] ({int(current * 100 / total)}%)'
        if current != total and divisions > 0:
            if int(current % (total / divisions)) == 0:
                Logger.info(msg, end='\r')
        else:
            Logger.success(msg)
