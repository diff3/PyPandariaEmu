#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from colorama import init, Fore, Style
from datetime import datetime
from enum import Enum, IntEnum

from protocol.opcodes.AuthPackets import *
from utils.ConfigLoader import ConfigLoader

config = ConfigLoader.load_config()
   
class DebugColorLevel(Enum):
    SUCCESS = Fore.GREEN + Style.BRIGHT
    INFO = Fore.BLUE + Style.BRIGHT
    ANTICHEAT = Fore.LIGHTBLUE_EX + Style.BRIGHT
    WARNING = Fore.YELLOW + Style.BRIGHT
    ERROR = Fore.RED + Style.BRIGHT
    DEBUG = Fore.CYAN + Style.BRIGHT
    SCRIPT = Fore.MAGENTA + Style.BRIGHT
    PACKAGE = Fore.WHITE + Style.BRIGHT 


class DebugLevel(IntEnum):
    NONE = 0x00
    SUCCESS = 0x01
    INFO = 0x02
    ANTICHEAT = 0x04
    WARNING = 0x08
    ERROR = 0x10
    DEBUG = 0x20
    SCRIPT = 0x40
    PACKAGE = 0x80
    ALL = 0xff


class Logger:
    init()

    @staticmethod
    def _get_logging_mask():
        levels = config['Logging'].get('logging_levels', 'All').split(', ')
        level_map = {
            'None': DebugLevel.NONE,
            'Success': DebugLevel.SUCCESS,
            'Information': DebugLevel.INFO,
            'Anticheat': DebugLevel.ANTICHEAT,
            'Warning': DebugLevel.WARNING,
            'Error': DebugLevel.ERROR,
            'Debug': DebugLevel.DEBUG,
            'Script': DebugLevel.SCRIPT,
            'Package': DebugLevel.PACKAGE, 
            'All': DebugLevel.ALL
        }
        mask = DebugLevel.NONE
        
        for level in levels:
            if level in level_map:
                mask |= level_map[level]
        
        return mask

    @staticmethod
    def _should_log(log_type: DebugLevel):
        logging_mask = Logger._get_logging_mask()
        return logging_mask & log_type

    @staticmethod
    def _colorize_message(label, color, msg):
        date_format = config['Logging']['date_format']
        date = datetime.now().strftime(date_format)
        return f'{color.value}{label}{Style.RESET_ALL} {date} {msg}'

    @staticmethod
    def add_to_log(msg, debugLevel):
        file = config['Logging']['log_file']
        date_format = config['Logging']['date_format']
        date = datetime.now().strftime(date_format)
        formatted_msg = f'[{debugLevel}] {date} {msg}'

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
            print(Logger._colorize_message('[INFO]', DebugColorLevel.INFO, msg), end=end)
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
    def package(data_str):
        """
        Logs the details of a data structure if Package logging is enabled.
        Args:
            data_str (str): String representation of the data to be logged.
        """
        if not Logger._should_log(DebugLevel.PACKAGE):
            return  

        try:
            data = eval(data_str)  
            class_name = data.__class__.__name__
            formatted_message = f'\n{class_name}(\n'
            
            for key, value in data.__dict__.items():
                if isinstance(value, bytes):
                    value_str = value[::-1].hex().upper()
                else:
                    value_str = repr(value)
                formatted_message += f'   {key}={value_str},\n'
            
            formatted_message = formatted_message.rstrip(',\n') + '\n)'
            print(Logger._colorize_message('[PACKAGE]', DebugColorLevel.DEBUG, formatted_message))
            Logger.add_to_log(formatted_message, 'PACKAGE')
        except Exception as e:
            Logger.error(f"Error logging package: {e}")


    @staticmethod
    def progress(msg, current, total, divisions=20):
        msg = f'{msg} [{current}/{total}] ({int(current * 100 / total)}%)'
        if current != total and divisions > 0:
            if int(current % (total / divisions)) == 0:
                Logger.info(msg, end='\r')
        else:
            Logger.success(msg)
