#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import yaml


class ConfigLoader:
    """Central configuration handler."""

    _config = None  # Cache for loaded configuration

    @staticmethod
    def get(key, default=None):
        """
        Retrieves a value from the loaded configuration.
        Args:
            key (str): The key to retrieve.
            default: Default value if the key is not found.
        Returns:
            The value for the specified key or the default.
        """
        if ConfigLoader._config is None:
            raise RuntimeError("Configuration has not been loaded.")
        return ConfigLoader._config.get(key, default)

    @staticmethod
    def load_config(filepath="etc/config.yaml"):
        """
        Loads the configuration file if not already cached.
        Args:
            filepath (str): Path to the YAML configuration file.
        Returns:
            dict: Loaded configuration.
        """
        if ConfigLoader._config is None:
            try:
                with open(filepath, 'r') as file:
                    ConfigLoader._config = yaml.safe_load(file)
            except FileNotFoundError:
                raise RuntimeError(f"Configuration file not found at {filepath}.")
            except yaml.YAMLError as e:
                raise RuntimeError(f"Error parsing YAML file: {e}")
        return ConfigLoader._config
