# utils/OpcodeLoader.py

import importlib
from utils.ConfigLoader import ConfigLoader

def load_opcode_module():
    """
    Loads the opcode module dynamically based on config
    protocols/<program>/<expansion>/<version>/opcodes/AuthOpcodes.py
    """
    config = ConfigLoader.load_config()
    program = config["program"]
    expansion = config.get("expansion")
    version = config["version"]

    module_path = f"protocols.{program}.{expansion}.{version}.modules.opcodes.AuthOpcodes"
    return importlib.import_module(module_path)


def load_auth_opcodes():
    """
    Returns (AUTH_CLIENT_OPCODES, AUTH_SERVER_OPCODES, lookup)
    from dynamically loaded opcode module.
    """
    mod = load_opcode_module()

    return (
        getattr(mod, "AUTH_CLIENT_OPCODES", {}),
        getattr(mod, "AUTH_SERVER_OPCODES", {}),
        getattr(mod, "lookup", None)
    )

def load_world_opcodes():
    config = ConfigLoader.load_config()
    program = config["program"]
    expansion = config.get("expansion")
    version = config["version"]

    module_path = f"protocols.{program}.{expansion}.{version}.modules.opcodes.WorldOpcodes"
    mod = importlib.import_module(module_path)

    return (
        getattr(mod, "WORLD_CLIENT_OPCODES", {}),
        getattr(mod, "WORLD_SERVER_OPCODES", {}),
        getattr(mod, "lookup", None)
    )
