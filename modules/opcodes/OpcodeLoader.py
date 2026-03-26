# utils/OpcodeLoader.py

from server.modules.opcodes.AuthOpcodes import (
    AUTH_CLIENT_OPCODES,
    AUTH_SERVER_OPCODES,
    lookup as auth_lookup,
)
from server.modules.opcodes.WorldOpcodes import (
    WORLD_CLIENT_OPCODES,
    WORLD_SERVER_OPCODES,
    lookup as world_lookup,
)

def load_opcode_module():
    return None


def load_auth_opcodes():
    return (
        AUTH_CLIENT_OPCODES,
        AUTH_SERVER_OPCODES,
        auth_lookup,
    )

def load_world_opcodes():
    return (
        WORLD_CLIENT_OPCODES,
        WORLD_SERVER_OPCODES,
        world_lookup,
    )
