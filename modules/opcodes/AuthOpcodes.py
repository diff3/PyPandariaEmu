# packets/AuthOpcodes.py

# Client → Server
AUTH_CLIENT_OPCODES = {
    0x00: "AUTH_LOGON_CHALLENGE_C",
    0x01: "AUTH_LOGON_PROOF_C",
    0x02: "AUTH_RECONNECT_CHALLENGE_C",
    0x03: "AUTH_RECONNECT_PROOF_C",
    0x10: "REALM_LIST_C",
}

# Server → Client
AUTH_SERVER_OPCODES = {
    0x00: "AUTH_LOGON_CHALLENGE_S",
    0x01: "AUTH_LOGON_PROOF_S",
    0x02: "AUTH_RECONNECT_CHALLENGE_S",
    0x03: "AUTH_RECONNECT_PROOF_S",
    0x10: "REALM_LIST_S",
}

def lookup(direction: str, opcode: int) -> str | None:
    """
    direction = "C2S" eller "S2C"
    Returnerar namnet på .def-filen eller None.
    """
    if direction == "C2S":
        return AUTH_CLIENT_OPCODES.get(opcode)
    elif direction == "S2C":
        return AUTH_SERVER_OPCODES.get(opcode)
    return None