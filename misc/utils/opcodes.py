WOW_SUCCESS = 0x00

AUTH_LOGON_CHALLENGE = 0x00
AUTH_LOGON_PROOF = 0x01
AUTH_RECONNECT_CHALLENGE = 0x02
AUTH_RECONNECT_PROOF = 0x03
REALM_LIST = 0x10
XFER_INITIATE = 0x30
XFER_DATA = 0x31
XFER_ACCEPT = 0x32
XFER_RESUME = 0x33
XFER_CANCEL = 0x34


class opcodes:
    
    @staticmethod
    def getCode(opcode):

        if opcode == AUTH_LOGON_CHALLENGE:
            return "AUTH_LOGON_CHALLENGE"
        elif opcode == AUTH_LOGON_PROOF:
            return "AUTH_LOGON_PROOF"
        elif opcode == AUTH_RECONNECT_CHALLENGE:
            return "AUTH_RECONNECT_CHALLENGE"
        elif opcode == AUTH_RECONNECT_PROOF:
            return "AUTH_RECONNECT_PROOF"
        elif opcode == REALM_LIST:
            return "REALM_LIST"
        elif opcode == XFER_INITIATE:
            return "XFER_INITIATE"
        elif opcode == XFER_DATA:
            return "XFER_DATA"
        elif opcode == XFER_ACCEPT:
            return "XFER_ACCEPT"
        elif opcode == XFER_RESUME:
            return "XFER_RESUME"
        elif opcode == XFER_CANCEL:
            return "XFER_CANCEL"
        else:
            return f"Unknown Opcode: {opcode}"
