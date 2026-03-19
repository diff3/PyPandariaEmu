#!/usr/bin/env python3
import sys
from shared.Logger import Logger
from server.modules.crypto.SRP6Crypto import SRP6Crypto
from server.modules.database.DatabaseConnection import DatabaseConnection


def main():
    if len(sys.argv) != 4:
        print("Usage: create_user <username> <password> <gmlevel>")
        return

    username = sys.argv[1]
    password = sys.argv[2]
    gmlevel = int(sys.argv[3])

    crypto = SRP6Crypto()
    salt, verifier = crypto.make_registration(username, password)

    DatabaseConnection.initialize()

    acc_id = DatabaseConnection.create_or_update_account(username.upper(), salt, verifier)
    DatabaseConnection.set_gmlevel(acc_id, gmlevel)

    Logger.success(f"User '{username}' created/updated (id={acc_id}).")
    Logger.success(f"GM level {gmlevel}")
    Logger.success(f"Salt: {salt.hex()}")
    Logger.success(f"Verifier: {verifier.hex()}")

if __name__ == "__main__":
    main()
