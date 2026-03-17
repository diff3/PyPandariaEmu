#!/usr/bin/env python3
import sys
from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader
from protocols.wow.shared.modules.crypto.SRP6Crypto import SRP6Crypto
import importlib

def get_db():
    cfg = ConfigLoader.load_config()
    program = cfg["program"]
    version = cfg["version"]

    mod = importlib.import_module(
        f"protocols.{program}.{cfg.get('expansion')}.{version}.modules.database.DatabaseConnection"
    )
    DB = getattr(mod, "DatabaseConnection")
    DB.initialize()
    return DB


def main():
    if len(sys.argv) != 4:
        print("Usage: create_user <username> <password> <gmlevel>")
        return

    username = sys.argv[1]
    password = sys.argv[2]
    gmlevel = int(sys.argv[3])

    crypto = SRP6Crypto()
    salt, verifier = crypto.make_registration(username, password)

    DB = get_db()

    acc_id = DB.create_or_update_account(username.upper(), salt, verifier)
    DB.set_gmlevel(acc_id, gmlevel)

    Logger.success(f"User '{username}' created/updated (id={acc_id}).")
    Logger.success(f"GM level {gmlevel}")
    Logger.success(f"Salt: {salt.hex()}")
    Logger.success(f"Verifier: {verifier.hex()}")

if __name__ == "__main__":
    main()
