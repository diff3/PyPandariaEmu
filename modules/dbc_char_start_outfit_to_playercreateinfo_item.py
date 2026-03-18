#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import importlib
from pathlib import Path

from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger
from server.modules.dbc import read_dbc


DBC_FMT_CHAR_START_OUTFIT = (
    "dbbbX"
    "iiiiiiiiiiiiiiiiiiiiiiii"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
)


def _build_outfit_map(
    records: list[list[int]],
    gender_filter: int | None,
    merge_genders: bool,
) -> dict[tuple[int, int], set[int]]:
    outfits: dict[tuple[int, int], set[int]] = {}

    for row in records:
        if len(row) < 28:
            continue
        race = int(row[1])
        class_ = int(row[2])
        gender = int(row[3])

        if gender_filter is not None and gender != gender_filter:
            continue

        items = [int(item_id) for item_id in row[4:4 + 24] if int(item_id) > 0]
        if not items:
            continue

        key = (race, class_)
        if key not in outfits:
            outfits[key] = set()
        if merge_genders or gender_filter is not None:
            outfits[key].update(items)
        else:
            if gender != 0:
                continue
            outfits[key].update(items)

    return outfits


def _resolve_dbc_path(dbc_path: str | None, game_root: str | None) -> Path:
    if dbc_path:
        return Path(dbc_path)
    if game_root:
        candidate = Path(game_root) / "Data" / "DBFilesClient" / "CharStartOutfit.dbc"
        return candidate
    return Path()


def _get_db_module():
    mod = importlib.import_module("server.modules.database.DatabaseConnection")
    mod.DatabaseConnection.initialize()
    return mod


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import CharStartOutfit.dbc into playercreateinfo_item.",
    )
    parser.add_argument("--dbc", help="Path to CharStartOutfit.dbc")
    parser.add_argument("--game-root", help="WoW root path (expects Data/DBFilesClient/CharStartOutfit.dbc)")
    parser.add_argument("--gender", type=int, choices=[0, 1], help="Filter by gender (0=male, 1=female)")
    parser.add_argument("--merge-genders", action="store_true", help="Merge both genders into one set")
    parser.add_argument("--insert", action="store_true", help="Insert into playercreateinfo_item (world DB)")
    parser.add_argument("--truncate", action="store_true", help="Clear playercreateinfo_item before insert")
    parser.add_argument("--print-sql", action="store_true", help="Print SQL INSERT statements")
    args = parser.parse_args()

    dbc_path = _resolve_dbc_path(args.dbc, args.game_root)
    if not dbc_path or not dbc_path.is_file():
        Logger.error(
            "CharStartOutfit.dbc not found. Extract it from MPQs and pass --dbc, "
            "or pass --game-root if already extracted to Data/DBFilesClient."
        )
        return 1

    records = read_dbc(dbc_path, DBC_FMT_CHAR_START_OUTFIT)
    outfits = _build_outfit_map(records, args.gender, args.merge_genders)

    if not outfits:
        Logger.warning("No outfit items found in DBC.")
        return 0

    rows = []
    for (race, class_), items in sorted(outfits.items()):
        for item_id in sorted(items):
            rows.append((race, class_, item_id, 1))

    if args.print_sql:
        for race, class_, item_id, amount in rows:
            print(
                "INSERT INTO playercreateinfo_item (race, class, itemid, amount) "
                f"VALUES ({race}, {class_}, {item_id}, {amount});"
            )

    if args.insert:
        mod = _get_db_module()
        session = mod.DatabaseConnection.world()
        if args.truncate:
            try:
                session.query(mod.PlayerCreateInfoItem).delete(synchronize_session=False)
            except Exception as exc:
                Logger.warning(f"[DB] Failed to truncate playercreateinfo_item: {exc}")
        try:
            session.add_all(
                [
                    mod.PlayerCreateInfoItem(race=r, class_=c, itemid=i, amount=a)
                    for r, c, i, a in rows
                ]
            )
            session.commit()
            Logger.success(f"Inserted {len(rows)} rows into playercreateinfo_item.")
        except Exception as exc:
            session.rollback()
            Logger.error(f"[DB] Insert failed: {exc}")
            return 1

    Logger.success(f"Processed {len(rows)} playercreateinfo_item rows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
