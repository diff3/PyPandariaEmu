#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from sqlalchemy import text

from shared.Logger import Logger
from server.modules.database.DatabaseConnection import DatabaseConnection


_FARM_PLOT_TABLE_READY = False
_STARTER_CLAIM_TABLE_READY = False


def ensure_farm_plot_table() -> bool:
    global _FARM_PLOT_TABLE_READY
    if _FARM_PLOT_TABLE_READY:
        return True

    session = DatabaseConnection.chars()
    try:
        session.execute(text(
            """
            CREATE TABLE IF NOT EXISTS farm_plot (
                guid INT UNSIGNED NOT NULL,
                plot_guid INT UNSIGNED NOT NULL,
                seed_item INT UNSIGNED NOT NULL DEFAULT 0,
                planted_at INT UNSIGNED NOT NULL DEFAULT 0,
                PRIMARY KEY (guid, plot_guid)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3
            """
        ))
        session.commit()
        _FARM_PLOT_TABLE_READY = True
        return True
    except Exception as exc:
        session.rollback()
        Logger.warning("[HalfhillFarm] ensure farm_plot table failed: %s", exc)
        return False


def ensure_farm_starter_seed_claim_table() -> bool:
    global _STARTER_CLAIM_TABLE_READY
    if _STARTER_CLAIM_TABLE_READY:
        return True

    session = DatabaseConnection.chars()
    try:
        session.execute(text(
            """
            CREATE TABLE IF NOT EXISTS farm_starter_seed_claim (
                guid INT UNSIGNED NOT NULL,
                claimed_at INT UNSIGNED NOT NULL DEFAULT 0,
                PRIMARY KEY (guid)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3
            """
        ))
        session.commit()
        _STARTER_CLAIM_TABLE_READY = True
        return True
    except Exception as exc:
        session.rollback()
        Logger.warning("[HalfhillFarm] ensure farm_starter_seed_claim table failed: %s", exc)
        return False


def load_player_plots(char_guid: int) -> dict[int, dict]:
    if int(char_guid or 0) <= 0:
        return {}
    if not ensure_farm_plot_table():
        return {}

    session = DatabaseConnection.chars()
    try:
        rows = session.execute(
            text(
                """
                SELECT guid, plot_guid, seed_item, planted_at
                FROM farm_plot
                WHERE guid = :guid
                """
            ),
            {"guid": int(char_guid)},
        ).mappings().all()
    except Exception as exc:
        Logger.warning("[HalfhillFarm] load_player_plots failed guid=%s err=%s", int(char_guid), exc)
        return {}

    return {
        int(row["plot_guid"]): {
            "guid": int(row["guid"] or 0),
            "plot_guid": int(row["plot_guid"] or 0),
            "seed_item": int(row["seed_item"] or 0),
            "planted_at": int(row["planted_at"] or 0),
        }
        for row in rows
    }


def save_plot(char_guid: int, plot_guid: int, *, seed_item: int, planted_at: int) -> bool:
    if int(char_guid or 0) <= 0 or int(plot_guid or 0) <= 0:
        return False
    if not ensure_farm_plot_table():
        return False

    session = DatabaseConnection.chars()
    try:
        session.execute(
            text(
                """
                REPLACE INTO farm_plot (guid, plot_guid, seed_item, planted_at)
                VALUES (:guid, :plot_guid, :seed_item, :planted_at)
                """
            ),
            {
                "guid": int(char_guid),
                "plot_guid": int(plot_guid),
                "seed_item": int(seed_item or 0),
                "planted_at": int(planted_at or 0),
            },
        )
        session.commit()
        return True
    except Exception as exc:
        session.rollback()
        Logger.warning(
            "[HalfhillFarm] save_plot failed guid=%s plot=%s err=%s",
            int(char_guid),
            int(plot_guid),
            exc,
        )
        return False


def clear_plot(char_guid: int, plot_guid: int) -> bool:
    if int(char_guid or 0) <= 0 or int(plot_guid or 0) <= 0:
        return False
    if not ensure_farm_plot_table():
        return False

    session = DatabaseConnection.chars()
    try:
        session.execute(
            text(
                """
                DELETE FROM farm_plot
                WHERE guid = :guid AND plot_guid = :plot_guid
                """
            ),
            {"guid": int(char_guid), "plot_guid": int(plot_guid)},
        )
        session.commit()
        return True
    except Exception as exc:
        session.rollback()
        Logger.warning(
            "[HalfhillFarm] clear_plot failed guid=%s plot=%s err=%s",
            int(char_guid),
            int(plot_guid),
            exc,
        )
        return False


def has_claimed_starter_seeds(char_guid: int) -> bool:
    if int(char_guid or 0) <= 0:
        return False
    if not ensure_farm_starter_seed_claim_table():
        return False

    session = DatabaseConnection.chars()
    try:
        row = session.execute(
            text(
                """
                SELECT guid
                FROM farm_starter_seed_claim
                WHERE guid = :guid
                LIMIT 1
                """
            ),
            {"guid": int(char_guid)},
        ).first()
        return row is not None
    except Exception as exc:
        Logger.warning("[HalfhillFarm] has_claimed_starter_seeds failed guid=%s err=%s", int(char_guid), exc)
        return False


def mark_starter_seed_claimed(char_guid: int, claimed_at: int) -> bool:
    if int(char_guid or 0) <= 0:
        return False
    if not ensure_farm_starter_seed_claim_table():
        return False

    session = DatabaseConnection.chars()
    try:
        session.execute(
            text(
                """
                REPLACE INTO farm_starter_seed_claim (guid, claimed_at)
                VALUES (:guid, :claimed_at)
                """
            ),
            {"guid": int(char_guid), "claimed_at": int(claimed_at or 0)},
        )
        session.commit()
        return True
    except Exception as exc:
        session.rollback()
        Logger.warning("[HalfhillFarm] mark_starter_seed_claimed failed guid=%s err=%s", int(char_guid), exc)
        return False
