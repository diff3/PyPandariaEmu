#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from hashlib import md5

from sqlalchemy import create_engine, or_, text
from sqlalchemy.orm import scoped_session, sessionmaker

from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger

from server.modules.database.AuthModel import Account, AccountAccess, RealmList
from server.modules.database.CharactersModel import (
    Characters,
    CharacterAction,
    CharacterSpell,
)
from server.modules.database.WorldModel import (
    ItemTemplate,
    PlayerFactionchangeAchievement,
    PlayerFactionchangeItems,
    PlayerFactionchangeQuests,
    PlayerFactionchangeReputations,
    PlayerFactionchangeSpells,
    PlayerFactionchangeTitles,
    PlayerLevelStats,
    PlayerXpForLevel,
    PlayerCreateInfo,
    PlayerCreateInfoAction,
    PlayerCreateInfoItem,
    PlayerCreateInfoSpell,
    PlayerCreateInfoSpellCast,
    PlayerCreateInfoSpellCustom,
)


class DatabaseConnection:
    """Handles separate DB connections for auth-db, characters-db, and world-db."""

    _auth_engine = None
    _auth_session = None

    _char_engine = None
    _char_session = None

    _world_engine = None
    _world_session = None
    _characters_db_name = None
    _world_db_name = None
    _world_cache_loaded = False
    _cache_playercreateinfo = {}
    _cache_playercreateinfo_items = {}
    _cache_playercreateinfo_actions = {}
    _cache_playercreateinfo_spell_rows = []
    _cache_playercreateinfo_spells_by_pair = {}
    _cache_levelstats = {}
    _cache_levelstats_by_pair = {}
    _cache_xp_for_level = {}
    _item_template_cache = {}
    _account_data_tables_ready = False
    _addon_tables_ready = False

    @staticmethod
    def initialize():
        """Initialize BOTH auth and characters DB connections."""
        config = ConfigLoader.load_config()
        db = config["database"]

        # AUTH DATABASE
        auth_url = (
            f"mysql+pymysql://{db['username']}:{db['password']}@"
            f"{db['host']}:{db['port']}/{db['auth_db']}?charset=utf8"
        )
        DatabaseConnection._auth_engine = create_engine(auth_url, pool_pre_ping=True)
        DatabaseConnection._auth_session = scoped_session(
            sessionmaker(bind=DatabaseConnection._auth_engine, autoflush=False)
        )

        # CHARACTERS DATABASE
        char_url = (
            f"mysql+pymysql://{db['username']}:{db['password']}@"
            f"{db['host']}:{db['port']}/{db['characters_db']}?charset=utf8"
        )
        DatabaseConnection._char_engine = create_engine(char_url, pool_pre_ping=True)
        DatabaseConnection._char_session = scoped_session(
            sessionmaker(bind=DatabaseConnection._char_engine, autoflush=False)
        )
        DatabaseConnection._characters_db_name = db.get("characters_db")

        # WORLD DATABASE (optional)
        world_db = db.get("world_db")
        if world_db:
            world_url = (
                f"mysql+pymysql://{db['username']}:{db['password']}@"
                f"{db['host']}:{db['port']}/{world_db}?charset=utf8"
            )
            DatabaseConnection._world_engine = create_engine(world_url, pool_pre_ping=True)
            DatabaseConnection._world_session = scoped_session(
                sessionmaker(bind=DatabaseConnection._world_engine, autoflush=False)
            )
            DatabaseConnection._world_db_name = world_db
            Logger.info("Database initialized (auth + characters + world)")
        else:
            Logger.info("Database initialized (auth + characters)")

    # WORLD CACHE
    @staticmethod
    def preload_world_cache() -> None:
        if DatabaseConnection._world_cache_loaded:
            return
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return

        try:
            rows = session.query(PlayerCreateInfo).all()
            DatabaseConnection._cache_playercreateinfo = {
                (int(row.race), int(row.class_)): row for row in rows
            }
        except Exception as exc:
            Logger.warning(f"[DB] playercreateinfo preload failed: {exc}")
            DatabaseConnection._cache_playercreateinfo = {}

        item_entries = set()
        try:
            rows = session.query(
                PlayerCreateInfoItem.race,
                PlayerCreateInfoItem.class_,
                PlayerCreateInfoItem.itemid,
            ).all()
            items: dict[tuple[int, int], list[int]] = {}
            for race, class_, itemid in rows:
                key = (int(race), int(class_))
                items.setdefault(key, []).append(int(itemid))
                item_entries.add(int(itemid))
            DatabaseConnection._cache_playercreateinfo_items = items
        except Exception as exc:
            Logger.warning(f"[DB] playercreateinfo_item preload failed: {exc}")
            DatabaseConnection._cache_playercreateinfo_items = {}

        try:
            rows = session.query(
                PlayerCreateInfoAction.race,
                PlayerCreateInfoAction.class_,
                PlayerCreateInfoAction.button,
                PlayerCreateInfoAction.action,
                PlayerCreateInfoAction.type,
            ).all()
            actions: dict[tuple[int, int], list[tuple[int, int, int]]] = {}
            for race, class_, button, action, type_ in rows:
                key = (int(race), int(class_))
                actions.setdefault(key, []).append((int(button), int(action), int(type_)))
            DatabaseConnection._cache_playercreateinfo_actions = actions
        except Exception as exc:
            Logger.warning(f"[DB] playercreateinfo_action preload failed: {exc}")
            DatabaseConnection._cache_playercreateinfo_actions = {}

        spell_rows = []
        for model in (PlayerCreateInfoSpell, PlayerCreateInfoSpellCustom, PlayerCreateInfoSpellCast):
            try:
                rows = session.query(model.racemask, model.classmask, model.spell).all()
                for racemask, classmask, spell in rows:
                    spell_rows.append((int(racemask), int(classmask), int(spell)))
            except Exception as exc:
                Logger.warning(f"[DB] {model.__tablename__} preload failed: {exc}")
        DatabaseConnection._cache_playercreateinfo_spell_rows = spell_rows
        DatabaseConnection._cache_playercreateinfo_spells_by_pair = {}

        try:
            rows = session.query(PlayerLevelStats).all()
            levelstats = {}
            levelstats_by_pair = {}
            for row in rows:
                key = (int(row.race), int(row.class_), int(row.level))
                levelstats[key] = row
                pair_key = (int(row.race), int(row.class_))
                levelstats_by_pair.setdefault(pair_key, []).append(row)
            for pair_key, entries in levelstats_by_pair.items():
                entries.sort(key=lambda r: int(r.level))
            DatabaseConnection._cache_levelstats = levelstats
            DatabaseConnection._cache_levelstats_by_pair = levelstats_by_pair
        except Exception as exc:
            Logger.warning(f"[DB] player_levelstats preload failed: {exc}")
            DatabaseConnection._cache_levelstats = {}
            DatabaseConnection._cache_levelstats_by_pair = {}

        try:
            rows = session.query(PlayerXpForLevel.lvl, PlayerXpForLevel.xp_for_next_level).all()
            DatabaseConnection._cache_xp_for_level = {int(lvl): int(xp) for lvl, xp in rows}
        except Exception as exc:
            Logger.warning(f"[DB] player_xp_for_level preload failed: {exc}")
            DatabaseConnection._cache_xp_for_level = {}

        if item_entries:
            DatabaseConnection.get_item_template_map(list(item_entries))

        DatabaseConnection._world_cache_loaded = True
        Logger.info("Database cache preloaded")

    @staticmethod
    def reload_world_cache() -> None:
        DatabaseConnection._world_cache_loaded = False
        DatabaseConnection._cache_playercreateinfo = {}
        DatabaseConnection._cache_playercreateinfo_items = {}
        DatabaseConnection._cache_playercreateinfo_actions = {}
        DatabaseConnection._cache_playercreateinfo_spell_rows = []
        DatabaseConnection._cache_playercreateinfo_spells_by_pair = {}
        DatabaseConnection._cache_levelstats = {}
        DatabaseConnection._cache_levelstats_by_pair = {}
        DatabaseConnection._cache_xp_for_level = {}
        DatabaseConnection._item_template_cache = {}
        DatabaseConnection.preload_world_cache()

    # AUTH DB SESSION
    @staticmethod
    def auth():
        if DatabaseConnection._auth_session is None:
            raise RuntimeError("DatabaseConnection.initialize() not called.")
        return DatabaseConnection._auth_session

    # CHARACTERS DB SESSION
    @staticmethod
    def chars():
        if DatabaseConnection._char_session is None:
            raise RuntimeError("DatabaseConnection.initialize() not called.")
        return DatabaseConnection._char_session

    # WORLD DB SESSION
    @staticmethod
    def world():
        if DatabaseConnection._world_session is None:
            raise RuntimeError("World database not configured.")
        return DatabaseConnection._world_session

    # AUTH QUERIES
    @staticmethod
    def get_user_by_username(username):
        return DatabaseConnection.auth().query(Account).filter(
            Account.username == username
        ).first()

    @staticmethod
    def get_account_id_by_username(username: str):
        row = (
            DatabaseConnection.auth()
            .query(Account.id)
            .filter(Account.username == username)
            .first()
        )
        return row[0] if row else None

    @staticmethod
    def get_realmlist():
        return DatabaseConnection.auth().query(RealmList).first()

    @staticmethod
    def get_all_realms():
        return DatabaseConnection.auth().query(RealmList).all()

    # CHARACTER QUERIES
    @staticmethod
    def get_characters_for_account(account_id, realm_id):
        session = DatabaseConnection.chars()
        base = session.query(Characters).filter(
            Characters.account == account_id,
            Characters.realm == realm_id,
        ).order_by(Characters.slot.asc(), Characters.guid.asc())
        try:
            return base.filter(
                or_(Characters.deleteDate == 0, Characters.deleteDate.is_(None)),
                or_(Characters.deleteInfos_Account == 0, Characters.deleteInfos_Account.is_(None)),
            ).all()
        except Exception as exc:
            Logger.warning(f"[DB] delete columns missing, fallback to base query: {exc}")
            return base.all()

    @staticmethod
    def count_characters_for_account(account_id, realm_id):
        session = DatabaseConnection.chars()
        base = session.query(Characters).filter(
            Characters.account == account_id,
            Characters.realm == realm_id,
        )
        try:
            return base.filter(
                or_(Characters.deleteDate == 0, Characters.deleteDate.is_(None)),
                or_(Characters.deleteInfos_Account == 0, Characters.deleteInfos_Account.is_(None)),
            ).count()
        except Exception as exc:
            Logger.warning(f"[DB] delete columns missing, fallback to base count: {exc}")
            return base.count()

    # CHARACTER QUERIES
    @staticmethod
    def get_character(char_guid: int, realm_id: int):
        """
        Fetch a single character by LOW guid and realm.
        """
        session = DatabaseConnection.chars()
        try:
            return (
                session.query(Characters)
                .filter(
                    Characters.guid == int(char_guid),
                    Characters.realm == int(realm_id),
                )
                .one_or_none()
            )
        except Exception as exc:
            Logger.error(
                f"[DB] Failed to fetch character guid={char_guid} realm={realm_id}: {exc}"
            )
            raise

    @staticmethod
    def _ensure_account_data_tables() -> None:
        if DatabaseConnection._account_data_tables_ready:
            return

        session = DatabaseConnection.chars()
        try:
            session.execute(text(
                """
                CREATE TABLE IF NOT EXISTS account_data (
                    accountId INT UNSIGNED NOT NULL DEFAULT 0,
                    type TINYINT UNSIGNED NOT NULL DEFAULT 0,
                    time INT UNSIGNED NOT NULL DEFAULT 0,
                    data LONGBLOB NOT NULL,
                    PRIMARY KEY (accountId, type)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3
                """
            ))
            session.execute(text(
                """
                CREATE TABLE IF NOT EXISTS character_account_data (
                    guid INT UNSIGNED NOT NULL DEFAULT 0,
                    type TINYINT UNSIGNED NOT NULL DEFAULT 0,
                    time INT UNSIGNED NOT NULL DEFAULT 0,
                    data LONGBLOB NOT NULL,
                    PRIMARY KEY (guid, type)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3
                """
            ))
            session.commit()
            DatabaseConnection._account_data_tables_ready = True
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] ensure account-data tables failed: {exc}")

    @staticmethod
    def _ensure_addon_tables() -> None:
        if DatabaseConnection._addon_tables_ready:
            return

        session = DatabaseConnection.chars()
        try:
            session.execute(text(
                """
                CREATE TABLE IF NOT EXISTS addons (
                    name VARCHAR(255) NOT NULL,
                    crc INT UNSIGNED NOT NULL DEFAULT 0,
                    PRIMARY KEY (name)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3
                """
            ))
            session.execute(text(
                """
                CREATE TABLE IF NOT EXISTS banned_addons (
                    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
                    name VARCHAR(255) NOT NULL DEFAULT '',
                    version VARCHAR(255) NOT NULL DEFAULT '',
                    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3
                """
            ))
            session.commit()
            DatabaseConnection._addon_tables_ready = True
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] ensure addon tables failed: {exc}")

    @staticmethod
    def load_known_addons() -> dict[str, int]:
        DatabaseConnection._ensure_addon_tables()
        session = DatabaseConnection.chars()
        try:
            rows = session.execute(text("SELECT name, crc FROM addons")).fetchall()
        except Exception as exc:
            Logger.warning(f"[DB] load_known_addons failed: {exc}")
            return {}

        result: dict[str, int] = {}
        for row in rows:
            try:
                result[str(row[0])] = int(row[1] or 0)
            except Exception:
                continue
        return result

    @staticmethod
    def save_known_addon(name: str, crc: int) -> bool:
        DatabaseConnection._ensure_addon_tables()
        session = DatabaseConnection.chars()
        try:
            session.execute(
                text("REPLACE INTO addons (name, crc) VALUES (:name, :crc)"),
                {"name": str(name or ""), "crc": int(crc or 0)},
            )
            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] save_known_addon failed name={name}: {exc}")
            return False

    @staticmethod
    def load_banned_addons() -> list[dict]:
        DatabaseConnection._ensure_addon_tables()
        session = DatabaseConnection.chars()
        try:
            rows = session.execute(
                text(
                    """
                    SELECT id, name, version, UNIX_TIMESTAMP(timestamp) AS ts
                    FROM banned_addons
                    ORDER BY id ASC
                    """
                )
            ).fetchall()
        except Exception as exc:
            Logger.warning(f"[DB] load_banned_addons failed: {exc}")
            return []

        result: list[dict] = []
        for row in rows:
            try:
                name = str(row[1] or "")
                version = str(row[2] or "")
                result.append({
                    "id": int(row[0] or 0),
                    "name": name,
                    "version": version,
                    "timestamp": int(row[3] or 0),
                    "name_md5": md5(name.encode("utf-8", errors="replace")).digest(),
                    "version_md5": md5(version.encode("utf-8", errors="replace")).digest(),
                })
            except Exception:
                continue
        return result

    @staticmethod
    def load_account_data(owner_id: int, *, per_character: bool) -> dict[int, tuple[int, str]]:
        DatabaseConnection._ensure_account_data_tables()
        session = DatabaseConnection.chars()
        table = "character_account_data" if per_character else "account_data"
        id_column = "guid" if per_character else "accountId"
        try:
            rows = session.execute(
                text(f"SELECT type, time, data FROM {table} WHERE {id_column} = :owner_id"),
                {"owner_id": int(owner_id or 0)},
            ).fetchall()
        except Exception as exc:
            Logger.warning(
                f"[DB] load_account_data failed table={table} owner_id={owner_id}: {exc}"
            )
            return {}

        result: dict[int, tuple[int, str]] = {}
        for row in rows:
            data_blob = row[2]
            if isinstance(data_blob, memoryview):
                data_blob = data_blob.tobytes()
            if isinstance(data_blob, (bytes, bytearray)):
                data_text = bytes(data_blob).decode("utf-8", errors="replace")
            else:
                data_text = str(data_blob or "")
            result[int(row[0])] = (int(row[1] or 0), data_text)
        return result

    @staticmethod
    def save_account_data(
        owner_id: int,
        data_type: int,
        timestamp: int,
        data: str,
        *,
        per_character: bool,
    ) -> bool:
        DatabaseConnection._ensure_account_data_tables()
        session = DatabaseConnection.chars()
        table = "character_account_data" if per_character else "account_data"
        id_column = "guid" if per_character else "accountId"
        try:
            session.execute(
                text(
                    f"""
                    REPLACE INTO {table} ({id_column}, type, time, data)
                    VALUES (:owner_id, :data_type, :timestamp, :data)
                    """
                ),
                {
                    "owner_id": int(owner_id or 0),
                    "data_type": int(data_type or 0),
                    "timestamp": int(timestamp or 0),
                    "data": (data or "").encode("utf-8", errors="strict"),
                },
            )
            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            Logger.warning(
                f"[DB] save_account_data failed table={table} owner_id={owner_id} "
                f"type={data_type}: {exc}"
            )
            return False

    @staticmethod
    def save_character_position(
        char_guid: int,
        realm_id: int,
        *,
        map_id: int,
        zone: int,
        instance_id: int,
        x: float,
        y: float,
        z: float,
        orientation: float,
        online: int | None = None,
        logout_time: int | None = None,
    ) -> bool:
        """Persist character world position and optional online/logout state."""
        session = DatabaseConnection.chars()
        try:
            values = {
                Characters.map: int(map_id or 0),
                Characters.zone: int(zone or 0),
                Characters.instance_id: int(instance_id or 0),
                Characters.position_x: float(x or 0.0),
                Characters.position_y: float(y or 0.0),
                Characters.position_z: float(z or 0.0),
                Characters.orientation: float(orientation or 0.0),
            }

            if online is not None:
                values[Characters.online] = int(online)
            if logout_time is not None:
                values[Characters.logout_time] = int(logout_time)

            updated = (
                session.query(Characters)
                .filter(
                    Characters.guid == int(char_guid),
                    Characters.realm == int(realm_id),
                )
                .update(values, synchronize_session=False)
            )

            if not updated:
                session.rollback()
                Logger.warning(
                    f"[DB] save_character_position missing character guid={char_guid} realm={realm_id}"
                )
                return False

            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            Logger.warning(
                f"[DB] save_character_position failed guid={char_guid} realm={realm_id}: {exc}"
            )
            return False

    @staticmethod
    def save_character_online_state(
        char_guid: int,
        realm_id: int,
        *,
        online: int | None = None,
        logout_time: int | None = None,
    ) -> bool:
        session = DatabaseConnection.chars()
        try:
            values = {}
            if online is not None:
                values[Characters.online] = int(online)
            if logout_time is not None:
                values[Characters.logout_time] = int(logout_time)
            if not values:
                return True

            updated = (
                session.query(Characters)
                .filter(
                    Characters.guid == int(char_guid),
                    Characters.realm == int(realm_id),
                )
                .update(values, synchronize_session=False)
            )
            if not updated:
                session.rollback()
                Logger.warning(
                    f"[DB] save_character_online_state missing character guid={char_guid} realm={realm_id}"
                )
                return False
            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            Logger.warning(
                f"[DB] save_character_online_state failed guid={char_guid} realm={realm_id}: {exc}"
            )
            return False

    @staticmethod
    def get_item_template_map(entries: list[int]) -> dict[int, tuple[int, int]]:
        if not entries:
            return {}
        cached = DatabaseConnection._item_template_cache
        missing = [entry for entry in entries if entry not in cached]
        if not missing:
            return {entry: cached.get(entry) for entry in entries if entry in cached}
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return {}
        result: dict[int, tuple[int, int]] = {}
        try:
            rows = (
                session.query(
                    ItemTemplate.entry,
                    ItemTemplate.displayid,
                    ItemTemplate.inventory_type,
                )
                .filter(ItemTemplate.entry.in_(list(missing)))
                .all()
            )
        except Exception as exc:
            Logger.warning(f"[DB] item_template lookup failed: {exc}")
            return {entry: cached.get(entry) for entry in entries if entry in cached}

        for row in rows:
            try:
                entry = int(row[0])
                display_id = int(row[1]) if row[1] is not None else 0
                inv_type = int(row[2]) if row[2] is not None else 0
                result[entry] = (display_id, inv_type)
                cached[entry] = (display_id, inv_type)
            except Exception:
                continue
        return {entry: cached.get(entry) for entry in entries if entry in cached}

    @staticmethod
    def get_creature_template(entry: int) -> dict | None:
        if int(entry or 0) <= 0:
            return None
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return None

        stmt = text(
            """
            SELECT
                entry,
                KillCredit1,
                KillCredit2,
                modelid1,
                modelid2,
                modelid3,
                modelid4,
                name,
                subname,
                IconName,
                exp,
                npc_rank,
                type,
                type_flags,
                type_flags2,
                family,
                movementId,
                Health_mod,
                Mana_mod,
                RacialLeader,
                questItem1,
                questItem2,
                questItem3,
                questItem4,
                questItem5,
                questItem6
            FROM creature_template
            WHERE entry = :entry
            LIMIT 1
            """
        )
        try:
            row = session.execute(stmt, {"entry": int(entry)}).mappings().first()
        except Exception as exc:
            Logger.warning(f"[DB] creature_template lookup failed for entry={entry}: {exc}")
            return None

        if row is None:
            return None
        return dict(row)

    @staticmethod
    def get_player_create_info(race: int, class_: int):
        if DatabaseConnection._world_cache_loaded:
            return DatabaseConnection._cache_playercreateinfo.get((int(race), int(class_)))
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return None

        try:
            return (
                session.query(PlayerCreateInfo)
                .filter(
                    PlayerCreateInfo.race == int(race),
                    PlayerCreateInfo.class_ == int(class_),
                )
                .first()
            )
        except Exception as exc:
            Logger.warning(f"[DB] playercreateinfo lookup failed: {exc}")
            return None

    @staticmethod
    def get_table_columns(table_name: str, schema: str | None = None) -> list[str]:
        Logger.warning("[DB] get_table_columns is deprecated; use ORM models instead.")
        return []

    @staticmethod
    def _insert_rows(table: str, columns: list[str], rows: list[dict]) -> None:
        Logger.warning("[DB] _insert_rows is deprecated; use ORM models instead.")

    @staticmethod
    def _delete_rows(table: str, guid: int) -> None:
        Logger.warning("[DB] _delete_rows is deprecated; use ORM models instead.")

    @staticmethod
    def _race_mask(race: int) -> int:
        mapping = {
            1: 1,
            2: 2,
            3: 4,
            4: 8,
            5: 16,
            6: 32,
            7: 64,
            8: 128,
            9: 256,
            10: 512,
            11: 1024,
            22: 2097152,
            24: 8388608,
            25: 16777216,
            26: 33554432,
        }
        return mapping.get(race, 1 << max(race - 1, 0))

    @staticmethod
    def _class_mask(class_: int) -> int:
        return 1 << max(class_ - 1, 0)

    @staticmethod
    def get_player_createinfo_actions(race: int, class_: int) -> list[tuple[int, int, int]]:
        if DatabaseConnection._world_cache_loaded:
            return DatabaseConnection._cache_playercreateinfo_actions.get((int(race), int(class_)), [])
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return []
        try:
            rows = (
                session.query(PlayerCreateInfoAction.button, PlayerCreateInfoAction.action, PlayerCreateInfoAction.type)
                .filter(
                    PlayerCreateInfoAction.race == int(race),
                    PlayerCreateInfoAction.class_ == int(class_),
                )
                .all()
            )
        except Exception as exc:
            Logger.warning(f"[DB] playercreateinfo_action lookup failed: {exc}")
            return []

        actions: list[tuple[int, int, int]] = []
        for row in rows:
            try:
                actions.append((int(row[0]), int(row[1]), int(row[2])))
            except Exception:
                continue
        return actions
    # --------------------------------------------------
    # CHARACTER ACTION BUTTONS
    # --------------------------------------------------
    @staticmethod
    def get_character_action_buttons(char_guid: int) -> list[int]:
        """
        Return action buttons for character.
        Falls back to createinfo actions if none exist.
        """
        session = DatabaseConnection.chars()

        rows = (
            session.query(
                CharacterAction.button,
                CharacterAction.action,
                CharacterAction.type_,
            )
            .filter(CharacterAction.guid == char_guid)
            .all()
        )

        # --------------------------------------------------
        # If character has saved actions
        # --------------------------------------------------
        if rows:
            buttons = [0] * 120
            for btn, action, type_ in rows:
                try:
                    idx = int(btn)
                    if 0 <= idx < 120:
                        # Pack action + type the same way Trinity/SkyFire does
                        buttons[idx] = (int(action) & 0x00FFFFFF) | (int(type_) << 24)
                except Exception:
                    continue
            return buttons

        # --------------------------------------------------
        # New character → use createinfo actions
        # --------------------------------------------------
        char = (
            session.query(Characters.race, Characters.class_)
            .filter(Characters.guid == char_guid)
            .first()
        )

        if not char:
            Logger.error(f"[DB] get_character_action_buttons: character {char_guid} not found")
            return [0] * 120

        buttons = [0] * 120
        actions = DatabaseConnection.get_player_createinfo_actions(
            race=int(char.race),
            class_=int(char.class_),
        )

        for button, action, type_ in actions:
            try:
                if 0 <= button < 120:
                    buttons[button] = (int(action) & 0x00FFFFFF) | (int(type_) << 24)
            except Exception:
                continue

        return buttons

    @staticmethod
    def _get_spell_table(model, race_mask: int, class_mask: int) -> list[int]:
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return []
        try:
            rows = (
                session.query(model.spell)
                .filter(
                    or_(model.racemask == 0, model.racemask.op("&")(race_mask) != 0),
                    or_(model.classmask == 0, model.classmask.op("&")(class_mask) != 0),
                )
                .all()
            )
        except Exception as exc:
            Logger.warning(f"[DB] {model.__tablename__} lookup failed: {exc}")
            return []

        spells: list[int] = []
        for row in rows:
            try:
                spell_id = int(row[0])
                if spell_id > 0:
                    spells.append(spell_id)
            except Exception:
                continue
        return spells

    @staticmethod
    def get_player_createinfo_spells(race: int, class_: int) -> list[int]:
        race_mask = DatabaseConnection._race_mask(int(race))
        class_mask = DatabaseConnection._class_mask(int(class_))
        if DatabaseConnection._world_cache_loaded:
            key = (int(race), int(class_))
            cached = DatabaseConnection._cache_playercreateinfo_spells_by_pair.get(key)
            if cached is not None:
                return cached
            spells = set()
            for racemask, classmask, spell_id in DatabaseConnection._cache_playercreateinfo_spell_rows:
                if racemask == 0 or (racemask & race_mask) != 0:
                    if classmask == 0 or (classmask & class_mask) != 0:
                        spells.add(int(spell_id))
            result = sorted(spells)
            DatabaseConnection._cache_playercreateinfo_spells_by_pair[key] = result
            return result
        spells = set(DatabaseConnection._get_spell_table(PlayerCreateInfoSpell, race_mask, class_mask))
        spells.update(DatabaseConnection._get_spell_table(PlayerCreateInfoSpellCustom, race_mask, class_mask))
        spells.update(DatabaseConnection._get_spell_table(PlayerCreateInfoSpellCast, race_mask, class_mask))
        return sorted(spells)

    # --------------------------------------------------
    # CHARACTER SPELLS
    # --------------------------------------------------
    @staticmethod
    def get_character_spells(char_guid: int) -> list[int]:
        """
        Return learned spells for character.
        Falls back to createinfo spells if none exist.
        """
        session = DatabaseConnection.chars()

        rows = (
            session.query(CharacterSpell.spell)
            .filter(
                CharacterSpell.guid == char_guid,
                CharacterSpell.disabled == 0,
            )
            .all()
        )

        if rows:
            return [int(r.spell) for r in rows]

        # --------------------------------------------------
        # New character → use createinfo spells
        # --------------------------------------------------
        char = (
            session.query(Characters.race, Characters.class_)
            .filter(Characters.guid == char_guid)
            .first()
        )

        if not char:
            Logger.error(f"[DB] get_character_spells: character {char_guid} not found")
            return []

        return DatabaseConnection.get_player_createinfo_spells(
            race=int(char.race),
            class_=int(char.class_),
        )

    @staticmethod
    def apply_playercreateinfo_to_character(guid: int, race: int, class_: int) -> None:
        actions = DatabaseConnection.get_player_createinfo_actions(race, class_)
        spells = DatabaseConnection.get_player_createinfo_spells(race, class_)

        session = DatabaseConnection.chars()

        try:
            session.query(CharacterAction).filter(CharacterAction.guid == int(guid)).delete(
                synchronize_session=False
            )
        except Exception as exc:
            Logger.warning(f"[DB] character_action clear failed: {exc}")

        if actions:
            action_rows = [
                CharacterAction(
                    guid=int(guid),
                    spec=0,
                    button=int(button),
                    action=int(action),
                    type_=int(type_),
                )
                for button, action, type_ in actions
            ]
            session.add_all(action_rows)

        try:
            session.query(CharacterSpell).filter(CharacterSpell.guid == int(guid)).delete(
                synchronize_session=False
            )
        except Exception as exc:
            Logger.warning(f"[DB] character_spell clear failed: {exc}")

        if spells:
            spell_rows = [
                CharacterSpell(
                    guid=int(guid),
                    spell=int(spell_id),
                    active=1,
                    disabled=0,
                    spec=0,
                    spec_mask=0,
                )
                for spell_id in spells
            ]
            session.add_all(spell_rows)

        try:
            session.commit()
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] Failed to apply playercreateinfo: {exc}")

    @staticmethod
    def get_starting_item_entries(race: int, class_: int, gender: int | None = None) -> list[int]:
        if DatabaseConnection._world_cache_loaded:
            return DatabaseConnection._cache_playercreateinfo_items.get((int(race), int(class_)), [])
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return []
        try:
            rows = (
                session.query(PlayerCreateInfoItem.itemid)
                .filter(
                    PlayerCreateInfoItem.race == int(race),
                    PlayerCreateInfoItem.class_ == int(class_),
                )
                .all()
            )
        except Exception as exc:
            Logger.warning(f"[DB] playercreateinfo_item lookup failed: {exc}")
            return []

        entries: list[int] = []
        for row in rows:
            try:
                entry = int(row[0])
                if entry > 0:
                    entries.append(entry)
            except Exception:
                continue
        return entries

    @staticmethod
    def get_starting_items_with_template(
        race: int,
        class_: int,
        gender: int | None = None,
    ) -> list[tuple[int, int, int]]:
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return []
        try:
            rows = (
                session.query(
                    PlayerCreateInfoItem.itemid,
                    ItemTemplate.displayid,
                    ItemTemplate.inventory_type,
                )
                .outerjoin(ItemTemplate, ItemTemplate.entry == PlayerCreateInfoItem.itemid)
                .filter(
                    PlayerCreateInfoItem.race == int(race),
                    PlayerCreateInfoItem.class_ == int(class_),
                )
                .all()
            )
        except Exception as exc:
            Logger.warning(f"[DB] playercreateinfo_item join failed: {exc}")
            return []

        items: list[tuple[int, int, int]] = []
        for row in rows:
            try:
                entry = int(row[0])
                display_id = int(row[1]) if row[1] is not None else 0
                inv_type = int(row[2]) if row[2] is not None else 0
                if entry > 0:
                    items.append((entry, display_id, inv_type))
            except Exception:
                continue
        return items

    # WORLD ORM HELPERS
    @staticmethod
    def get_factionchange_achievements() -> dict[int, int]:
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return {}
        try:
            rows = session.query(PlayerFactionchangeAchievement).all()
        except Exception as exc:
            Logger.warning(f"[DB] player_factionchange_achievement lookup failed: {exc}")
            return {}
        return {int(row.alliance_id): int(row.horde_id) for row in rows}

    @staticmethod
    def get_factionchange_items() -> list[PlayerFactionchangeItems]:
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return []
        try:
            return session.query(PlayerFactionchangeItems).all()
        except Exception as exc:
            Logger.warning(f"[DB] player_factionchange_items lookup failed: {exc}")
            return []

    @staticmethod
    def get_factionchange_quests() -> dict[int, int]:
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return {}
        try:
            rows = session.query(PlayerFactionchangeQuests).all()
        except Exception as exc:
            Logger.warning(f"[DB] player_factionchange_quests lookup failed: {exc}")
            return {}
        return {int(row.alliance_id): int(row.horde_id) for row in rows}

    @staticmethod
    def get_factionchange_reputations() -> dict[int, int]:
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return {}
        try:
            rows = session.query(PlayerFactionchangeReputations).all()
        except Exception as exc:
            Logger.warning(f"[DB] player_factionchange_reputations lookup failed: {exc}")
            return {}
        return {int(row.alliance_id): int(row.horde_id) for row in rows}

    @staticmethod
    def get_factionchange_spells() -> dict[int, int]:
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return {}
        try:
            rows = session.query(PlayerFactionchangeSpells).all()
        except Exception as exc:
            Logger.warning(f"[DB] player_factionchange_spells lookup failed: {exc}")
            return {}
        return {int(row.alliance_id): int(row.horde_id) for row in rows}

    @staticmethod
    def get_factionchange_titles() -> dict[int, int]:
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return {}
        try:
            rows = session.query(PlayerFactionchangeTitles).all()
        except Exception as exc:
            Logger.warning(f"[DB] player_factionchange_titles lookup failed: {exc}")
            return {}
        return {int(row.alliance_id): int(row.horde_id) for row in rows}

    @staticmethod
    def get_level_stats(race: int, class_: int, level: int):
        if DatabaseConnection._world_cache_loaded:
            return DatabaseConnection._cache_levelstats.get((int(race), int(class_), int(level)))
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return None
        try:
            return (
                session.query(PlayerLevelStats)
                .filter(
                    PlayerLevelStats.race == int(race),
                    PlayerLevelStats.class_ == int(class_),
                    PlayerLevelStats.level == int(level),
                )
                .first()
            )
        except Exception as exc:
            Logger.warning(f"[DB] player_levelstats lookup failed: {exc}")
            return None

    @staticmethod
    def get_level_stats_for_class(race: int, class_: int) -> list[PlayerLevelStats]:
        if DatabaseConnection._world_cache_loaded:
            return DatabaseConnection._cache_levelstats_by_pair.get((int(race), int(class_)), [])
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return []
        try:
            return (
                session.query(PlayerLevelStats)
                .filter(
                    PlayerLevelStats.race == int(race),
                    PlayerLevelStats.class_ == int(class_),
                )
                .order_by(PlayerLevelStats.level.asc())
                .all()
            )
        except Exception as exc:
            Logger.warning(f"[DB] player_levelstats lookup failed: {exc}")
            return []

    @staticmethod
    def get_xp_for_level(level: int) -> int | None:
        if DatabaseConnection._world_cache_loaded:
            return DatabaseConnection._cache_xp_for_level.get(int(level))
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return None
        try:
            row = (
                session.query(PlayerXpForLevel.xp_for_next_level)
                .filter(PlayerXpForLevel.lvl == int(level))
                .first()
            )
        except Exception as exc:
            Logger.warning(f"[DB] player_xp_for_level lookup failed: {exc}")
            return None
        if not row:
            return None
        try:
            return int(row[0])
        except Exception:
            return None

    @staticmethod
    def get_xp_table() -> dict[int, int]:
        if DatabaseConnection._world_cache_loaded:
            return dict(DatabaseConnection._cache_xp_for_level)
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return {}
        try:
            rows = session.query(PlayerXpForLevel.lvl, PlayerXpForLevel.xp_for_next_level).all()
        except Exception as exc:
            Logger.warning(f"[DB] player_xp_for_level lookup failed: {exc}")
            return {}
        result: dict[int, int] = {}
        for row in rows:
            try:
                result[int(row[0])] = int(row[1])
            except Exception:
                continue
        return result

    # SRP helpers
    @staticmethod
    def update_sessionkey(account, key_bytes):
        s = DatabaseConnection.auth()
        account.session_key = key_bytes
        s.commit()

    @staticmethod
    def update_verifier_and_salt(account, verifier, salt):
        s = DatabaseConnection.auth()
        account.verifier = verifier
        account.salt = salt
        s.commit()
    
    # ACCOUNT ORM HELPERS
    @staticmethod
    def get_user_by_username(username: str):
        """Fetch Account row by username."""
        return (
            DatabaseConnection.auth()
            .query(Account)
            .filter(Account.username == username)
            .first()
        )

    @staticmethod
    def create_or_update_account(username, salt, verifier):
        """
        Create or update account using the ORM Account model.
        Matches the style used by proxies.
        """
        session = DatabaseConnection.auth()

        acc = (
            session.query(Account)
            .filter(Account.username == username)
            .first()
        )

        if acc is None:
            acc = Account(username=username, salt=salt, verifier=verifier)
            session.add(acc)
            Logger.success(f"[DB] Created account {username}")
        else:
            acc.salt = salt
            acc.verifier = verifier
            Logger.success(f"[DB] Updated account {username}")

        session.commit()
        return acc.id

    @staticmethod
    def set_gmlevel(account_id, gmlevel):
        """
        Uses ORM model for account_access just like SkyFire expects.
        """
        session = DatabaseConnection.auth()

        row = (
            session.query(AccountAccess)
            .filter(AccountAccess.id == account_id)
            .first()
        )

        if row is None:
            row = AccountAccess(id=account_id, gmlevel=gmlevel, RealmID=-1)
            session.add(row)
        else:
            row.gmlevel = gmlevel

        session.commit()
        Logger.success(f"[DB] GM level set to {gmlevel} for account {account_id}")
