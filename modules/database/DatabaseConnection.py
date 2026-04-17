#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from hashlib import md5

from sqlalchemy import create_engine, or_, text
from sqlalchemy.orm import scoped_session, sessionmaker

from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger

from server.modules.auth.AuthConnection import AuthConnection
from server.modules.database.CharactersModel import (
    Characters,
    CharacterAction,
    CharacterSpell,
    CharacterInventory,
    ItemInstance,
)
from server.modules.database.WorldModel import (
    ItemTemplate,
    WorldCreature,
    WorldCreatureTemplate,
    WorldGameObject,
    WorldGameObjectTemplate,
    GameEventGameObject,
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
    """Handles DB connections for characters-db and world-db."""

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
    _item_template_details_cache = {}
    _cache_creature_templates = {}
    _cache_creatures_by_map = {}
    _cache_creatures_loaded = False
    _cache_gameobjects_by_map = {}
    _cache_gameobjects_loaded = False
    _account_data_tables_ready = False
    _addon_tables_ready = False
    _db_signature = None

    @staticmethod
    def _signature(db: dict) -> tuple:
        return (
            str(db.get("host", "")),
            int(db.get("port", 3306) or 3306),
            str(db.get("username", "")),
            str(db.get("password", "")),
            str(db.get("characters_db", "")),
            str(db.get("world_db", "")),
        )

    @staticmethod
    def _dispose_existing() -> None:
        for session in (DatabaseConnection._char_session, DatabaseConnection._world_session):
            if session is not None:
                try:
                    session.remove()
                except Exception:
                    pass

        for engine in (DatabaseConnection._char_engine, DatabaseConnection._world_engine):
            if engine is not None:
                try:
                    engine.dispose()
                except Exception:
                    pass

        DatabaseConnection._char_engine = None
        DatabaseConnection._char_session = None
        DatabaseConnection._world_engine = None
        DatabaseConnection._world_session = None
        DatabaseConnection._characters_db_name = None
        DatabaseConnection._world_db_name = None
        DatabaseConnection._db_signature = None

    @staticmethod
    def _reset_caches() -> None:
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
        DatabaseConnection._item_template_details_cache = {}
        DatabaseConnection._cache_creature_templates = {}
        DatabaseConnection._cache_creatures_by_map = {}
        DatabaseConnection._cache_creatures_loaded = False
        DatabaseConnection._cache_gameobjects_by_map = {}
        DatabaseConnection._cache_gameobjects_loaded = False
        DatabaseConnection._account_data_tables_ready = False
        DatabaseConnection._addon_tables_ready = False

    @staticmethod
    def initialize():
        """Initialize characters-db and optional world-db. Auth lives in AuthConnection."""
        config = ConfigLoader.load_config()
        db = config["database"]
        signature = DatabaseConnection._signature(db)

        if DatabaseConnection._char_session is not None and DatabaseConnection._db_signature == signature:
            return

        DatabaseConnection._dispose_existing()
        DatabaseConnection._reset_caches()

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
        DatabaseConnection._db_signature = signature

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
            Logger.info("Database initialized (characters + world)")
        else:
            Logger.info("Database initialized (characters)")

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

        preload_npcs = bool(
            ConfigLoader.load_config().get("worldserver", {}).get("preload_npcs", False)
        )
        if preload_npcs:
            try:
                rows = session.query(WorldCreatureTemplate).all()
                DatabaseConnection._cache_creature_templates = {
                    int(row.entry): DatabaseConnection._build_creature_template_entry(row)
                    for row in rows
                    if int(getattr(row, "entry", 0) or 0) > 0
                }
                Logger.info("[DB] preloaded %s creature templates", len(DatabaseConnection._cache_creature_templates))
            except Exception as exc:
                Logger.warning(f"[DB] creature_template preload failed: {exc}")
                DatabaseConnection._cache_creature_templates = {}

            try:
                rows = session.query(WorldCreature).all()
                by_map: dict[int, list[dict]] = {}
                for row in rows:
                    candidate = DatabaseConnection._build_creature_candidate(row)
                    if candidate is None:
                        continue
                    by_map.setdefault(int(candidate["map_id"]), []).append(candidate)
                DatabaseConnection._cache_creatures_by_map = by_map
                DatabaseConnection._cache_creatures_loaded = True
                Logger.info(
                    "[DB] preloaded %s creature spawns across %s maps",
                    sum(len(entries) for entries in by_map.values()),
                    len(by_map),
                )
            except Exception as exc:
                Logger.warning(f"[DB] creature preload failed: {exc}")
                DatabaseConnection._cache_creatures_by_map = {}
                DatabaseConnection._cache_creatures_loaded = False
        else:
            DatabaseConnection._cache_creature_templates = {}
            DatabaseConnection._cache_creatures_by_map = {}
            DatabaseConnection._cache_creatures_loaded = False
            Logger.info("[DB] creature preload disabled by config")

        preload_gameobjects = bool(
            ConfigLoader.load_config().get("worldserver", {}).get("preload_gameobjects", True)
        )
        if preload_gameobjects:
            try:
                rows = (
                    session.query(
                        WorldGameObject.guid,
                        WorldGameObject.id,
                        WorldGameObject.map,
                        WorldGameObject.position_x,
                        WorldGameObject.position_y,
                        WorldGameObject.position_z,
                        WorldGameObject.orientation,
                        WorldGameObject.rotation0,
                        WorldGameObject.rotation1,
                        WorldGameObject.rotation2,
                        WorldGameObject.rotation3,
                        WorldGameObject.animprogress,
                        WorldGameObject.state,
                        WorldGameObjectTemplate.type,
                        WorldGameObjectTemplate.displayId,
                        WorldGameObjectTemplate.name,
                        WorldGameObjectTemplate.faction,
                        WorldGameObjectTemplate.flags,
                        WorldGameObjectTemplate.size,
                        WorldGameObjectTemplate.data0,
                        WorldGameObjectTemplate.data1,
                        WorldGameObjectTemplate.data2,
                        WorldGameObjectTemplate.data3,
                    )
                    .join(WorldGameObjectTemplate, WorldGameObjectTemplate.entry == WorldGameObject.id)
                    .outerjoin(GameEventGameObject, GameEventGameObject.guid == WorldGameObject.guid)
                    .filter(GameEventGameObject.guid.is_(None))
                    .all()
                )
                by_map: dict[int, list[dict]] = {}
                for row in rows:
                    candidate = DatabaseConnection._build_gameobject_candidate(row)
                    if candidate is None:
                        continue
                    by_map.setdefault(int(candidate["map_id"]), []).append(candidate)
                DatabaseConnection._cache_gameobjects_by_map = by_map
                DatabaseConnection._cache_gameobjects_loaded = True
                Logger.info(
                    "[DB] preloaded %s gameobjects across %s maps",
                    sum(len(entries) for entries in by_map.values()),
                    len(by_map),
                )
            except Exception as exc:
                Logger.warning(f"[DB] gameobject preload failed: {exc}")
                DatabaseConnection._cache_gameobjects_by_map = {}
                DatabaseConnection._cache_gameobjects_loaded = False
        else:
            DatabaseConnection._cache_gameobjects_by_map = {}
            DatabaseConnection._cache_gameobjects_loaded = False
            Logger.info("[DB] gameobject preload disabled by config")

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
        DatabaseConnection._item_template_details_cache = {}
        DatabaseConnection._cache_creature_templates = {}
        DatabaseConnection._cache_creatures_by_map = {}
        DatabaseConnection._cache_creatures_loaded = False
        DatabaseConnection._cache_gameobjects_by_map = {}
        DatabaseConnection._cache_gameobjects_loaded = False
        DatabaseConnection.preload_world_cache()

    # AUTH DB SESSION
    @staticmethod
    def auth():
        return AuthConnection.session()

    @staticmethod
    def auth_legacy():
        return AuthConnection.session()

    @staticmethod
    def auth_old():
        return AuthConnection.session()

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
    def get_user_by_username_old(username):
        return AuthConnection.get_user(username)

    @staticmethod
    def get_account_id_by_username_old(username: str):
        return AuthConnection.get_account_id(username)

    @staticmethod
    def get_realmlist_old():
        return AuthConnection.get_realmlist()

    @staticmethod
    def get_all_realms_old():
        return AuthConnection.get_all_realms()

    # CHARACTER QUERIES
    @staticmethod
    def get_characters_for_account(account_id, realm_id):
        session = DatabaseConnection.chars()
        session.expire_all()
        base = session.query(Characters).populate_existing().filter(
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
            session.expire_all()
            return (
                session.query(Characters)
                .populate_existing()
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
            session.expire_all()
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
            session.expire_all()
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
    def get_item_template_details(entries: list[int]) -> dict[int, dict[str, int]]:
        if not entries:
            return {}

        cached = DatabaseConnection._item_template_details_cache
        missing = [entry for entry in entries if entry not in cached]
        if missing:
            try:
                session = DatabaseConnection.world()
            except Exception as exc:
                Logger.warning(f"[DB] World DB unavailable: {exc}")
                return {entry: cached.get(entry) for entry in entries if entry in cached}

            try:
                rows = (
                    session.query(ItemTemplate)
                    .filter(ItemTemplate.entry.in_(list(missing)))
                    .all()
                )
            except Exception as exc:
                Logger.warning(f"[DB] item_template detail lookup failed: {exc}")
                return {entry: cached.get(entry) for entry in entries if entry in cached}

            for row in rows:
                try:
                    entry = int(row.entry)
                    cached[entry] = {
                        "entry": entry,
                        "display_id": int(row.displayid or 0),
                        "inventory_type": int(row.inventory_type or 0),
                        "stackable": max(1, int(row.stackable or 1)),
                        "buy_count": max(1, int(row.buy_count or 1)),
                        "bag_family": int(row.bag_family or 0),
                        "item_class": int(row.class_ or 0),
                        "subclass": int(row.subclass or 0),
                        "container_slots": int(row.container_slots or 0),
                    }
                except Exception:
                    continue

        return {entry: cached.get(entry) for entry in entries if entry in cached}

    @staticmethod
    def get_character_inventory_rows(char_guid: int) -> list[dict]:
        session = DatabaseConnection.chars()
        try:
            rows = (
                session.query(CharacterInventory, ItemInstance)
                .join(ItemInstance, ItemInstance.guid == CharacterInventory.item)
                .filter(CharacterInventory.guid == int(char_guid))
                .order_by(CharacterInventory.bag.asc(), CharacterInventory.slot.asc(), CharacterInventory.item.asc())
                .all()
            )
        except Exception as exc:
            Logger.warning(f"[DB] get_character_inventory_rows failed guid={char_guid}: {exc}")
            return []

        result: list[dict] = []
        for inv_row, item_row in rows:
            try:
                result.append(
                    {
                        "guid": int(inv_row.guid or 0),
                        "bag": int(inv_row.bag or 0),
                        "slot": int(inv_row.slot or 0),
                        "item_guid": int(inv_row.item or 0),
                        "item_entry": int(item_row.itemEntry or 0),
                        "owner_guid": int(item_row.owner_guid or 0),
                        "count": int(item_row.count or 0),
                        "flags": int(item_row.flags or 0),
                        "durability": int(item_row.durability or 0),
                        "random_property_id": int(item_row.randomPropertyId or 0),
                    }
                )
            except Exception:
                continue
        return result

    @staticmethod
    def save_character_equipment_cache(char_guid: int, realm_id: int, equipment_cache: str) -> bool:
        session = DatabaseConnection.chars()
        try:
            updated = (
                session.query(Characters)
                .filter(
                    Characters.guid == int(char_guid),
                    Characters.realm == int(realm_id),
                )
                .update({Characters.equipmentCache: str(equipment_cache or "")}, synchronize_session=False)
            )
            if not updated:
                session.rollback()
                Logger.warning(
                    f"[DB] save_character_equipment_cache missing character guid={char_guid} realm={realm_id}"
                )
                return False
            session.commit()
            session.expire_all()
            return True
        except Exception as exc:
            session.rollback()
            Logger.warning(
                f"[DB] save_character_equipment_cache failed guid={char_guid} realm={realm_id}: {exc}"
            )
            return False

    @staticmethod
    def save_character_explored_zones(char_guid: int, realm_id: int, explored_zones: str) -> bool:
        session = DatabaseConnection.chars()
        try:
            updated = (
                session.query(Characters)
                .filter(
                    Characters.guid == int(char_guid),
                    Characters.realm == int(realm_id),
                )
                .update({Characters.exploredZones: str(explored_zones or "")}, synchronize_session=False)
            )
            session.commit()
            if updated <= 0:
                Logger.warning(
                    f"[DB] save_character_explored_zones missing character guid={char_guid} realm={realm_id}"
                )
                return False
            return True
        except Exception as exc:
            session.rollback()
            Logger.error(
                f"[DB] save_character_explored_zones failed guid={char_guid} realm={realm_id}: {exc}"
            )
            return False

    @staticmethod
    def save_character_level(char_guid: int, realm_id: int, level: int, *, xp: int = 0) -> bool:
        session = DatabaseConnection.chars()
        try:
            updated = (
                session.query(Characters)
                .filter(
                    Characters.guid == int(char_guid),
                    Characters.realm == int(realm_id),
                )
                .update(
                    {
                        Characters.level: int(level),
                        Characters.xp: int(xp),
                    },
                    synchronize_session=False,
                )
            )
            session.commit()
            if updated <= 0:
                Logger.warning(
                    f"[DB] save_character_level missing character guid={char_guid} realm={realm_id}"
                )
                return False
            return True
        except Exception as exc:
            session.rollback()
            Logger.error(
                f"[DB] save_character_level failed guid={char_guid} realm={realm_id}: {exc}"
            )
            return False

    @staticmethod
    def get_creature_template(entry: int) -> dict | None:
        if int(entry or 0) <= 0:
            return None
        if DatabaseConnection._world_cache_loaded and DatabaseConnection._cache_creatures_loaded:
            cached = DatabaseConnection._cache_creature_templates.get(int(entry))
            return dict(cached) if cached is not None else None
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
    def get_creatures_near(
        map_id: int,
        x: float,
        y: float,
        *,
        radius: float = 120.0,
        limit: int = 200,
    ) -> list[dict]:
        radius = max(0.0, float(radius))
        min_x = float(x) - radius
        max_x = float(x) + radius
        min_y = float(y) - radius
        max_y = float(y) + radius
        radius_sq = radius * radius

        if DatabaseConnection._world_cache_loaded and DatabaseConnection._cache_creatures_loaded:
            entries = list(DatabaseConnection._cache_creatures_by_map.get(int(map_id), ()) or ())
            if not entries:
                return []

            matches: list[dict] = []
            for entry in entries:
                entry_x = float(entry.get("x", 0.0) or 0.0)
                entry_y = float(entry.get("y", 0.0) or 0.0)

                if entry_x < min_x or entry_x > max_x or entry_y < min_y or entry_y > max_y:
                    continue

                dx = entry_x - float(x)
                dy = entry_y - float(y)
                if (dx * dx) + (dy * dy) > radius_sq:
                    continue

                matches.append(dict(entry))
                if len(matches) >= int(limit):
                    break

            return matches

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return []

        try:
            rows = (
                session.query(WorldCreature)
                .filter(
                    WorldCreature.map == int(map_id),
                    WorldCreature.position_x >= min_x,
                    WorldCreature.position_x <= max_x,
                    WorldCreature.position_y >= min_y,
                    WorldCreature.position_y <= max_y,
                )
                .limit(int(limit))
                .all()
            )
        except Exception as exc:
            Logger.warning(f"[DB] creature lookup failed map={map_id} x={x:.1f} y={y:.1f}: {exc}")
            return []

        creatures: list[dict] = []
        for row in rows:
            candidate = DatabaseConnection._build_creature_candidate(row)
            if candidate is None:
                continue

            entry_x = float(candidate.get("x", 0.0) or 0.0)
            entry_y = float(candidate.get("y", 0.0) or 0.0)
            dx = entry_x - float(x)
            dy = entry_y - float(y)
            if (dx * dx) + (dy * dy) > radius_sq:
                continue

            creatures.append(candidate)
            if len(creatures) >= int(limit):
                break

        return creatures

    @staticmethod
    def get_gameobjects_near(
        map_id: int,
        x: float,
        y: float,
        *,
        radius: float = 120.0,
        limit: int = 200,
    ) -> list[dict]:
        radius = max(0.0, float(radius))
        min_x = float(x) - radius
        max_x = float(x) + radius
        min_y = float(y) - radius
        max_y = float(y) + radius
        radius_sq = radius * radius

        if DatabaseConnection._world_cache_loaded and DatabaseConnection._cache_gameobjects_loaded:
            entries = list(DatabaseConnection._cache_gameobjects_by_map.get(int(map_id), ()) or ())
            if not entries:
                return []

            matches: list[dict] = []
            for entry in entries:
                entry_x = float(entry.get("x", 0.0) or 0.0)
                entry_y = float(entry.get("y", 0.0) or 0.0)

                if entry_x < min_x or entry_x > max_x or entry_y < min_y or entry_y > max_y:
                    continue

                dx = entry_x - float(x)
                dy = entry_y - float(y)
                if (dx * dx) + (dy * dy) > radius_sq:
                    continue

                matches.append(dict(entry))
                if len(matches) >= int(limit):
                    break

            return matches

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return []

        try:
            rows = (
                session.query(
                    WorldGameObject.guid,
                    WorldGameObject.id,
                    WorldGameObject.map,
                    WorldGameObject.position_x,
                    WorldGameObject.position_y,
                    WorldGameObject.position_z,
                    WorldGameObject.orientation,
                    WorldGameObject.rotation0,
                    WorldGameObject.rotation1,
                    WorldGameObject.rotation2,
                    WorldGameObject.rotation3,
                    WorldGameObject.animprogress,
                    WorldGameObject.state,
                    WorldGameObjectTemplate.type,
                    WorldGameObjectTemplate.displayId,
                    WorldGameObjectTemplate.name,
                    WorldGameObjectTemplate.faction,
                    WorldGameObjectTemplate.flags,
                    WorldGameObjectTemplate.size,
                    WorldGameObjectTemplate.data0,
                    WorldGameObjectTemplate.data1,
                    WorldGameObjectTemplate.data2,
                    WorldGameObjectTemplate.data3,
                )
                .join(WorldGameObjectTemplate, WorldGameObjectTemplate.entry == WorldGameObject.id)
                .outerjoin(GameEventGameObject, GameEventGameObject.guid == WorldGameObject.guid)
                .filter(GameEventGameObject.guid.is_(None))
                .filter(
                    WorldGameObject.map == int(map_id),
                    WorldGameObject.position_x >= min_x,
                    WorldGameObject.position_x <= max_x,
                    WorldGameObject.position_y >= min_y,
                    WorldGameObject.position_y <= max_y,
                )
                .limit(int(limit))
                .all()
            )
        except Exception as exc:
            Logger.warning(f"[DB] gameobject lookup failed map={map_id} x={x:.1f} y={y:.1f}: {exc}")
            return []

        gameobjects: list[dict] = []

        for row in rows:
            candidate = DatabaseConnection._build_gameobject_candidate(row)
            if candidate is None:
                continue

            dx = candidate["x"] - float(x)
            dy = candidate["y"] - float(y)

            if (dx * dx) + (dy * dy) > radius_sq:
                continue

            gameobjects.append(candidate)

        return gameobjects

    @staticmethod
    def _build_gameobject_candidate(row) -> dict | None:
        display_id = int(getattr(row, "displayId", 0) or 0)
        if display_id == 0:
            return None

        name = str(getattr(row, "name", "") or "").lower()
        if any(token in name for token in ("darkmoon", "faire")):
            return None

        go_type = int(getattr(row, "type", 0) or 0)
        flags = int(getattr(row, "flags", 0) or 0)
        if flags == 0 and go_type == 5:
            return None

        return {
            "guid": int(getattr(row, "guid", 0) or 0),
            "entry": int(getattr(row, "id", 0) or 0),
            "map_id": int(getattr(row, "map", 0) or 0),
            "x": float(getattr(row, "position_x", 0.0) or 0.0),
            "y": float(getattr(row, "position_y", 0.0) or 0.0),
            "z": float(getattr(row, "position_z", 0.0) or 0.0),
            "orientation": float(getattr(row, "orientation", 0.0) or 0.0),
            "rotation0": float(getattr(row, "rotation0", 0.0) or 0.0),
            "rotation1": float(getattr(row, "rotation1", 0.0) or 0.0),
            "rotation2": float(getattr(row, "rotation2", 0.0) or 0.0),
            "rotation3": float(getattr(row, "rotation3", 0.0) or 0.0),
            "animprogress": int(getattr(row, "animprogress", 0) or 0),
            "state": int(getattr(row, "state", 0) or 0),
            "type": go_type,
            "display_id": display_id,
            "name": str(getattr(row, "name", "") or ""),
            "faction": int(getattr(row, "faction", 0) or 0),
            "flags": flags,
            "size": float(getattr(row, "size", 1.0) or 1.0),
            "data0": int(getattr(row, "data0", 0) or 0),
            "data1": int(getattr(row, "data1", 0) or 0),
            "data2": int(getattr(row, "data2", 0) or 0),
            "data3": int(getattr(row, "data3", 0) or 0),
        }

    @staticmethod
    def _build_creature_template_entry(row) -> dict:
        return {
            "entry": int(getattr(row, "entry", 0) or 0),
            "KillCredit1": int(getattr(row, "KillCredit1", 0) or 0),
            "KillCredit2": int(getattr(row, "KillCredit2", 0) or 0),
            "modelid1": int(getattr(row, "modelid1", 0) or 0),
            "modelid2": int(getattr(row, "modelid2", 0) or 0),
            "modelid3": int(getattr(row, "modelid3", 0) or 0),
            "modelid4": int(getattr(row, "modelid4", 0) or 0),
            "name": str(getattr(row, "name", "") or ""),
            "subname": str(getattr(row, "subname", "") or ""),
            "IconName": str(getattr(row, "IconName", "") or ""),
            "exp": int(getattr(row, "exp", 0) or 0),
            "npc_rank": int(getattr(row, "npc_rank", 0) or 0),
            "type": int(getattr(row, "type", 0) or 0),
            "type_flags": int(getattr(row, "type_flags", 0) or 0),
            "type_flags2": int(getattr(row, "type_flags2", 0) or 0),
            "family": int(getattr(row, "family", 0) or 0),
            "movementId": int(getattr(row, "movementId", 0) or 0),
            "Health_mod": float(getattr(row, "Health_mod", 0.0) or 0.0),
            "Mana_mod": float(getattr(row, "Mana_mod", 0.0) or 0.0),
            "RacialLeader": int(getattr(row, "RacialLeader", 0) or 0),
            "questItem1": int(getattr(row, "questItem1", 0) or 0),
            "questItem2": int(getattr(row, "questItem2", 0) or 0),
            "questItem3": int(getattr(row, "questItem3", 0) or 0),
            "questItem4": int(getattr(row, "questItem4", 0) or 0),
            "questItem5": int(getattr(row, "questItem5", 0) or 0),
            "questItem6": int(getattr(row, "questItem6", 0) or 0),
        }

    @staticmethod
    def _build_creature_candidate(row) -> dict | None:
        entry = int(getattr(row, "id", 0) or 0)
        guid = int(getattr(row, "guid", 0) or 0)
        if entry <= 0 or guid <= 0:
            return None

        return {
            "guid": guid,
            "entry": entry,
            "map_id": int(getattr(row, "map", 0) or 0),
            "modelid": int(getattr(row, "modelid", 0) or 0),
            "equipment_id": int(getattr(row, "equipment_id", 0) or 0),
            "x": float(getattr(row, "position_x", 0.0) or 0.0),
            "y": float(getattr(row, "position_y", 0.0) or 0.0),
            "z": float(getattr(row, "position_z", 0.0) or 0.0),
            "orientation": float(getattr(row, "orientation", 0.0) or 0.0),
            "spawntimesecs": int(getattr(row, "spawntimesecs", 0) or 0),
            "spawndist": float(getattr(row, "spawndist", 0.0) or 0.0),
            "currentwaypoint": int(getattr(row, "currentwaypoint", 0) or 0),
            "curhealth": int(getattr(row, "curhealth", 0) or 0),
            "curmana": int(getattr(row, "curmana", 0) or 0),
            "movement_type": int(getattr(row, "MovementType", 0) or 0),
            "npcflag": int(getattr(row, "npcflag", 0) or 0),
            "unit_flags": int(getattr(row, "unit_flags", 0) or 0),
            "dynamicflags": int(getattr(row, "dynamicflags", 0) or 0),
        }

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
    def update_character_money(guid: int, realm_id: int, money: int) -> None:
        session = DatabaseConnection.chars()

        try:
            char = session.query(Characters).filter_by(
                guid=int(guid),
                realm=int(realm_id),
            ).first()

            if not char:
                return

            char.money = int(money)
            session.commit()

        except Exception:
            session.rollback()
            raise

        finally:
            session.close()

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
        Return action buttons merged from createinfo defaults and saved rows.
        """
        session = DatabaseConnection.chars()

        char = (
            session.query(Characters.race, Characters.class_)
            .filter(Characters.guid == char_guid)
            .first()
        )

        if not char:
            Logger.error(f"[DB] get_character_action_buttons: character {char_guid} not found")
            return [0] * 132

        buttons = [0] * 132
        actions = DatabaseConnection.get_player_createinfo_actions(
            race=int(char.race),
            class_=int(char.class_),
        )
        Logger.info(
            "[ACTION_BUTTON] loading default action bar guid=%s race=%s class=%s count=%s",
            int(char_guid),
            int(char.race),
            int(char.class_),
            len(actions),
        )

        for button, action, type_ in actions:
            try:
                if 0 <= button < 132:
                    buttons[int(button)] = (int(action) & 0x00FFFFFF) | ((int(type_) & 0xFF) << 24)
            except Exception:
                continue

        try:
            saved_rows = (
                session.query(CharacterAction.button, CharacterAction.action, CharacterAction.type_)
                .filter(
                    CharacterAction.guid == int(char_guid),
                    CharacterAction.spec == 0,
                )
                .all()
            )
        except Exception as exc:
            Logger.warning(f"[DB] character_action lookup failed guid={char_guid}: {exc}")
            saved_rows = []

        for button, action, type_ in saved_rows:
            try:
                button_index = int(button)
                if not (0 <= button_index < 132):
                    continue
                buttons[button_index] = (
                    (int(action) & 0x00FFFFFF) | ((int(type_) & 0xFF) << 24)
                ) if int(action) > 0 else 0
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
    def save_character_action_button(guid: int, button: int, action: int, type_: int, *, spec: int = 0) -> bool:
        session = DatabaseConnection.chars()
        guid = int(guid)
        button = int(button)
        action = int(action)
        type_ = int(type_)
        spec = int(spec)

        try:
            row = (
                session.query(CharacterAction)
                .filter(
                    CharacterAction.guid == guid,
                    CharacterAction.spec == spec,
                    CharacterAction.button == button,
                )
                .one_or_none()
            )

            if action <= 0:
                if row is not None:
                    session.delete(row)
            else:
                if row is None:
                    row = CharacterAction(
                        guid=guid,
                        spec=spec,
                        button=button,
                        action=action,
                        type_=type_,
                    )
                    session.add(row)
                else:
                    row.action = action
                    row.type_ = type_

            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            Logger.error(
                f"[DB] save_character_action_button failed guid={guid} button={button} "
                f"action={action} type={type_}: {exc}"
            )
            return False

    @staticmethod
    def ensure_character_spells(guid: int, spell_ids: list[int] | tuple[int, ...] | set[int]) -> list[int]:
        session = DatabaseConnection.chars()
        guid = int(guid)
        desired = sorted(
            {
                int(spell_id)
                for spell_id in (spell_ids or [])
                if int(spell_id or 0) > 0
            }
        )
        if guid <= 0 or not desired:
            return []

        try:
            existing_rows = (
                session.query(CharacterSpell.spell)
                .filter(
                    CharacterSpell.guid == guid,
                    CharacterSpell.spell.in_(desired),
                    CharacterSpell.disabled == 0,
                )
                .all()
            )
            existing = {int(row[0]) for row in existing_rows}
            missing = [spell_id for spell_id in desired if spell_id not in existing]
            if not missing:
                return []

            session.add_all(
                CharacterSpell(
                    guid=guid,
                    spell=int(spell_id),
                    active=1,
                    disabled=0,
                    spec=0,
                    spec_mask=0,
                )
                for spell_id in missing
            )
            session.commit()
            return missing
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] ensure_character_spells failed guid={guid}: {exc}")
            return []

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
    

    @staticmethod
    def get_areatrigger_teleport(trigger_id: int) -> dict | None:
        session = DatabaseConnection.world()

        try:
            row = session.execute(text(
                """
                SELECT
                    name,
                    target_map,
                    target_position_x,
                    target_position_y,
                    target_position_z,
                    target_orientation
                FROM areatrigger_teleport
                WHERE id = :id
                LIMIT 1
                """),
                {"id": int(trigger_id)},
            ).mappings().first()

            return dict(row) if row else None

        finally:
            session.close()

    # SRP helpers
    @staticmethod
    def update_sessionkey_old(account, key_bytes):
        return AuthConnection.update_sessionkey(account, key_bytes)

    @staticmethod
    def update_verifier_and_salt_old(account, verifier, salt):
        return AuthConnection.update_verifier(account, verifier, salt)
    
    # ACCOUNT ORM HELPERS
    @staticmethod
    def create_or_update_account_old(username, salt, verifier):
        return AuthConnection.create_or_update_account(username, salt, verifier)

    @staticmethod
    def set_gmlevel_old(account_id, gmlevel):
        return AuthConnection.set_gmlevel(account_id, gmlevel)
    



DatabaseConnection.auth = staticmethod(DatabaseConnection.auth_old)
DatabaseConnection.get_user_by_username = staticmethod(DatabaseConnection.get_user_by_username_old)
DatabaseConnection.get_account_id_by_username = staticmethod(
    DatabaseConnection.get_account_id_by_username_old
)
DatabaseConnection.get_realmlist = staticmethod(DatabaseConnection.get_realmlist_old)
DatabaseConnection.get_all_realms = staticmethod(DatabaseConnection.get_all_realms_old)
DatabaseConnection.update_sessionkey = staticmethod(DatabaseConnection.update_sessionkey_old)
DatabaseConnection.update_verifier_and_salt = staticmethod(
    DatabaseConnection.update_verifier_and_salt_old
)
DatabaseConnection.create_or_update_account = staticmethod(
    DatabaseConnection.create_or_update_account_old
)
DatabaseConnection.set_gmlevel = staticmethod(DatabaseConnection.set_gmlevel_old)
