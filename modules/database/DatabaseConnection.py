#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from hashlib import md5
import math

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

from server.modules.database.AuthModel import Account


ACTION_BUTTON_COUNT = 132
PRIMARY_ACTION_BAR_SLOTS = 12
ACTION_BUTTON_TYPE_SPELL = 0

_ACTION_BUTTON_LANGUAGE_SPELLS = {
    668,
    669,
    670,
    671,
    672,
    7340,
    7341,
    813,
    17737,
    29932,
    108127,
    108130,
    108131,
}
_ACTION_BUTTON_PASSIVE_OR_SYSTEM_SPELLS = {
    81,
    201,
    203,
    204,
    227,
    522,
    2382,
    3050,
    3365,
    5009,
    5019,
    6233,
    6246,
    6247,
    6477,
    6478,
    7355,
    8386,
    9078,
    9125,
    21651,
    21652,
    22027,
    22810,
    28877,
    45927,
    61437,
    68398,
    71761,
    76276,
    76298,
    79684,
    79748,
    85801,
    92315,
    96220,
    111621,
    113873,
}
_ACTION_BUTTON_EXCLUDED_SPELLS = _ACTION_BUTTON_LANGUAGE_SPELLS | _ACTION_BUTTON_PASSIVE_OR_SYSTEM_SPELLS
_ACTION_BUTTON_PRIORITY_SPELLS = (
    44614,  # Frostfire Bolt
    6603,   # Attack
    28730,  # Arcane Torrent
)


def _battle_pet_action_excluded_spells() -> set[int]:
    try:
        from server.modules.handlers.world.pet.pet_service import battle_pet_summon_spells
    except Exception:
        return set()
    return set(int(spell_id) for spell_id in battle_pet_summon_spells())


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
    _cache_spell_target_positions: dict[tuple[int, int], dict] = {}
    _account_data_tables_ready = False
    _addon_tables_ready = False
    _mount_state_table_ready = False
    _achievement_tables_ready = False
    _gameobject_scale_column_ready = False
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
        from server.modules.handlers.world.collision import clear_gameobject_collision_index
        from server.modules.handlers.world.runtime.gameobject_store import (
            get_gameobject_runtime_store,
        )
        from server.modules.handlers.world.runtime.creature_store import (
            get_creature_runtime_store,
        )

        clear_gameobject_collision_index()
        get_creature_runtime_store().clear()
        get_gameobject_runtime_store().clear()
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
        DatabaseConnection._mount_state_table_ready = False
        DatabaseConnection._achievement_tables_ready = False
        DatabaseConnection._gameobject_scale_column_ready = False

    @staticmethod
    def _ensure_gameobject_scale_column() -> None:
        if DatabaseConnection._gameobject_scale_column_ready:
            return
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable while ensuring gameobject.scale: {exc}")
            return
        try:
            exists = session.execute(
                text(
                    "SELECT COUNT(*) FROM information_schema.COLUMNS "
                    "WHERE TABLE_SCHEMA = DATABASE() "
                    "AND TABLE_NAME = 'gameobject' "
                    "AND COLUMN_NAME = 'scale'"
                )
            ).scalar()
            if int(exists or 0) <= 0:
                session.execute(text("ALTER TABLE gameobject ADD COLUMN scale FLOAT NOT NULL DEFAULT 1.0"))
                session.commit()
                Logger.info("[DB] added gameobject.scale column")
            DatabaseConnection._gameobject_scale_column_ready = True
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] failed ensuring gameobject.scale column: {exc}")

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

    @staticmethod
    def initialize_auth():
        """Initialize auth database only. Used by AuthServer."""
        config = ConfigLoader.load_config()
        db = config["database"]

        # Reuse existing auth session if already initialized
        if AuthConnection._auth_session is not None:
            return

        auth_db = db.get("auth_db")
        if not auth_db:
            raise RuntimeError("Missing auth_db in database configuration")

        auth_url = (
            f"mysql+pymysql://{db['username']}:{db['password']}@"
            f"{db['host']}:{db['port']}/{auth_db}?charset=utf8"
        )

        AuthConnection._auth_engine = create_engine(
            auth_url,
            pool_pre_ping=True
        )

        AuthConnection._auth_session = scoped_session(
            sessionmaker(
                bind=AuthConnection._auth_engine,
                autoflush=False
            )
        )

        AuthConnection._auth_db_name = auth_db

        Logger.info("Auth database initialized")

    @staticmethod
    def initialize_characters():
        """Initialize characters database only. Used by AuthServer realm list."""
        config = ConfigLoader.load_config()
        db = config["database"]

        # Reuse existing characters session if already initialized
        if DatabaseConnection._char_session is not None:
            return

        characters_db = db.get("characters_db")
        if not characters_db:
            raise RuntimeError("Missing characters_db in database configuration")

        char_url = (
            f"mysql+pymysql://{db['username']}:{db['password']}@"
            f"{db['host']}:{db['port']}/{characters_db}?charset=utf8"
        )

        DatabaseConnection._char_engine = create_engine(
            char_url,
            pool_pre_ping=True
        )

        DatabaseConnection._char_session = scoped_session(
            sessionmaker(
                bind=DatabaseConnection._char_engine,
                autoflush=False
            )
        )

        DatabaseConnection._characters_db_name = characters_db

        Logger.info("Characters database initialized")


    @classmethod
    def get_all_auth_accounts(cls):
        """
        Return all auth accounts used for login cache preload.
        """

        return cls.auth().query(Account).all()


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
                try:
                    DatabaseConnection._populate_creature_runtime_store(
                        by_map,
                        DatabaseConnection._cache_creature_templates,
                    )
                except Exception as exc:
                    Logger.warning(f"[DB] creature runtime mirror failed: {exc}")
                    from server.modules.handlers.world.runtime.creature_store import (
                        get_creature_runtime_store,
                    )

                    get_creature_runtime_store().clear()
                Logger.info(
                    "[DB] preloaded %s creature spawns across %s maps",
                    sum(len(entries) for entries in by_map.values()),
                    len(by_map),
                )
            except Exception as exc:
                Logger.warning(f"[DB] creature preload failed: {exc}")
                DatabaseConnection._cache_creatures_by_map = {}
                DatabaseConnection._cache_creatures_loaded = False
                from server.modules.handlers.world.runtime.creature_store import (
                    get_creature_runtime_store,
                )

                get_creature_runtime_store().clear()
        else:
            DatabaseConnection._cache_creature_templates = {}
            DatabaseConnection._cache_creatures_by_map = {}
            DatabaseConnection._cache_creatures_loaded = False
            from server.modules.handlers.world.runtime.creature_store import (
                get_creature_runtime_store,
            )

            get_creature_runtime_store().clear()
            Logger.info("[DB] creature preload disabled by config")

        preload_gameobjects = bool(
            ConfigLoader.load_config().get("worldserver", {}).get("preload_gameobjects", True)
        )
        if preload_gameobjects:
            DatabaseConnection._ensure_gameobject_scale_column()
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
                        WorldGameObject.scale,
                        WorldGameObjectTemplate.type,
                        WorldGameObjectTemplate.displayId,
                        WorldGameObjectTemplate.name,
                        WorldGameObjectTemplate.faction,
                        WorldGameObjectTemplate.flags,
                        WorldGameObjectTemplate.size,
                        *[
                            getattr(WorldGameObjectTemplate, f"data{index}")
                            for index in range(24)
                        ],
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
                try:
                    DatabaseConnection._populate_gameobject_runtime_store(by_map)
                except Exception as exc:
                    Logger.warning(f"[DB] gameobject runtime mirror failed: {exc}")
                    from server.modules.handlers.world.runtime.gameobject_store import (
                        get_gameobject_runtime_store,
                    )

                    get_gameobject_runtime_store().clear()
                from server.modules.handlers.world.collision import build_gameobject_collision_index
                build_gameobject_collision_index(by_map)
                Logger.info(
                    "[DB] preloaded %s gameobjects across %s maps",
                    sum(len(entries) for entries in by_map.values()),
                    len(by_map),
                )
            except Exception as exc:
                Logger.warning(f"[DB] gameobject preload failed: {exc}")
                DatabaseConnection._cache_gameobjects_by_map = {}
                DatabaseConnection._cache_gameobjects_loaded = False
                from server.modules.handlers.world.runtime.gameobject_store import (
                    get_gameobject_runtime_store,
                )

                get_gameobject_runtime_store().clear()
                from server.modules.handlers.world.collision import clear_gameobject_collision_index
                clear_gameobject_collision_index()
        else:
            DatabaseConnection._cache_gameobjects_by_map = {}
            DatabaseConnection._cache_gameobjects_loaded = False
            from server.modules.handlers.world.runtime.gameobject_store import (
                get_gameobject_runtime_store,
            )

            get_gameobject_runtime_store().clear()
            from server.modules.handlers.world.collision import clear_gameobject_collision_index
            clear_gameobject_collision_index()
            Logger.info("[DB] gameobject preload disabled by config")

        if item_entries:
            DatabaseConnection.get_item_template_map(list(item_entries))

        DatabaseConnection._world_cache_loaded = True
        Logger.info("Database cache preloaded")

    @staticmethod
    def reload_world_cache() -> None:
        from server.modules.handlers.world.runtime.creature_store import (
            get_creature_runtime_store,
        )
        from server.modules.handlers.world.runtime.gameobject_store import (
            get_gameobject_runtime_store,
        )

        get_creature_runtime_store().clear()
        get_gameobject_runtime_store().clear()
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

    @staticmethod
    def _populate_creature_runtime_store(
        entries_by_map: dict[int, list[dict]],
        templates_by_entry: dict[int, dict] | None = None,
    ) -> None:
        """Mirror authoritative Creature cache entries into runtime objects."""
        from server.modules.game.guid import CreatureGuid
        from server.modules.handlers.world.runtime.creature import Creature
        from server.modules.handlers.world.runtime.creature_store import (
            get_creature_runtime_store,
        )

        templates = templates_by_entry if isinstance(templates_by_entry, dict) else {}
        store = get_creature_runtime_store()
        store.clear()
        for entries in entries_by_map.values():
            for entry in entries or ():
                runtime_mapping = dict(entry)
                template = templates.get(int(runtime_mapping.get("entry", 0) or 0))
                if isinstance(template, dict):
                    runtime_mapping["template"] = template
                spawn_id = int(runtime_mapping.get("guid", 0) or 0)
                world_guid = int(runtime_mapping.get("world_guid", 0) or 0)
                if world_guid <= 0:
                    realm_id = int(runtime_mapping.get("realm_id", 1) or 1)
                    world_guid = int(
                        CreatureGuid.from_spawn_guid(spawn_id, realm_id)
                    )
                store.add(
                    Creature.from_mapping(
                        runtime_mapping,
                        runtime_guid=world_guid,
                    )
                )

    @staticmethod
    def _populate_gameobject_runtime_store(entries_by_map: dict[int, list[dict]]) -> None:
        """Mirror authoritative persistent cache entries into runtime objects."""
        from server.modules.game.guid import GameObjectGuid, MoTransportGuid
        from server.modules.handlers.world.runtime.gameobject import GameObject
        from server.modules.handlers.world.runtime.gameobject_store import (
            get_gameobject_runtime_store,
        )

        store = get_gameobject_runtime_store()
        store.clear()
        for entries in entries_by_map.values():
            for entry in entries or ():
                spawn_id = int(entry.get("guid", 0) or 0)
                world_guid = int(entry.get("world_guid", 0) or 0)
                if world_guid <= 0:
                    go_type = int(entry.get("type", -1) or -1)
                    if go_type == 15 or bool(entry.get("use_transport_guid")):
                        world_guid = int(MoTransportGuid.from_spawn_guid(spawn_id))
                    else:
                        realm_id = int(entry.get("realm_id", 1) or 1)
                        world_guid = int(GameObjectGuid.from_spawn_guid(spawn_id, realm_id))
                store.add(GameObject.from_mapping(entry, runtime_guid=world_guid))

    # AUTH DB SESSION
    @staticmethod
    def auth():
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
    def _ensure_mount_state_table() -> bool:
        if DatabaseConnection._mount_state_table_ready:
            return True

        session = DatabaseConnection.chars()
        try:
            session.execute(text(
                """
                CREATE TABLE IF NOT EXISTS character_mount_state (
                    guid INT UNSIGNED NOT NULL,
                    realm INT UNSIGNED NOT NULL DEFAULT 0,
                    spell INT UNSIGNED NOT NULL DEFAULT 0,
                    display_id INT UNSIGNED NOT NULL DEFAULT 0,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                        ON UPDATE CURRENT_TIMESTAMP,
                    PRIMARY KEY (guid, realm)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3
                """
            ))
            session.commit()
            DatabaseConnection._mount_state_table_ready = True
            return True
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] ensure mount-state table failed: {exc}")
            return False

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
    def ensure_character_homebind_table() -> bool:
        """Ensure the minimal homebind table used by innkeeper binding exists."""
        session = DatabaseConnection.chars()
        try:
            session.execute(text("""
                CREATE TABLE IF NOT EXISTS character_homebind (
                    guid INT UNSIGNED NOT NULL,
                    mapId SMALLINT UNSIGNED NOT NULL DEFAULT 0,
                    zoneId SMALLINT UNSIGNED NOT NULL DEFAULT 0,
                    posX FLOAT NOT NULL DEFAULT 0,
                    posY FLOAT NOT NULL DEFAULT 0,
                    posZ FLOAT NOT NULL DEFAULT 0,
                    orientation FLOAT NOT NULL DEFAULT 0,
                    PRIMARY KEY (guid)
                )
            """))
            session.commit()
        except Exception as exc:
            session.rollback()
            Logger.warning("[DB] character_homebind create failed: %s", exc)
            return False

        try:
            session.execute(text(
                "ALTER TABLE character_homebind "
                "ADD COLUMN orientation FLOAT NOT NULL DEFAULT 0"
            ))
            session.commit()
        except Exception:
            session.rollback()

        return True

    @staticmethod
    def load_character_homebind(char_guid: int, realm_id: int = 0) -> dict | None:
        """Load a character homebind row if one exists."""
        _ = int(realm_id or 0)
        if int(char_guid or 0) <= 0:
            return None

        if not DatabaseConnection.ensure_character_homebind_table():
            return None

        session = DatabaseConnection.chars()
        try:
            row = session.execute(
                text("""
                    SELECT guid, mapId, zoneId, posX, posY, posZ, orientation
                    FROM character_homebind
                    WHERE guid = :guid
                    LIMIT 1
                """),
                {"guid": int(char_guid)},
            ).mappings().first()
            if row is None:
                return None
            return dict(row)
        except Exception as exc:
            Logger.warning(
                "[DB] load_character_homebind failed guid=%s realm=%s: %s",
                int(char_guid),
                int(realm_id or 0),
                exc,
            )
            return None

    @staticmethod
    def save_character_homebind(
        char_guid: int,
        realm_id: int,
        *,
        map_id: int,
        zone_id: int,
        x: float,
        y: float,
        z: float,
        orientation: float,
    ) -> bool:
        """Persist the player's Hearthstone bind point."""
        _ = int(realm_id or 0)
        if int(char_guid or 0) <= 0:
            return False

        if not DatabaseConnection.ensure_character_homebind_table():
            return False

        session = DatabaseConnection.chars()
        try:
            session.execute(
                text("""
                    INSERT INTO character_homebind
                        (guid, mapId, zoneId, posX, posY, posZ, orientation)
                    VALUES
                        (:guid, :map_id, :zone_id, :x, :y, :z, :orientation)
                    ON DUPLICATE KEY UPDATE
                        mapId = VALUES(mapId),
                        zoneId = VALUES(zoneId),
                        posX = VALUES(posX),
                        posY = VALUES(posY),
                        posZ = VALUES(posZ),
                        orientation = VALUES(orientation)
                """),
                {
                    "guid": int(char_guid),
                    "map_id": int(map_id or 0),
                    "zone_id": int(zone_id or 0),
                    "x": float(x or 0.0),
                    "y": float(y or 0.0),
                    "z": float(z or 0.0),
                    "orientation": float(orientation or 0.0),
                },
            )
            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            Logger.warning(
                "[DB] save_character_homebind failed guid=%s realm=%s: %s",
                int(char_guid),
                int(realm_id or 0),
                exc,
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
    def load_character_mount_state(char_guid: int, realm_id: int) -> dict | None:
        """Return persisted mount state for a character, if one exists."""
        if int(char_guid or 0) <= 0:
            return None
        if not DatabaseConnection._ensure_mount_state_table():
            return None

        session = DatabaseConnection.chars()
        try:
            row = session.execute(
                text(
                    """
                    SELECT spell, display_id
                    FROM character_mount_state
                    WHERE guid = :guid AND realm = :realm
                    LIMIT 1
                    """
                ),
                {"guid": int(char_guid), "realm": int(realm_id or 0)},
            ).mappings().first()
        except Exception as exc:
            Logger.warning(f"[DB] load_character_mount_state failed guid={char_guid}: {exc}")
            return None

        if row is None:
            return None
        return {
            "spell": int(row.get("spell") or 0),
            "display_id": int(row.get("display_id") or 0),
        }

    @staticmethod
    def save_character_mount_state(
        char_guid: int,
        realm_id: int,
        *,
        spell_id: int,
        display_id: int,
    ) -> bool:
        """Persist current mounted state. Invalid zero state is ignored."""
        if int(char_guid or 0) <= 0 or int(spell_id or 0) <= 0 or int(display_id or 0) <= 0:
            return False
        if not DatabaseConnection._ensure_mount_state_table():
            return False

        session = DatabaseConnection.chars()
        try:
            session.execute(
                text(
                    """
                    INSERT INTO character_mount_state (guid, realm, spell, display_id)
                    VALUES (:guid, :realm, :spell, :display_id)
                    ON DUPLICATE KEY UPDATE
                        spell = VALUES(spell),
                        display_id = VALUES(display_id)
                    """
                ),
                {
                    "guid": int(char_guid),
                    "realm": int(realm_id or 0),
                    "spell": int(spell_id),
                    "display_id": int(display_id),
                },
            )
            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] save_character_mount_state failed guid={char_guid}: {exc}")
            return False

    @staticmethod
    def clear_character_mount_state(char_guid: int, realm_id: int) -> bool:
        """Forget persisted mount state for explicit dismounts and teleports."""
        if int(char_guid or 0) <= 0:
            return True
        if not DatabaseConnection._ensure_mount_state_table():
            return False

        session = DatabaseConnection.chars()
        try:
            session.execute(
                text(
                    """
                    DELETE FROM character_mount_state
                    WHERE guid = :guid AND realm = :realm
                    """
                ),
                {"guid": int(char_guid), "realm": int(realm_id or 0)},
            )
            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] clear_character_mount_state failed guid={char_guid}: {exc}")
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
    def get_server_motd() -> str:
        """Read MOTD directly from DB. This intentionally does not cache the value."""
        try:
            session = DatabaseConnection.chars()
            session.rollback()
            DatabaseConnection._ensure_server_motd_table(session)
            row = session.execute(
                text("SELECT message FROM server_motd WHERE id = 1 LIMIT 1")
            ).mappings().first()
            motd = str((row or {}).get("message", "") or "").strip()
            session.rollback()
            return motd
        except Exception as exc:
            try:
                session.rollback()
            except Exception:
                pass
            Logger.warning(f"[DB] get_server_motd failed: {exc}")

        return ""

    @staticmethod
    def set_server_motd(message: str) -> bool:
        normalized = str(message or "").strip()
        session = DatabaseConnection.chars()
        try:
            DatabaseConnection._ensure_server_motd_table(session)
            session.execute(
                text(
                    "INSERT INTO server_motd (id, message) VALUES (1, :message) "
                    "ON DUPLICATE KEY UPDATE message = VALUES(message)"
                ),
                {"message": normalized},
            )
            session.commit()
            session.expire_all()
            return True
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] set_server_motd failed: {exc}")
            return False

    @staticmethod
    def _ensure_server_motd_table(session) -> None:
        session.execute(
            text(
                "CREATE TABLE IF NOT EXISTS server_motd ("
                "id TINYINT UNSIGNED NOT NULL PRIMARY KEY, "
                "message TEXT NOT NULL"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            )
        )

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
    def save_character_taximask(char_guid: int, realm_id: int, taximask: str) -> bool:
        session = DatabaseConnection.chars()
        try:
            updated = (
                session.query(Characters)
                .filter(
                    Characters.guid == int(char_guid),
                    Characters.realm == int(realm_id),
                )
                .update({Characters.taximask: str(taximask or "")}, synchronize_session=False)
            )
            session.commit()
            if updated <= 0:
                Logger.warning(
                    f"[DB] save_character_taximask missing character guid={char_guid} realm={realm_id}"
                )
                return False
            return True
        except Exception as exc:
            session.rollback()
            Logger.error(
                f"[DB] save_character_taximask failed guid={char_guid} realm={realm_id}: {exc}"
            )
            return False

    @staticmethod
    def ensure_character_achievement_tables() -> bool:
        if DatabaseConnection._achievement_tables_ready:
            return True

        session = DatabaseConnection.chars()
        try:
            session.execute(text("""
                CREATE TABLE IF NOT EXISTS character_exploration (
                    guid BIGINT UNSIGNED NOT NULL,
                    realm INT UNSIGNED NOT NULL DEFAULT 1,
                    area_id INT UNSIGNED NOT NULL,
                    discovered_at INT UNSIGNED NOT NULL DEFAULT 0,
                    PRIMARY KEY (guid, realm, area_id),
                    KEY idx_character_exploration_area (area_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """))
            session.execute(text("""
                CREATE TABLE IF NOT EXISTS character_criteria_progress (
                    guid BIGINT UNSIGNED NOT NULL,
                    realm INT UNSIGNED NOT NULL DEFAULT 1,
                    criteria_id INT UNSIGNED NOT NULL,
                    counter BIGINT UNSIGNED NOT NULL DEFAULT 0,
                    completed_at INT UNSIGNED NOT NULL DEFAULT 0,
                    PRIMARY KEY (guid, realm, criteria_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """))
            session.execute(text("""
                CREATE TABLE IF NOT EXISTS character_achievement_completed (
                    guid BIGINT UNSIGNED NOT NULL,
                    realm INT UNSIGNED NOT NULL DEFAULT 1,
                    achievement_id INT UNSIGNED NOT NULL,
                    completed TINYINT UNSIGNED NOT NULL DEFAULT 0,
                    completion_time INT UNSIGNED NOT NULL DEFAULT 0,
                    PRIMARY KEY (guid, realm, achievement_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """))
            session.commit()
            DatabaseConnection._achievement_tables_ready = True
            return True
        except Exception as exc:
            session.rollback()
            Logger.error(f"[DB] ensure_character_achievement_tables failed: {exc}")
            return False

    @staticmethod
    def load_character_exploration(char_guid: int, realm_id: int) -> dict[int, int]:
        if not DatabaseConnection.ensure_character_achievement_tables():
            return {}
        session = DatabaseConnection.chars()
        try:
            rows = session.execute(
                text("""
                    SELECT area_id, discovered_at
                    FROM character_exploration
                    WHERE guid = :guid AND realm = :realm
                """),
                {"guid": int(char_guid), "realm": int(realm_id)},
            ).fetchall()
            return {int(row[0]): int(row[1] or 0) for row in rows}
        except Exception as exc:
            Logger.error(
                f"[DB] load_character_exploration failed guid={char_guid} realm={realm_id}: {exc}"
            )
            return {}

    @staticmethod
    def save_character_exploration(
        char_guid: int,
        realm_id: int,
        area_id: int,
        discovered_at: int,
    ) -> bool:
        if not DatabaseConnection.ensure_character_achievement_tables():
            return False
        session = DatabaseConnection.chars()
        try:
            session.execute(
                text("""
                    INSERT INTO character_exploration
                        (guid, realm, area_id, discovered_at)
                    VALUES
                        (:guid, :realm, :area_id, :discovered_at)
                    ON DUPLICATE KEY UPDATE
                        discovered_at = LEAST(discovered_at, VALUES(discovered_at))
                """),
                {
                    "guid": int(char_guid),
                    "realm": int(realm_id),
                    "area_id": int(area_id),
                    "discovered_at": int(discovered_at),
                },
            )
            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            Logger.error(
                f"[DB] save_character_exploration failed guid={char_guid} realm={realm_id} "
                f"area={area_id}: {exc}"
            )
            return False

    @staticmethod
    def load_character_criteria_progress(char_guid: int, realm_id: int) -> dict[int, dict]:
        if not DatabaseConnection.ensure_character_achievement_tables():
            return {}
        session = DatabaseConnection.chars()
        try:
            rows = session.execute(
                text("""
                    SELECT criteria_id, counter, completed_at
                    FROM character_criteria_progress
                    WHERE guid = :guid AND realm = :realm
                """),
                {"guid": int(char_guid), "realm": int(realm_id)},
            ).fetchall()
            return {
                int(row[0]): {
                    "counter": int(row[1] or 0),
                    "completed_at": int(row[2] or 0),
                }
                for row in rows
            }
        except Exception as exc:
            Logger.error(
                f"[DB] load_character_criteria_progress failed guid={char_guid} "
                f"realm={realm_id}: {exc}"
            )
            return {}

    @staticmethod
    def save_character_criteria_progress(
        char_guid: int,
        realm_id: int,
        criteria_id: int,
        counter: int,
        completed_at: int,
    ) -> bool:
        if not DatabaseConnection.ensure_character_achievement_tables():
            return False
        session = DatabaseConnection.chars()
        try:
            session.execute(
                text("""
                    INSERT INTO character_criteria_progress
                        (guid, realm, criteria_id, counter, completed_at)
                    VALUES
                        (:guid, :realm, :criteria_id, :counter, :completed_at)
                    ON DUPLICATE KEY UPDATE
                        counter = GREATEST(counter, VALUES(counter)),
                        completed_at = IF(completed_at = 0, VALUES(completed_at), completed_at)
                """),
                {
                    "guid": int(char_guid),
                    "realm": int(realm_id),
                    "criteria_id": int(criteria_id),
                    "counter": int(counter),
                    "completed_at": int(completed_at),
                },
            )
            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            Logger.error(
                f"[DB] save_character_criteria_progress failed guid={char_guid} "
                f"realm={realm_id} criteria={criteria_id}: {exc}"
            )
            return False

    @staticmethod
    def load_character_achievement_progress(char_guid: int, realm_id: int) -> dict[int, int]:
        if not DatabaseConnection.ensure_character_achievement_tables():
            return {}
        session = DatabaseConnection.chars()
        try:
            rows = session.execute(
                text("""
                    SELECT achievement_id, completion_time
                    FROM character_achievement_completed
                    WHERE guid = :guid AND realm = :realm AND completed = 1
                """),
                {"guid": int(char_guid), "realm": int(realm_id)},
            ).fetchall()
            return {int(row[0]): int(row[1] or 0) for row in rows}
        except Exception as exc:
            Logger.error(
                f"[DB] load_character_achievement_progress failed guid={char_guid} "
                f"realm={realm_id}: {exc}"
            )
            return {}

    @staticmethod
    def save_character_achievement_progress(
        char_guid: int,
        realm_id: int,
        achievement_id: int,
        completion_time: int,
    ) -> bool:
        if not DatabaseConnection.ensure_character_achievement_tables():
            return False
        session = DatabaseConnection.chars()
        try:
            session.execute(
                text("""
                    INSERT INTO character_achievement_completed
                        (guid, realm, achievement_id, completed, completion_time)
                    VALUES
                        (:guid, :realm, :achievement_id, 1, :completion_time)
                    ON DUPLICATE KEY UPDATE
                        completed = 1,
                        completion_time = IF(completion_time = 0, VALUES(completion_time), completion_time)
                """),
                {
                    "guid": int(char_guid),
                    "realm": int(realm_id),
                    "achievement_id": int(achievement_id),
                    "completion_time": int(completion_time),
                },
            )
            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            Logger.error(
                f"[DB] save_character_achievement_progress failed guid={char_guid} "
                f"realm={realm_id} achievement={achievement_id}: {exc}"
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
                npcflag,
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
    def get_gameobject_template(entry: int) -> dict | None:
        if int(entry or 0) <= 0:
            return None

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return None

        data_columns = ",\n                ".join(f"data{i}" for i in range(24))
        quest_columns = ",\n                ".join(f"questItem{i}" for i in range(1, 7))
        stmt = text(
            f"""
            SELECT
                entry,
                type,
                displayId,
                name,
                IconName,
                castBarCaption,
                unk1,
                {data_columns},
                size,
                {quest_columns},
                unkInt32
            FROM gameobject_template
            WHERE entry = :entry
            LIMIT 1
            """
        )
        try:
            row = session.execute(stmt, {"entry": int(entry)}).mappings().first()
        except Exception as exc:
            Logger.warning(f"[DB] gameobject_template lookup failed for entry={entry}: {exc}")
            return None

        if row is None:
            return None
        return dict(row)

    @staticmethod
    def search_gameobject_templates(search_text: str, *, limit: int = 20) -> list[dict]:
        needle = str(search_text or "").strip()
        if not needle:
            return []
        limit = max(1, min(int(limit or 20), 100))

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return []

        stmt = text(
            """
            SELECT
                entry,
                name,
                type
            FROM gameobject_template
            WHERE LOWER(name) LIKE LOWER(:needle)
            ORDER BY LOWER(name), entry
            LIMIT :limit
            """
        )
        try:
            rows = session.execute(
                stmt,
                {
                    "needle": f"%{needle}%",
                    "limit": int(limit),
                },
            ).mappings().all()
        except Exception as exc:
            Logger.warning(f"[DB] gameobject_template search failed text={needle!r}: {exc}")
            return []

        return [dict(row) for row in rows]

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
    def search_creature_templates(search_text: str, *, limit: int = 20) -> list[dict]:
        needle = str(search_text or "").strip()
        if not needle:
            return []
        limit = max(1, min(int(limit or 20), 100))

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return []

        stmt = text(
            """
            SELECT
                entry,
                name,
                type
            FROM creature_template
            WHERE LOWER(name) LIKE LOWER(:needle)
            ORDER BY LOWER(name), entry
            LIMIT :limit
            """
        )
        try:
            rows = session.execute(
                stmt,
                {
                    "needle": f"%{needle}%",
                    "limit": int(limit),
                },
            ).mappings().all()
        except Exception as exc:
            Logger.warning(f"[DB] creature_template search failed text={needle!r}: {exc}")
            return []
        finally:
            session.close()

        return [dict(row) for row in rows]

    @staticmethod
    def get_creature_spawn(spawn_guid: int) -> dict | None:
        if int(spawn_guid or 0) <= 0:
            return None

        if DatabaseConnection._world_cache_loaded and DatabaseConnection._cache_creatures_loaded:
            for entries in (DatabaseConnection._cache_creatures_by_map or {}).values():
                for entry in entries or ():
                    if int(entry.get("guid", 0) or 0) == int(spawn_guid):
                        return dict(entry)

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return None

        try:
            row = (
                session.query(WorldCreature)
                .filter(WorldCreature.guid == int(spawn_guid))
                .first()
            )
        except Exception as exc:
            Logger.warning(f"[DB] creature spawn lookup failed guid={spawn_guid}: {exc}")
            return None
        finally:
            session.close()

        if row is None:
            return None
        return DatabaseConnection._build_creature_candidate(row)

    @staticmethod
    def _cache_remove_creature_spawn(spawn_guid: int) -> None:
        cache_by_map = getattr(DatabaseConnection, "_cache_creatures_by_map", None)
        if not isinstance(cache_by_map, dict):
            return
        for map_id, entries in list(cache_by_map.items()):
            cache_by_map[int(map_id)] = [
                dict(entry)
                for entry in (entries or ())
                if int(entry.get("guid", 0) or 0) != int(spawn_guid)
            ]

    @staticmethod
    def _cache_restore_creature_spawn(entry: dict) -> None:
        cache_by_map = getattr(DatabaseConnection, "_cache_creatures_by_map", None)
        if not isinstance(cache_by_map, dict):
            return
        spawn_guid = int(entry.get("guid", 0) or 0)
        map_id = int(entry.get("map_id", entry.get("map", 0)) or 0)
        if spawn_guid <= 0:
            return
        DatabaseConnection._cache_remove_creature_spawn(spawn_guid)
        cache_by_map.setdefault(map_id, []).append(dict(entry))

    @staticmethod
    def delete_creature_spawn(spawn_guid: int) -> dict | None:
        existing = DatabaseConnection.get_creature_spawn(int(spawn_guid))
        if existing is None:
            return None

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return None

        try:
            deleted = (
                session.query(WorldCreature)
                .filter(WorldCreature.guid == int(spawn_guid))
                .delete(synchronize_session=False)
            )
            if int(deleted or 0) <= 0:
                session.rollback()
                return None
            session.commit()
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] creature delete failed guid={spawn_guid}: {exc}")
            return None
        finally:
            session.close()

        DatabaseConnection._cache_remove_creature_spawn(int(spawn_guid))
        return dict(existing)

    @staticmethod
    def restore_creature_spawn(entry: dict) -> bool:
        if not isinstance(entry, dict):
            return False
        spawn_guid = int(entry.get("guid", 0) or 0)
        creature_entry = int(entry.get("entry", 0) or 0)
        if spawn_guid <= 0 or creature_entry <= 0:
            return False

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return False

        try:
            existing = session.query(WorldCreature).filter(WorldCreature.guid == spawn_guid).first()
            if existing is not None:
                session.delete(existing)
                session.flush()
            row = WorldCreature(
                guid=spawn_guid,
                id=creature_entry,
                map=int(entry.get("map_id", entry.get("map", 0)) or 0),
                spawnMask=int(entry.get("spawnMask", 1) or 1),
                phaseId=int(entry.get("phaseId", 0) or 0),
                phaseGroup=int(entry.get("phaseGroup", 0) or 0),
                modelid=int(entry.get("modelid", 0) or 0),
                equipment_id=int(entry.get("equipment_id", 0) or 0),
                position_x=float(entry.get("x", 0.0) or 0.0),
                position_y=float(entry.get("y", 0.0) or 0.0),
                position_z=float(entry.get("z", 0.0) or 0.0),
                orientation=float(entry.get("orientation", 0.0) or 0.0),
                spawntimesecs=int(entry.get("spawntimesecs", 300) or 0),
                spawndist=float(entry.get("spawndist", 0.0) or 0.0),
                currentwaypoint=int(entry.get("currentwaypoint", 0) or 0),
                curhealth=int(entry.get("curhealth", 1) or 1),
                curmana=int(entry.get("curmana", 0) or 0),
                MovementType=int(entry.get("movement_type", entry.get("MovementType", 0)) or 0),
                npcflag=int(entry.get("npcflag", 0) or 0),
                unit_flags=int(entry.get("unit_flags", 0) or 0),
                dynamicflags=int(entry.get("dynamicflags", 0) or 0),
            )
            session.add(row)
            session.commit()
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] creature restore failed guid={spawn_guid}: {exc}")
            return False
        finally:
            session.close()

        DatabaseConnection._cache_restore_creature_spawn(dict(entry))
        return True

    @staticmethod
    def create_creature_spawn(
        entry: int,
        *,
        map_id: int,
        x: float,
        y: float,
        z: float,
        orientation: float,
        spawn_mask: int = 1,
        phase_id: int = 0,
        phase_group: int = 0,
        spawntimesecs: int = 300,
        spawndist: float = 0.0,
        movement_type: int = 0,
    ) -> dict | None:
        if int(entry or 0) <= 0:
            return None
        template = DatabaseConnection.get_creature_template(int(entry))
        if template is None:
            return None

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return None

        spawn_guid = 0
        try:
            max_guid = session.query(WorldCreature.guid).order_by(WorldCreature.guid.desc()).first()
            spawn_guid = int(max_guid[0] if max_guid else 0) + 1
            row = WorldCreature(
                guid=spawn_guid,
                id=int(entry),
                map=int(map_id),
                spawnMask=int(spawn_mask or 1),
                phaseId=int(phase_id or 0),
                phaseGroup=int(phase_group or 0),
                modelid=int(template.get("modelid1", 0) or 0),
                equipment_id=0,
                position_x=float(x),
                position_y=float(y),
                position_z=float(z),
                orientation=float(orientation or 0.0),
                spawntimesecs=int(spawntimesecs or 0),
                spawndist=float(spawndist or 0.0),
                currentwaypoint=0,
                curhealth=1,
                curmana=0,
                MovementType=int(movement_type or 0),
                npcflag=int(template.get("npcflag", 0) or 0),
                unit_flags=0,
                dynamicflags=0,
            )
            session.add(row)
            session.commit()
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] creature create failed entry={entry}: {exc}")
            return None
        finally:
            session.close()

        created = DatabaseConnection.get_creature_spawn(spawn_guid)
        if created is not None:
            DatabaseConnection._cache_restore_creature_spawn(dict(created))
        return created

    @staticmethod
    def update_creature_spawn_transform(
        spawn_guid: int,
        *,
        x: float | None = None,
        y: float | None = None,
        z: float | None = None,
        orientation: float | None = None,
    ) -> dict | None:
        existing = DatabaseConnection.get_creature_spawn(int(spawn_guid))
        if existing is None:
            return None

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return None

        try:
            row = session.query(WorldCreature).filter(WorldCreature.guid == int(spawn_guid)).first()
            if row is None:
                session.rollback()
                return None
            if x is not None:
                row.position_x = float(x)
            if y is not None:
                row.position_y = float(y)
            if z is not None:
                row.position_z = float(z)
            if orientation is not None:
                row.orientation = float(orientation)
            session.commit()
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] creature transform update failed guid={spawn_guid}: {exc}")
            return None
        finally:
            session.close()

        updated = DatabaseConnection.get_creature_spawn(int(spawn_guid))
        if updated is not None:
            DatabaseConnection._cache_restore_creature_spawn(dict(updated))
        return updated

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

        DatabaseConnection._ensure_gameobject_scale_column()
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
                    WorldGameObject.scale,
                    WorldGameObjectTemplate.type,
                    WorldGameObjectTemplate.displayId,
                    WorldGameObjectTemplate.name,
                    WorldGameObjectTemplate.faction,
                    WorldGameObjectTemplate.flags,
                    WorldGameObjectTemplate.size,
                    *[
                        getattr(WorldGameObjectTemplate, f"data{index}")
                        for index in range(24)
                    ],
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
    def get_gameobject_spawn(spawn_guid: int) -> dict | None:
        if int(spawn_guid or 0) <= 0:
            return None

        if DatabaseConnection._world_cache_loaded and DatabaseConnection._cache_gameobjects_loaded:
            for entries in (DatabaseConnection._cache_gameobjects_by_map or {}).values():
                for entry in entries or ():
                    if int(entry.get("guid", 0) or 0) == int(spawn_guid):
                        return dict(entry)

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return None

        DatabaseConnection._ensure_gameobject_scale_column()
        try:
            row = (
                session.query(
                    WorldGameObject.guid,
                    WorldGameObject.id,
                    WorldGameObject.map,
                    WorldGameObject.spawnMask,
                    WorldGameObject.phaseId,
                    WorldGameObject.phaseGroup,
                    WorldGameObject.position_x,
                    WorldGameObject.position_y,
                    WorldGameObject.position_z,
                    WorldGameObject.orientation,
                    WorldGameObject.rotation0,
                    WorldGameObject.rotation1,
                    WorldGameObject.rotation2,
                    WorldGameObject.rotation3,
                    WorldGameObject.spawntimesecs,
                    WorldGameObject.animprogress,
                    WorldGameObject.state,
                    WorldGameObject.scale,
                    WorldGameObjectTemplate.type,
                    WorldGameObjectTemplate.displayId,
                    WorldGameObjectTemplate.name,
                    WorldGameObjectTemplate.faction,
                    WorldGameObjectTemplate.flags,
                    WorldGameObjectTemplate.size,
                    *[
                        getattr(WorldGameObjectTemplate, f"data{index}")
                        for index in range(24)
                    ],
                )
                .join(WorldGameObjectTemplate, WorldGameObjectTemplate.entry == WorldGameObject.id)
                .outerjoin(GameEventGameObject, GameEventGameObject.guid == WorldGameObject.guid)
                .filter(GameEventGameObject.guid.is_(None))
                .filter(WorldGameObject.guid == int(spawn_guid))
                .first()
            )
        except Exception as exc:
            Logger.warning(f"[DB] gameobject spawn lookup failed guid={spawn_guid}: {exc}")
            return None
        finally:
            session.close()

        if row is None:
            return None
        return DatabaseConnection._build_gameobject_candidate(row)

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

        template_size = getattr(row, "size", 1.0)
        spawn_scale = getattr(row, "scale", None)
        effective_scale = spawn_scale if spawn_scale is not None else template_size

        return {
            "guid": int(getattr(row, "guid", 0) or 0),
            "entry": int(getattr(row, "id", 0) or 0),
            "map_id": int(getattr(row, "map", 0) or 0),
            "map": int(getattr(row, "map", 0) or 0),
            "spawnMask": int(getattr(row, "spawnMask", 1) or 1),
            "phaseId": int(getattr(row, "phaseId", 0) or 0),
            "phaseGroup": int(getattr(row, "phaseGroup", 0) or 0),
            "x": float(getattr(row, "position_x", 0.0) or 0.0),
            "y": float(getattr(row, "position_y", 0.0) or 0.0),
            "z": float(getattr(row, "position_z", 0.0) or 0.0),
            "orientation": float(getattr(row, "orientation", 0.0) or 0.0),
            "rotation0": float(getattr(row, "rotation0", 0.0) or 0.0),
            "rotation1": float(getattr(row, "rotation1", 0.0) or 0.0),
            "rotation2": float(getattr(row, "rotation2", 0.0) or 0.0),
            "rotation3": float(getattr(row, "rotation3", 0.0) or 0.0),
            "spawntimesecs": int(getattr(row, "spawntimesecs", 0) or 0),
            "animprogress": int(getattr(row, "animprogress", 0) or 0),
            "state": int(getattr(row, "state", 0) or 0),
            "type": go_type,
            "display_id": display_id,
            "name": str(getattr(row, "name", "") or ""),
            "faction": int(getattr(row, "faction", 0) or 0),
            "flags": flags,
            "size": float(effective_scale or 1.0),
            "template_size": float(template_size or 1.0),
            **{
                f"data{index}": int(getattr(row, f"data{index}", 0) or 0)
                for index in range(24)
            },
        }

    @staticmethod
    def _cache_remove_gameobject_spawn(spawn_guid: int) -> None:
        cache_by_map = getattr(DatabaseConnection, "_cache_gameobjects_by_map", None)
        if not isinstance(cache_by_map, dict):
            return
        for map_id, entries in list(cache_by_map.items()):
            cache_by_map[int(map_id)] = [
                dict(entry)
                for entry in (entries or ())
                if int(entry.get("guid", 0) or 0) != int(spawn_guid)
            ]

    @staticmethod
    def _cache_restore_gameobject_spawn(entry: dict) -> None:
        cache_by_map = getattr(DatabaseConnection, "_cache_gameobjects_by_map", None)
        if not isinstance(cache_by_map, dict):
            return
        spawn_guid = int(entry.get("guid", 0) or 0)
        map_id = int(entry.get("map_id", entry.get("map", 0)) or 0)
        if spawn_guid <= 0:
            return
        DatabaseConnection._cache_remove_gameobject_spawn(spawn_guid)
        cache_by_map.setdefault(map_id, []).append(dict(entry))

    @staticmethod
    def _gameobject_save_snapshot(
        existing: dict,
        requested: dict,
        synchronized_fields: tuple[str, ...],
    ) -> dict:
        """Use runtime state at the explicit GameObject save boundary."""
        if not synchronized_fields:
            return dict(requested)
        from server.modules.handlers.world.runtime.gameobject_persistence import (
            gameobject_persistence_snapshot,
        )
        from server.modules.handlers.world.runtime.gameobject_store import (
            get_gameobject_runtime_store,
        )

        runtime_object = get_gameobject_runtime_store().get_by_spawn_id(
            int(existing.get("guid", 0) or 0)
        )
        if runtime_object is None:
            return dict(requested)
        if (
            int(runtime_object.spawn_id) != int(existing.get("guid", 0) or 0)
            or int(runtime_object.entry) != int(existing.get("entry", 0) or 0)
        ):
            return dict(requested)
        runtime_snapshot = gameobject_persistence_snapshot(
            runtime_object,
            existing,
        )
        if any(
            runtime_snapshot.get(field) != requested.get(field)
            for field in synchronized_fields
        ):
            return dict(requested)
        return runtime_snapshot

    @staticmethod
    def delete_gameobject_spawn(spawn_guid: int) -> dict | None:
        existing = DatabaseConnection.get_gameobject_spawn(int(spawn_guid))
        if existing is None:
            return None

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return None

        try:
            deleted = (
                session.query(WorldGameObject)
                .filter(WorldGameObject.guid == int(spawn_guid))
                .delete(synchronize_session=False)
            )
            if int(deleted or 0) <= 0:
                session.rollback()
                return None
            session.commit()
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] gameobject delete failed guid={spawn_guid}: {exc}")
            return None
        finally:
            session.close()

        DatabaseConnection._cache_remove_gameobject_spawn(int(spawn_guid))
        return dict(existing)

    @staticmethod
    def restore_gameobject_spawn(entry: dict) -> bool:
        if not isinstance(entry, dict):
            return False
        spawn_guid = int(entry.get("guid", 0) or 0)
        go_entry = int(entry.get("entry", 0) or 0)
        if spawn_guid <= 0 or go_entry <= 0:
            return False

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return False

        try:
            DatabaseConnection._ensure_gameobject_scale_column()
            existing = session.query(WorldGameObject).filter(WorldGameObject.guid == spawn_guid).first()
            if existing is not None:
                session.delete(existing)
                session.flush()
            spawn_scale = float(entry.get("size", entry.get("scale", 1.0)) or 1.0)
            row = WorldGameObject(
                guid=spawn_guid,
                id=go_entry,
                map=int(entry.get("map_id", entry.get("map", 0)) or 0),
                spawnMask=int(entry.get("spawnMask", 1) or 1),
                phaseId=int(entry.get("phaseId", 0) or 0),
                phaseGroup=int(entry.get("phaseGroup", 0) or 0),
                position_x=float(entry.get("x", 0.0) or 0.0),
                position_y=float(entry.get("y", 0.0) or 0.0),
                position_z=float(entry.get("z", 0.0) or 0.0),
                orientation=float(entry.get("orientation", 0.0) or 0.0),
                scale=spawn_scale,
                rotation0=float(entry.get("rotation0", 0.0) or 0.0),
                rotation1=float(entry.get("rotation1", 0.0) or 0.0),
                rotation2=float(entry.get("rotation2", 0.0) or 0.0),
                rotation3=float(entry.get("rotation3", 0.0) or 0.0),
                spawntimesecs=int(entry.get("spawntimesecs", 0) or 0),
                animprogress=int(entry.get("animprogress", 0) or 0),
                state=int(entry.get("state", 0) or 0),
            )
            session.add(row)
            session.commit()
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] gameobject restore failed guid={spawn_guid}: {exc}")
            return False
        finally:
            session.close()

        DatabaseConnection._cache_restore_gameobject_spawn(dict(entry))
        return True

    @staticmethod
    def _gameobject_rotation_from_orientation(orientation: float) -> tuple[float, float, float, float]:
        yaw = float(orientation or 0.0)
        return 0.0, 0.0, math.sin(yaw * 0.5), math.cos(yaw * 0.5)

    @staticmethod
    def create_gameobject_spawn(
        entry: int,
        *,
        map_id: int,
        x: float,
        y: float,
        z: float,
        orientation: float,
        spawn_mask: int = 1,
        phase_id: int = 0,
        phase_group: int = 0,
        state: int = 1,
        animprogress: int = 255,
        spawntimesecs: int = 300,
        scale: float | None = None,
    ) -> dict | None:
        if int(entry or 0) <= 0:
            return None
        template = DatabaseConnection.get_gameobject_template(int(entry))
        if template is None:
            return None

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return None

        rotation0, rotation1, rotation2, rotation3 = DatabaseConnection._gameobject_rotation_from_orientation(
            float(orientation or 0.0)
        )
        spawn_scale = float(scale if scale is not None else template.get("size", 1.0) or 1.0)
        spawn_guid = 0
        try:
            DatabaseConnection._ensure_gameobject_scale_column()
            max_guid = session.query(WorldGameObject.guid).order_by(WorldGameObject.guid.desc()).first()
            spawn_guid = int(max_guid[0] if max_guid else 0) + 1
            row = WorldGameObject(
                guid=spawn_guid,
                id=int(entry),
                map=int(map_id),
                spawnMask=int(spawn_mask or 1),
                phaseId=int(phase_id or 0),
                phaseGroup=int(phase_group or 0),
                position_x=float(x),
                position_y=float(y),
                position_z=float(z),
                orientation=float(orientation or 0.0),
                scale=spawn_scale,
                rotation0=float(rotation0),
                rotation1=float(rotation1),
                rotation2=float(rotation2),
                rotation3=float(rotation3),
                spawntimesecs=int(spawntimesecs or 0),
                animprogress=max(0, min(int(animprogress or 0), 255)),
                state=max(0, min(int(state or 0), 255)),
            )
            session.add(row)
            session.commit()
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] gameobject create failed entry={entry}: {exc}")
            return None
        finally:
            session.close()

        created = DatabaseConnection.get_gameobject_spawn(spawn_guid)
        if created is None:
            created = {
                "guid": int(spawn_guid),
                "entry": int(entry),
                "map_id": int(map_id),
                "map": int(map_id),
                "spawnMask": int(spawn_mask or 1),
                "phaseId": int(phase_id or 0),
                "phaseGroup": int(phase_group or 0),
                "x": float(x),
                "y": float(y),
                "z": float(z),
                "orientation": float(orientation or 0.0),
                "rotation0": float(rotation0),
                "rotation1": float(rotation1),
                "rotation2": float(rotation2),
                "rotation3": float(rotation3),
                "spawntimesecs": int(spawntimesecs or 0),
                "animprogress": max(0, min(int(animprogress or 0), 255)),
                "state": max(0, min(int(state or 0), 255)),
                "type": int(template.get("type", 0) or 0),
                "display_id": int(template.get("displayId", template.get("display_id", 0)) or 0),
                "name": str(template.get("name", "") or ""),
                "faction": int(template.get("faction", 0) or 0),
                "flags": int(template.get("flags", 0) or 0),
                "size": float(spawn_scale or 1.0),
                "template_size": float(template.get("size", 1.0) or 1.0),
                **{
                    f"data{index}": int(template.get(f"data{index}", 0) or 0)
                    for index in range(24)
                },
            }
        if created is not None:
            DatabaseConnection._cache_restore_gameobject_spawn(dict(created))
        return created

    @staticmethod
    def update_gameobject_spawn_transform(
        spawn_guid: int,
        *,
        x: float | None = None,
        y: float | None = None,
        z: float | None = None,
        orientation: float | None = None,
    ) -> dict | None:
        existing = DatabaseConnection.get_gameobject_spawn(int(spawn_guid))
        if existing is None:
            return None

        requested = dict(existing)
        synchronized_fields: list[str] = []
        if x is not None:
            requested["x"] = float(x)
            synchronized_fields.append("x")
        if y is not None:
            requested["y"] = float(y)
            synchronized_fields.append("y")
        if z is not None:
            requested["z"] = float(z)
            synchronized_fields.append("z")
        if orientation is not None:
            rotation = DatabaseConnection._gameobject_rotation_from_orientation(
                float(orientation)
            )
            requested["orientation"] = float(orientation)
            requested["rotation0"] = float(rotation[0])
            requested["rotation1"] = float(rotation[1])
            requested["rotation2"] = float(rotation[2])
            requested["rotation3"] = float(rotation[3])
            synchronized_fields.append("orientation")
        persistence_snapshot = DatabaseConnection._gameobject_save_snapshot(
            existing,
            requested,
            tuple(synchronized_fields),
        )

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return None

        try:
            row = session.query(WorldGameObject).filter(WorldGameObject.guid == int(spawn_guid)).first()
            if row is None:
                session.rollback()
                return None
            if x is not None:
                row.position_x = float(persistence_snapshot["x"])
            if y is not None:
                row.position_y = float(persistence_snapshot["y"])
            if z is not None:
                row.position_z = float(persistence_snapshot["z"])
            if orientation is not None:
                row.orientation = float(persistence_snapshot["orientation"])
                row.rotation0 = float(persistence_snapshot["rotation0"])
                row.rotation1 = float(persistence_snapshot["rotation1"])
                row.rotation2 = float(persistence_snapshot["rotation2"])
                row.rotation3 = float(persistence_snapshot["rotation3"])
            session.commit()
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] gameobject transform update failed guid={spawn_guid}: {exc}")
            return None
        finally:
            session.close()

        updated = dict(persistence_snapshot)
        DatabaseConnection._cache_restore_gameobject_spawn(dict(updated))
        return updated

    @staticmethod
    def update_gameobject_spawn_scale(spawn_guid: int, size: float) -> dict | None:
        if int(spawn_guid or 0) <= 0:
            return None
        size = max(0.01, float(size or 0.0))
        existing = DatabaseConnection.get_gameobject_spawn(int(spawn_guid))
        if existing is None:
            return None
        requested = dict(existing)
        requested["size"] = float(size)
        persistence_snapshot = DatabaseConnection._gameobject_save_snapshot(
            existing,
            requested,
            ("size",),
        )

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return None

        try:
            DatabaseConnection._ensure_gameobject_scale_column()
            row = session.query(WorldGameObject).filter(WorldGameObject.guid == int(spawn_guid)).first()
            if row is None:
                session.rollback()
                return None
            row.scale = float(persistence_snapshot["size"])
            session.commit()
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] gameobject spawn scale update failed guid={spawn_guid}: {exc}")
            return None
        finally:
            session.close()

        updated = dict(persistence_snapshot)
        DatabaseConnection._cache_restore_gameobject_spawn(dict(updated))
        return updated

    @staticmethod
    def update_gameobject_template_size(entry: int, size: float) -> bool:
        if int(entry or 0) <= 0:
            return False
        size = max(0.01, float(size or 0.0))

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning(f"[DB] World DB unavailable: {exc}")
            return False

        try:
            row = session.query(WorldGameObjectTemplate).filter(WorldGameObjectTemplate.entry == int(entry)).first()
            if row is None:
                session.rollback()
                return False
            row.size = float(size)
            session.commit()
        except Exception as exc:
            session.rollback()
            Logger.warning(f"[DB] gameobject template size update failed entry={entry}: {exc}")
            return False
        finally:
            session.close()

        cached_templates = getattr(DatabaseConnection, "_cache_gameobject_templates", None)
        if isinstance(cached_templates, dict) and int(entry) in cached_templates:
            cached_templates[int(entry)] = dict(cached_templates[int(entry)])
            cached_templates[int(entry)]["size"] = float(size)
        cache_by_map = getattr(DatabaseConnection, "_cache_gameobjects_by_map", None)
        if isinstance(cache_by_map, dict):
            for map_id, entries in list(cache_by_map.items()):
                cache_by_map[int(map_id)] = [
                    dict(spawn, size=float(size)) if int(spawn.get("entry", 0) or 0) == int(entry) else dict(spawn)
                    for spawn in (entries or ())
                ]
        return True

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
            "npcflag": int(getattr(row, "npcflag", 0) or 0),
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
    def update_character_title_state(
        guid: int,
        realm_id: int,
        chosen_title: int,
        known_titles: str,
    ) -> None:
        session = DatabaseConnection.chars()

        try:
            char = session.query(Characters).filter_by(
                guid=int(guid),
                realm=int(realm_id),
            ).first()

            if not char:
                return

            char.chosenTitle = int(chosen_title)
            char.knownTitles = str(known_titles or "")
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
    def _pack_action_button(action: int, type_: int = ACTION_BUTTON_TYPE_SPELL) -> int:
        return (int(action) & 0x00FFFFFF) | ((int(type_) & 0xFF) << 24)

    @staticmethod
    def _fallback_action_spell_ids(default_actions: list[tuple[int, int, int]], spells: list[int]) -> list[int]:
        ordered: list[int] = []
        seen: set[int] = set()
        excluded_spells = _ACTION_BUTTON_EXCLUDED_SPELLS | _battle_pet_action_excluded_spells()
        available_spells = {
            int(action)
            for _button, action, type_ in default_actions
            if int(type_ or 0) == ACTION_BUTTON_TYPE_SPELL and int(action or 0) > 0
        }
        available_spells.update(int(spell_id) for spell_id in spells if int(spell_id or 0) > 0)

        def add_spell(spell_id: int) -> None:
            try:
                spell_id = int(spell_id)
            except Exception:
                return
            if spell_id <= 0 or spell_id in seen or spell_id in excluded_spells:
                return
            ordered.append(spell_id)
            seen.add(spell_id)

        for spell_id in _ACTION_BUTTON_PRIORITY_SPELLS:
            if int(spell_id) in available_spells:
                add_spell(spell_id)
        for _button, action, type_ in default_actions:
            if int(type_ or 0) == ACTION_BUTTON_TYPE_SPELL:
                add_spell(int(action))
        for spell_id in spells:
            add_spell(int(spell_id))

        return ordered

    @staticmethod
    def _fill_sparse_action_buttons(
        buttons: list[int],
        *,
        default_actions: list[tuple[int, int, int]],
        spells: list[int],
        saved_slots: set[int],
    ) -> list[int]:
        if len(buttons) < ACTION_BUTTON_COUNT:
            buttons = list(buttons) + [0] * (ACTION_BUTTON_COUNT - len(buttons))
        else:
            buttons = list(buttons[:ACTION_BUTTON_COUNT])

        used_actions = {int(value) & 0x00FFFFFF for value in buttons if int(value or 0) > 0}
        candidate_spells = [
            spell_id
            for spell_id in DatabaseConnection._fallback_action_spell_ids(default_actions, spells)
            if spell_id not in used_actions
        ]
        if not candidate_spells:
            return buttons

        for slot in range(PRIMARY_ACTION_BAR_SLOTS):
            if not candidate_spells:
                break
            if slot in saved_slots or int(buttons[slot] or 0) != 0:
                continue
            spell_id = candidate_spells.pop(0)
            buttons[slot] = DatabaseConnection._pack_action_button(spell_id, ACTION_BUTTON_TYPE_SPELL)
            used_actions.add(spell_id)

        return buttons

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

        buttons = [0] * ACTION_BUTTON_COUNT
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
                if 0 <= button < ACTION_BUTTON_COUNT:
                    buttons[int(button)] = DatabaseConnection._pack_action_button(action, type_)
            except Exception:
                continue

        saved_slots: set[int] = set()
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

        excluded_action_spells = _battle_pet_action_excluded_spells()
        for button, action, type_ in saved_rows:
            try:
                button_index = int(button)
                if not (0 <= button_index < ACTION_BUTTON_COUNT):
                    continue
                saved_slots.add(button_index)
                if (
                    int(type_ or 0) == ACTION_BUTTON_TYPE_SPELL
                    and int(action or 0) in excluded_action_spells
                ):
                    buttons[button_index] = 0
                    continue
                buttons[button_index] = (
                    DatabaseConnection._pack_action_button(action, type_)
                ) if int(action) > 0 else 0
            except Exception:
                continue

        spells = []
        try:
            spells = list(DatabaseConnection.get_character_spells(int(char_guid)))
        except Exception as exc:
            Logger.warning(f"[DB] character spell lookup for action fallback failed guid={char_guid}: {exc}")

        buttons = DatabaseConnection._fill_sparse_action_buttons(
            buttons,
            default_actions=actions,
            spells=spells,
            saved_slots=saved_slots,
        )

        filled_count = sum(1 for value in buttons[:PRIMARY_ACTION_BAR_SLOTS] if int(value or 0) > 0)
        Logger.info(
            "[ACTION_BUTTON] resolved action bar guid=%s primary_filled=%s saved_slots=%s",
            int(char_guid),
            int(filled_count),
            len(saved_slots),
        )

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
        Return learned spells for character merged with createinfo spells.
        """
        session = DatabaseConnection.chars()

        rows = (
            session.query(CharacterSpell.spell, CharacterSpell.disabled)
            .filter(CharacterSpell.guid == char_guid)
            .all()
        )

        char = (
            session.query(Characters.race, Characters.class_)
            .filter(Characters.guid == char_guid)
            .first()
        )

        if not char:
            Logger.error(f"[DB] get_character_spells: character {char_guid} not found")
            return []

        disabled_spells = {
            int(r.spell)
            for r in rows
            if int(getattr(r, "disabled", 0) or 0) != 0 and int(getattr(r, "spell", 0) or 0) > 0
        }
        spells = {
            int(spell_id)
            for spell_id in DatabaseConnection.get_player_createinfo_spells(
                race=int(char.race),
                class_=int(char.class_),
            )
            if int(spell_id) > 0 and int(spell_id) not in disabled_spells
        }
        spells.update(
            int(r.spell)
            for r in rows
            if int(r.spell) > 0 and int(r.disabled or 0) == 0
        )

        return sorted(spells)

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
                if row is None:
                    row = CharacterAction(
                        guid=guid,
                        spec=spec,
                        button=button,
                        action=0,
                        type_=0,
                    )
                    session.add(row)
                else:
                    row.action = 0
                    row.type_ = 0
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
    def save_character_cinematic_state(guid: int, realm_id: int, cinematic: int) -> bool:
        session = DatabaseConnection.chars()
        try:
            row = (
                session.query(Characters)
                .filter(
                    Characters.guid == int(guid),
                    Characters.realm == int(realm_id),
                )
                .one_or_none()
            )
            if row is None:
                return False
            row.cinematic = int(cinematic)
            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            Logger.warning(
                "[DB] save_character_cinematic_state failed guid=%s realm=%s cinematic=%s: %s",
                int(guid),
                int(realm_id),
                int(cinematic),
                exc,
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
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning("[DB] areatrigger_teleport DB unavailable id=%s: %s", int(trigger_id), exc)
            return None

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

    @staticmethod
    def get_areatrigger_teleports() -> list[dict]:
        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning("[DB] areatrigger_teleport list DB unavailable: %s", exc)
            return []

        try:
            rows = session.execute(text(
                """
                SELECT
                    id,
                    name,
                    target_map,
                    target_position_x,
                    target_position_y,
                    target_position_z,
                    target_orientation
                FROM areatrigger_teleport
                """
            )).mappings().all()
            return [dict(row) for row in rows]
        except Exception as exc:
            Logger.warning("[DB] areatrigger_teleport list failed: %s", exc)
            return []
        finally:
            session.close()

    @staticmethod
    def get_spell_target_position(spell_id: int, effect_index: int = 0) -> dict | None:
        spell = int(spell_id or 0)
        eff_index = int(effect_index or 0)
        if spell <= 0:
            return None

        cache_key = (spell, eff_index)
        if cache_key in DatabaseConnection._cache_spell_target_positions:
            return dict(DatabaseConnection._cache_spell_target_positions[cache_key])

        try:
            session = DatabaseConnection.world()
        except Exception as exc:
            Logger.warning("[DB] spell_target_position DB unavailable spell=%s: %s", spell, exc)
            return None

        try:
            row = session.execute(
                text(
                    """
                    SELECT
                        id,
                        effIndex,
                        target_map,
                        target_position_x,
                        target_position_y,
                        target_position_z,
                        target_orientation
                    FROM spell_target_position
                    WHERE id = :id AND effIndex = :eff_index
                    LIMIT 1
                    """
                ),
                {"id": spell, "eff_index": eff_index},
            ).mappings().first()
            if row is None and eff_index != 0:
                row = session.execute(
                    text(
                        """
                        SELECT
                            id,
                            effIndex,
                            target_map,
                            target_position_x,
                            target_position_y,
                            target_position_z,
                            target_orientation
                        FROM spell_target_position
                        WHERE id = :id AND effIndex = 0
                        LIMIT 1
                        """
                    ),
                    {"id": spell},
                ).mappings().first()
            if row is None:
                row = session.execute(
                    text(
                        """
                        SELECT
                            id,
                            effIndex,
                            target_map,
                            target_position_x,
                            target_position_y,
                            target_position_z,
                            target_orientation
                        FROM spell_target_position
                        WHERE id = :id
                        ORDER BY effIndex ASC
                        LIMIT 1
                        """
                    ),
                    {"id": spell},
                ).mappings().first()
            if row is None:
                return None

            result = dict(row)
            DatabaseConnection._cache_spell_target_positions[
                (spell, int(result.get("effIndex", eff_index) or 0))
            ] = dict(result)
            DatabaseConnection._cache_spell_target_positions[cache_key] = dict(result)
            return result
        except Exception as exc:
            Logger.warning("[DB] spell_target_position lookup failed spell=%s: %s", spell, exc)
            return None
        finally:
            session.close()

    @staticmethod
    def get_gameobject_teleport(spawn_guid: int, entry: int) -> dict | None:
        guid = int(spawn_guid or 0)
        go_entry = int(entry or 0)
        if guid <= 0 and go_entry <= 0:
            return None

        try:
            session = DatabaseConnection.world()
        except Exception:
            return None

        try:
            row = session.execute(
                text(
                    """
                    SELECT
                        COALESCE(name, '') AS name,
                        target_map,
                        target_position_x,
                        target_position_y,
                        target_position_z,
                        target_orientation
                    FROM gameobject_teleport
                    WHERE
                        (:guid > 0 AND guid = :guid)
                        OR (:entry > 0 AND entry = :entry)
                    ORDER BY CASE WHEN guid = :guid THEN 0 ELSE 1 END
                    LIMIT 1
                    """
                ),
                {"guid": guid, "entry": go_entry},
            ).mappings().first()
            return dict(row) if row else None
        except Exception:
            return None
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
