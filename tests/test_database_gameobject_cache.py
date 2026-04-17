import importlib
import sys
import types


def _import_database_connection():
    sqlalchemy = types.ModuleType("sqlalchemy")
    sqlalchemy.create_engine = lambda *args, **kwargs: None
    sqlalchemy.or_ = lambda *args, **kwargs: None
    sqlalchemy.text = lambda sql: sql
    sys.modules["sqlalchemy"] = sqlalchemy

    sqlalchemy_orm = types.ModuleType("sqlalchemy.orm")
    sqlalchemy_orm.scoped_session = lambda factory: factory
    sqlalchemy_orm.sessionmaker = lambda **kwargs: (lambda: None)
    sys.modules["sqlalchemy.orm"] = sqlalchemy_orm

    auth_module = types.ModuleType("server.modules.auth.AuthConnection")
    auth_module.AuthConnection = type(
        "AuthConnection",
        (),
        {"session": staticmethod(lambda: None)},
    )
    sys.modules["server.modules.auth.AuthConnection"] = auth_module

    config_module = types.ModuleType("shared.ConfigLoader")
    config_module.ConfigLoader = type(
        "ConfigLoader",
        (),
        {"load_config": staticmethod(lambda: {"database": {}})},
    )
    sys.modules["shared.ConfigLoader"] = config_module

    logger_module = types.ModuleType("shared.Logger")
    logger_module.Logger = type(
        "Logger",
        (),
        {
            "info": staticmethod(lambda *args, **kwargs: None),
            "warning": staticmethod(lambda *args, **kwargs: None),
            "error": staticmethod(lambda *args, **kwargs: None),
        },
    )
    sys.modules["shared.Logger"] = logger_module

    characters_model = types.ModuleType("server.modules.database.CharactersModel")
    for name in (
        "Characters",
        "CharacterAction",
        "CharacterSpell",
        "CharacterInventory",
        "ItemInstance",
    ):
        setattr(characters_model, name, type(name, (), {}))
    sys.modules["server.modules.database.CharactersModel"] = characters_model

    world_model = types.ModuleType("server.modules.database.WorldModel")
    for name in (
        "ItemTemplate",
        "WorldCreature",
        "WorldCreatureTemplate",
        "WorldGameObject",
        "WorldGameObjectTemplate",
        "GameEventGameObject",
        "PlayerFactionchangeAchievement",
        "PlayerFactionchangeItems",
        "PlayerFactionchangeQuests",
        "PlayerFactionchangeReputations",
        "PlayerFactionchangeSpells",
        "PlayerFactionchangeTitles",
        "PlayerLevelStats",
        "PlayerXpForLevel",
        "PlayerCreateInfo",
        "PlayerCreateInfoAction",
        "PlayerCreateInfoItem",
        "PlayerCreateInfoSpell",
        "PlayerCreateInfoSpellCast",
        "PlayerCreateInfoSpellCustom",
    ):
        setattr(world_model, name, type(name, (), {}))
    sys.modules["server.modules.database.WorldModel"] = world_model

    sys.modules.pop("server.modules.database.DatabaseConnection", None)
    module = importlib.import_module("server.modules.database.DatabaseConnection")
    return module.DatabaseConnection


def test_get_gameobjects_near_uses_preloaded_cache_without_db():
    DatabaseConnection = _import_database_connection()

    DatabaseConnection._world_cache_loaded = True
    DatabaseConnection._cache_gameobjects_loaded = True
    DatabaseConnection._cache_gameobjects_by_map = {
        1: [
            {"guid": 1, "map_id": 1, "x": 100.0, "y": 100.0, "name": "crate"},
            {"guid": 2, "map_id": 1, "x": 250.0, "y": 250.0, "name": "far crate"},
        ]
    }
    DatabaseConnection.world = staticmethod(lambda: (_ for _ in ()).throw(AssertionError("DB should not be used")))

    results = DatabaseConnection.get_gameobjects_near(1, 100.0, 100.0, radius=120.0, limit=10)

    assert [entry["guid"] for entry in results] == [1]


def test_get_gameobjects_near_cache_respects_limit():
    DatabaseConnection = _import_database_connection()

    DatabaseConnection._world_cache_loaded = True
    DatabaseConnection._cache_gameobjects_loaded = True
    DatabaseConnection._cache_gameobjects_by_map = {
        0: [
            {"guid": 11, "map_id": 0, "x": -1.0, "y": 0.0},
            {"guid": 12, "map_id": 0, "x": 1.0, "y": 0.0},
            {"guid": 13, "map_id": 0, "x": 2.0, "y": 0.0},
        ]
    }

    results = DatabaseConnection.get_gameobjects_near(0, 0.0, 0.0, radius=10.0, limit=2)

    assert [entry["guid"] for entry in results] == [11, 12]


def test_get_creature_template_uses_preloaded_cache_without_db():
    DatabaseConnection = _import_database_connection()

    DatabaseConnection._world_cache_loaded = True
    DatabaseConnection._cache_creatures_loaded = True
    DatabaseConnection._cache_creature_templates = {
        123: {"entry": 123, "name": "Stormwind Guard", "modelid1": 19724}
    }
    DatabaseConnection.world = staticmethod(lambda: (_ for _ in ()).throw(AssertionError("DB should not be used")))

    result = DatabaseConnection.get_creature_template(123)

    assert result == {"entry": 123, "name": "Stormwind Guard", "modelid1": 19724}


def test_get_creatures_near_uses_preloaded_cache_without_db():
    DatabaseConnection = _import_database_connection()

    DatabaseConnection._world_cache_loaded = True
    DatabaseConnection._cache_creatures_loaded = True
    DatabaseConnection._cache_creatures_by_map = {
        1: [
            {"guid": 21, "entry": 68, "map_id": 1, "x": 10.0, "y": 10.0},
            {"guid": 22, "entry": 69, "map_id": 1, "x": 250.0, "y": 250.0},
        ]
    }
    DatabaseConnection.world = staticmethod(lambda: (_ for _ in ()).throw(AssertionError("DB should not be used")))

    results = DatabaseConnection.get_creatures_near(1, 10.0, 10.0, radius=120.0, limit=10)

    assert [entry["guid"] for entry in results] == [21]


def test_get_creatures_near_falls_back_to_db_when_preload_disabled():
    DatabaseConnection = _import_database_connection()

    DatabaseConnection._world_cache_loaded = False
    DatabaseConnection._cache_creatures_loaded = False

    class Field:
        def __eq__(self, other):
            return ("eq", other)

        def __ge__(self, other):
            return ("ge", other)

        def __le__(self, other):
            return ("le", other)

    world_model = sys.modules["server.modules.database.WorldModel"]
    world_model.WorldCreature.map = Field()
    world_model.WorldCreature.position_x = Field()
    world_model.WorldCreature.position_y = Field()

    class CreatureRow:
        guid = 31
        id = 68
        map = 1
        modelid = 19724
        equipment_id = 0
        position_x = 15.0
        position_y = 20.0
        position_z = 5.0
        orientation = 1.0
        spawntimesecs = 120
        spawndist = 0.0
        currentwaypoint = 0
        curhealth = 100
        curmana = 0
        MovementType = 0
        npcflag = 0
        unit_flags = 0
        dynamicflags = 0

    class Query:
        def filter(self, *args, **kwargs):
            return self

        def limit(self, value):
            return self

        def all(self):
            return [CreatureRow()]

    class Session:
        def query(self, model):
            return Query()

    DatabaseConnection.world = staticmethod(lambda: Session())

    results = DatabaseConnection.get_creatures_near(1, 10.0, 10.0, radius=20.0, limit=10)

    assert [entry["guid"] for entry in results] == [31]
