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

    auth_model = types.ModuleType("server.modules.database.AuthModel")
    auth_model.Account = type("Account", (), {})
    sys.modules["server.modules.database.AuthModel"] = auth_model

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


def test_fill_sparse_action_buttons_respects_saved_empty_slots():
    DatabaseConnection = _import_database_connection()

    buttons = [0] * 132
    buttons[0] = 44614
    filled = DatabaseConnection._fill_sparse_action_buttons(
        buttons,
        default_actions=[(0, 44614, 0), (9, 28730, 0)],
        spells=[44614, 6603, 28730, 668, 813],
        saved_slots={1},
    )

    assert filled[0] == 44614
    assert filled[1] == 0
    assert filled[2] == 6603
    assert filled[3] == 28730


def test_fallback_action_spells_only_prioritizes_available_spells():
    DatabaseConnection = _import_database_connection()

    spells = DatabaseConnection._fallback_action_spell_ids(
        default_actions=[],
        spells=[6603, 668, 813, 139196],
    )

    assert 44614 not in spells
    assert spells[:2] == [6603, 139196]


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


def test_cache_restore_gameobject_spawn_replaces_only_affected_spawn():
    DatabaseConnection = _import_database_connection()

    DatabaseConnection._world_cache_loaded = True
    DatabaseConnection._cache_gameobjects_loaded = True
    DatabaseConnection._cache_gameobjects_by_map = {
        0: [
            {"guid": 11, "entry": 100, "map_id": 0, "map": 0, "x": 1.0, "y": 2.0},
            {"guid": 12, "entry": 101, "map_id": 0, "map": 0, "x": 3.0, "y": 4.0},
        ],
        1: [
            {"guid": 13, "entry": 102, "map_id": 1, "map": 1, "x": 5.0, "y": 6.0},
        ],
    }

    DatabaseConnection._cache_restore_gameobject_spawn(
        {"guid": 12, "entry": 101, "map_id": 0, "map": 0, "x": 30.0, "y": 40.0}
    )

    assert DatabaseConnection.get_gameobject_spawn(11)["x"] == 1.0
    assert DatabaseConnection.get_gameobject_spawn(12)["x"] == 30.0
    assert DatabaseConnection.get_gameobject_spawn(12)["y"] == 40.0
    assert DatabaseConnection.get_gameobject_spawn(13)["x"] == 5.0


def test_cached_gameobject_transform_update_entry_is_immediately_authoritative():
    DatabaseConnection = _import_database_connection()

    existing = {
        "guid": 22,
        "entry": 200,
        "map_id": 1,
        "map": 1,
        "x": 10.0,
        "y": 20.0,
        "z": 30.0,
        "orientation": 1.0,
        "rotation0": 0.0,
        "rotation1": 0.0,
        "rotation2": 0.0,
        "rotation3": 1.0,
    }
    DatabaseConnection._world_cache_loaded = True
    DatabaseConnection._cache_gameobjects_loaded = True
    DatabaseConnection._cache_gameobjects_by_map = {1: [dict(existing)]}

    updated = dict(DatabaseConnection.get_gameobject_spawn(22))
    updated.update(
        {
            "x": 100.0,
            "y": 200.0,
            "z": 300.0,
            "orientation": 2.0,
            "rotation0": 0.0,
            "rotation1": 0.0,
            "rotation2": DatabaseConnection._gameobject_rotation_from_orientation(2.0)[2],
            "rotation3": DatabaseConnection._gameobject_rotation_from_orientation(2.0)[3],
        }
    )
    DatabaseConnection._cache_restore_gameobject_spawn(updated)

    fresh = DatabaseConnection.get_gameobject_spawn(22)

    assert fresh["x"] == 100.0
    assert fresh["y"] == 200.0
    assert fresh["z"] == 300.0
    assert fresh["orientation"] == 2.0
    assert fresh["rotation2"] == DatabaseConnection._gameobject_rotation_from_orientation(2.0)[2]
    assert fresh["rotation3"] == DatabaseConnection._gameobject_rotation_from_orientation(2.0)[3]


def test_update_gameobject_spawn_transform_updates_loaded_cache_without_db_reload():
    DatabaseConnection = _import_database_connection()

    DatabaseConnection._world_cache_loaded = True
    DatabaseConnection._cache_gameobjects_loaded = True
    DatabaseConnection._cache_gameobjects_by_map = {
        1: [
            {
                "guid": 33,
                "entry": 300,
                "map_id": 1,
                "map": 1,
                "x": 10.0,
                "y": 20.0,
                "z": 30.0,
                "orientation": 1.0,
                "rotation0": 0.0,
                "rotation1": 0.0,
                "rotation2": 0.0,
                "rotation3": 1.0,
                "size": 1.0,
            }
        ]
    }

    world_model = sys.modules["server.modules.database.WorldModel"]

    class Field:
        def __eq__(self, other):
            return ("eq", other)

    world_model.WorldGameObject.guid = Field()

    class Row:
        position_x = 10.0
        position_y = 20.0
        position_z = 30.0
        orientation = 1.0
        rotation0 = 0.0
        rotation1 = 0.0
        rotation2 = 0.0
        rotation3 = 1.0

    row = Row()

    class Query:
        def filter(self, *args, **kwargs):
            return self

        def first(self):
            return row

    class Session:
        committed = False
        closed = False

        def query(self, *args, **kwargs):
            return Query()

        def commit(self):
            self.committed = True

        def rollback(self):
            raise AssertionError("rollback should not be called")

        def close(self):
            self.closed = True

    db_session = Session()
    DatabaseConnection.world = staticmethod(lambda: db_session)

    updated = DatabaseConnection.update_gameobject_spawn_transform(
        33,
        x=100.0,
        y=200.0,
        z=300.0,
        orientation=2.5,
    )
    fresh = DatabaseConnection.get_gameobject_spawn(33)

    assert db_session.committed is True
    assert db_session.closed is True
    assert row.position_x == 100.0
    assert row.position_y == 200.0
    assert row.position_z == 300.0
    assert row.orientation == 2.5
    assert updated["x"] == 100.0
    assert updated["y"] == 200.0
    assert updated["z"] == 300.0
    assert updated["orientation"] == 2.5
    assert fresh["x"] == 100.0
    assert fresh["y"] == 200.0
    assert fresh["z"] == 300.0
    assert fresh["orientation"] == 2.5


def test_gameobject_candidate_uses_spawn_scale_before_template_size():
    DatabaseConnection = _import_database_connection()

    class Row:
        guid = 55
        id = 500
        map = 1
        position_x = 0.0
        position_y = 0.0
        position_z = 0.0
        orientation = 0.0
        rotation0 = 0.0
        rotation1 = 0.0
        rotation2 = 0.0
        rotation3 = 1.0
        animprogress = 255
        state = 1
        type = 5
        displayId = 100
        name = "Scaled Crate"
        faction = 0
        flags = 1
        size = 1.0
        scale = 2.5

    candidate = DatabaseConnection._build_gameobject_candidate(Row())

    assert candidate is not None
    assert candidate["size"] == 2.5
    assert candidate["template_size"] == 1.0


def test_gameobject_candidate_falls_back_to_template_size_without_spawn_scale():
    DatabaseConnection = _import_database_connection()

    class Row:
        guid = 56
        id = 501
        map = 1
        position_x = 0.0
        position_y = 0.0
        position_z = 0.0
        orientation = 0.0
        rotation0 = 0.0
        rotation1 = 0.0
        rotation2 = 0.0
        rotation3 = 1.0
        animprogress = 255
        state = 1
        type = 5
        displayId = 100
        name = "Template Crate"
        faction = 0
        flags = 1
        size = 1.75

    candidate = DatabaseConnection._build_gameobject_candidate(Row())

    assert candidate is not None
    assert candidate["size"] == 1.75
    assert candidate["template_size"] == 1.75


def test_update_gameobject_spawn_scale_updates_only_target_cached_spawn():
    DatabaseConnection = _import_database_connection()

    DatabaseConnection._world_cache_loaded = True
    DatabaseConnection._cache_gameobjects_loaded = True
    DatabaseConnection._gameobject_scale_column_ready = True
    DatabaseConnection._cache_gameobjects_by_map = {
        1: [
            {"guid": 70, "entry": 700, "map_id": 1, "map": 1, "x": 1.0, "y": 1.0, "size": 1.0},
            {"guid": 71, "entry": 700, "map_id": 1, "map": 1, "x": 2.0, "y": 2.0, "size": 1.0},
        ]
    }

    world_model = sys.modules["server.modules.database.WorldModel"]

    class Field:
        def __eq__(self, other):
            return ("eq", other)

    world_model.WorldGameObject.guid = Field()

    class Row:
        scale = 1.0

    row = Row()

    class Query:
        def filter(self, *args, **kwargs):
            return self

        def first(self):
            return row

    class Session:
        committed = False
        closed = False

        def query(self, *args, **kwargs):
            return Query()

        def commit(self):
            self.committed = True

        def rollback(self):
            raise AssertionError("rollback should not be called")

        def close(self):
            self.closed = True

    db_session = Session()
    DatabaseConnection.world = staticmethod(lambda: db_session)

    updated = DatabaseConnection.update_gameobject_spawn_scale(71, 2.0)

    assert db_session.committed is True
    assert db_session.closed is True
    assert row.scale == 2.0
    assert updated["size"] == 2.0
    assert DatabaseConnection.get_gameobject_spawn(70)["size"] == 1.0
    assert DatabaseConnection.get_gameobject_spawn(71)["size"] == 2.0


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
