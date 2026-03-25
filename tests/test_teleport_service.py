from world.teleport import teleport_service


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return list(self._rows)


class _FakeDb:
    def __init__(self, rows=None):
        self.rows = list(rows or [])
        self.calls = []
        self.commits = 0

    def execute(self, query, params=None):
        self.calls.append((str(query), dict(params or {})))
        if "SELECT name, map, position_x, position_y, position_z, orientation" in str(query):
            return _FakeResult(self.rows)
        return _FakeResult([])

    def commit(self):
        self.commits += 1


def test_load_find_search_and_nearest_teleports():
    db = _FakeDb(
        rows=[
            ("Stormwind", 0, -8833.07, 622.778, 93.9317, 0.6771),
            ("Goldshire", 0, -9464.0, 62.32, 56.77, 2.89),
            ("Orgrimmar", 1, 1502.78, -4415.66, 22.55, 0.12),
        ]
    )

    teleport_service.TELEPORTS.clear()
    teleport_service.load_teleports(db)

    exact = teleport_service.find_teleport("stormwind")
    prefix = teleport_service.find_teleport("gold")
    fuzzy = teleport_service.find_teleport("stormwnd")
    nearest = teleport_service.nearest_teleport(0, -8800.0, 600.0)
    matches = teleport_service.search_teleports("storm")

    assert exact["name"] == "Stormwind"
    assert prefix["name"] == "Goldshire"
    assert fuzzy["name"] == "Stormwind"
    assert nearest["name"] == "Stormwind"
    assert matches == ["Stormwind"]


def test_add_and_remove_teleport_updates_cache_and_db():
    db = _FakeDb()
    teleport_service.TELEPORTS.clear()

    entry = teleport_service.add_teleport(db, "GM Island", 1, 10.0, 20.0, 30.0, 1.5)
    removed = teleport_service.remove_teleport(db, "gm island")

    assert entry["name"] == "GM Island"
    assert "gm island" not in teleport_service.TELEPORTS
    assert removed is True
    assert db.commits == 2
