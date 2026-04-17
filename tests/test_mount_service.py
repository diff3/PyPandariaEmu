from server.modules.handlers.world.mount import mount_service


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        rows = self.fetchall()
        return rows[0] if rows else None


class _FakeDb:
    def __init__(self, rows=None, *, tables=None):
        self.rows = list(rows or [])
        self.calls = []
        self.tables = set({"spell_effect"} if tables is None else tables)

    def execute(self, query, params=None):
        sql = str(query)
        self.calls.append((sql, dict(params or {})))
        if "FROM information_schema.tables" in sql:
            table_name = str((params or {}).get("table_name") or "")
            if table_name in self.tables:
                return _FakeResult([(1,)])
            return _FakeResult([])
        if "SELECT DISTINCT spell" in sql:
            return _FakeResult(self.rows)
        return _FakeResult([])


def test_load_mount_spells_populates_global_set():
    db = _FakeDb(rows=[(32235,), (32235,), (61425,), ("abc",), (0,)])

    mount_service.ALL_MOUNT_SPELLS.clear()
    mount_service.load_mount_spells(db)

    assert mount_service.ALL_MOUNT_SPELLS == {32235, 61425}


def test_is_mount_spell_checks_loaded_cache():
    mount_service.ALL_MOUNT_SPELLS.clear()
    mount_service.ALL_MOUNT_SPELLS.update({458, 470})

    assert mount_service.is_mount_spell(458) is True
    assert mount_service.is_mount_spell(999999) is False


def test_granted_mount_spells_include_riding_support():
    mount_service.ALL_MOUNT_SPELLS.clear()
    mount_service.ALL_MOUNT_SPELLS.update({72286})

    spells = set(mount_service.granted_mount_spells())

    assert 72286 in spells
    assert 33388 in spells
    assert 33391 in spells
    assert 34090 in spells
    assert 34091 in spells
    assert 54197 in spells
    assert 115913 in spells


def test_load_mount_spells_uses_fallback_when_spell_effect_missing():
    db = _FakeDb(
        rows=[(32235,)],
        tables=set(),
    )

    mount_service.ALL_MOUNT_SPELLS.clear()
    mount_service.load_mount_spells(db)

    assert set(mount_service.FALLBACK_MOUNT_SPELLS).issubset(mount_service.ALL_MOUNT_SPELLS)


def test_get_mount_display_id_returns_specific_mount_displays():
    mount_service.ALL_MOUNT_SPELLS.clear()
    mount_service.ALL_MOUNT_SPELLS.update({458, 470, 578, 580, 61425, 72286})

    assert mount_service.get_mount_display_id(458) == 2404
    assert mount_service.get_mount_display_id(470) == 2402
    assert mount_service.get_mount_display_id(34769) == 19296
    assert mount_service.get_mount_display_id(578) == 2346
    assert mount_service.get_mount_display_id(580) == 247
    assert mount_service.get_mount_display_id(61425) == 27237
    assert mount_service.get_mount_display_id(72286) == 31007
    assert mount_service.get_mount_display_id(999999) == 0


def test_fallback_mount_cases_are_recognized_and_mapped():
    mount_service.ALL_MOUNT_SPELLS.clear()
    mount_service._load_fallback_mount_spells()

    expected_displays = {
        59535: 27659,
        61455: 27240,
        63644: 22471,
        87840: 41711,
        134735: 42703,
    }

    for spell_id, display_id in expected_displays.items():
        assert mount_service.is_mount_spell(spell_id) is True
        assert mount_service.get_mount_display_id(spell_id) == display_id
