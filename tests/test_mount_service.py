from world.mount import mount_service


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        rows = self.fetchall()
        return rows[0] if rows else None


class _FakeDb:
    def __init__(self, rows=None, *, tables=None, row_counts=None):
        self.rows = list(rows or [])
        self.calls = []
        self.tables = set(tables or {"spell_effect"})
        self.row_counts = dict(row_counts or {})

    def execute(self, query, params=None):
        sql = str(query)
        self.calls.append((sql, dict(params or {})))
        if "FROM information_schema.tables" in sql:
            table_name = str((params or {}).get("table_name") or "")
            if table_name in self.tables:
                return _FakeResult([(1,)])
            return _FakeResult([])
        if "SELECT COUNT(*) FROM" in sql:
            table_name = sql.split("FROM", 1)[1].strip().split()[0]
            return _FakeResult([(int(self.row_counts.get(table_name, 0)),)])
        if "SELECT DISTINCT spell" in sql or "SELECT DISTINCT EffectSpellId AS spell" in sql:
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


def test_load_mount_spells_skips_incomplete_spelleffect_dbc():
    db = _FakeDb(
        rows=[(32235,)],
        tables={"spelleffect_dbc"},
        row_counts={"spelleffect_dbc": 73},
    )

    mount_service.ALL_MOUNT_SPELLS.clear()
    mount_service.load_mount_spells(db)

    assert set(mount_service.FALLBACK_TEST_MOUNT_SPELLS).issubset(mount_service.ALL_MOUNT_SPELLS)


def test_get_mount_display_id_returns_known_test_mapping():
    mount_service.ALL_MOUNT_SPELLS.clear()
    mount_service.ALL_MOUNT_SPELLS.update({72286, 34769})

    assert mount_service.get_mount_display_id(72286) == 31007
    assert mount_service.get_mount_display_id(34769) == 31007
    assert mount_service.get_mount_display_id(999999) == 0
