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
    def __init__(self, rows=None, *, tables=None, creature_rows=None):
        self.rows = list(rows or [])
        self.creature_rows = list(creature_rows or [])
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
        if "FROM creature_template" in sql:
            return _FakeResult(self.creature_rows)
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
    assert 90265 in spells
    assert 90267 in spells
    assert 115913 in spells
    assert 130487 in spells


def test_load_mount_spells_uses_fallback_when_spell_effect_missing():
    db = _FakeDb(
        rows=[(32235,)],
        tables=set(),
    )

    mount_service.ALL_MOUNT_SPELLS.clear()
    mount_service.load_mount_spells(db)

    assert set(mount_service.FALLBACK_MOUNT_SPELLS).issubset(mount_service.ALL_MOUNT_SPELLS)


def test_load_mount_spells_from_dbc_updates_display_and_flying(monkeypatch, tmp_path):
    spell_effect_path = tmp_path / "SpellEffect.dbc"
    spell_effect_path.write_bytes(b"stub")
    (tmp_path / "MountType.dbc").write_bytes(b"stub")
    (tmp_path / "MountCapability.dbc").write_bytes(b"stub")
    mounted_brown_horse = [0] * 30
    mounted_brown_horse[mount_service._SPELL_EFFECT_EFFECT_INDEX] = mount_service._SPELL_EFFECT_APPLY_AURA
    mounted_brown_horse[mount_service._SPELL_EFFECT_AURA_INDEX] = mount_service._SPELL_AURA_MOUNTED
    mounted_brown_horse[mount_service._SPELL_EFFECT_MISC_VALUE_INDEX] = 284
    mounted_brown_horse[mount_service._SPELL_EFFECT_MISC_VALUE_B_INDEX] = 230
    mounted_brown_horse[mount_service._SPELL_EFFECT_SPELL_ID_INDEX] = 458
    mounted_ebon_gryphon = [0] * 30
    mounted_ebon_gryphon[mount_service._SPELL_EFFECT_EFFECT_INDEX] = mount_service._SPELL_EFFECT_APPLY_AURA
    mounted_ebon_gryphon[mount_service._SPELL_EFFECT_AURA_INDEX] = mount_service._SPELL_AURA_MOUNTED
    mounted_ebon_gryphon[mount_service._SPELL_EFFECT_MISC_VALUE_INDEX] = 18357
    mounted_ebon_gryphon[mount_service._SPELL_EFFECT_MISC_VALUE_B_INDEX] = 248
    mounted_ebon_gryphon[mount_service._SPELL_EFFECT_SPELL_ID_INDEX] = 32239
    ground_capability = [226, 29, 75, 0, 0, 0, 86457, 0xFFFFFFFF]
    flying_capability = [241, 7, 225, 0, 0, 0, 86459, 530]
    ground_mount_type = [230, 226] + ([0] * 23)
    flying_mount_type = [248, 226, 241] + ([0] * 22)

    monkeypatch.setattr(mount_service, "get_dbc_root", lambda: tmp_path)

    def fake_read_dbc(path, _fmt):
        name = path.name
        if name == "SpellEffect.dbc":
            return [mounted_brown_horse, mounted_ebon_gryphon]
        if name == "MountCapability.dbc":
            return [ground_capability, flying_capability]
        if name == "MountType.dbc":
            return [ground_mount_type, flying_mount_type]
        return []

    monkeypatch.setattr(mount_service, "read_dbc", fake_read_dbc)
    db = _FakeDb(
        rows=[],
        tables={"creature_template"},
        creature_rows=[
            (284, "Brown Horse", 2404),
            (18357, "Ebon Gryphon", 17694),
        ],
    )

    mount_service.ALL_MOUNT_SPELLS.clear()
    mount_service.load_mount_spells(db)

    assert mount_service.is_mount_spell(458) is True
    assert mount_service.get_mount_display_id(458) == 2404
    assert mount_service.is_mount_spell(32239) is True
    assert mount_service.get_mount_display_id(32239) == 17694
    assert mount_service.is_flying_mount_spell(32239) is True
    assert mount_service.is_flying_mount_spell(458) is False


def test_cloud_serpent_names_are_detected_as_flying_mounts():
    assert mount_service._is_flying_mount_name("Azure Cloud Serpent") is True
    assert mount_service._is_flying_mount_name("Red Flying Cloud") is True
    assert mount_service._is_flying_mount_name("Bloodbathed Frostbrood Vanquisher") is True


def test_get_mount_display_id_returns_specific_mount_displays():
    mount_service.ALL_MOUNT_SPELLS.clear()
    mount_service.ALL_MOUNT_SPELLS.update({458, 72286})

    assert mount_service.get_mount_display_id(458) == 2404
    assert mount_service.get_mount_display_id(72286) == 31007
    assert mount_service.get_mount_display_id(999999) == 0


def test_fallback_mount_cases_include_one_ground_and_one_flying_mount():
    mount_service.ALL_MOUNT_SPELLS.clear()
    mount_service._load_fallback_mount_spells()

    expected_displays = {
        458: 2404,
        72286: 31007,
    }

    for spell_id, display_id in expected_displays.items():
        assert mount_service.is_mount_spell(spell_id) is True
        assert mount_service.get_mount_display_id(spell_id) == display_id
    assert mount_service.is_flying_mount_spell(458) is False
    assert mount_service.is_flying_mount_spell(72286) is True
