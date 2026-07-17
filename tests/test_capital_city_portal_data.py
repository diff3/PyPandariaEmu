from pathlib import Path


MIGRATION = (
    Path(__file__).resolve().parents[2]
    / "sql"
    / "world"
    / "2026_07_17_capital_city_portals.sql"
)


def test_capital_city_portal_migration_restores_alliance_earthshrine():
    sql = MIGRATION.read_text(encoding="utf-8")

    for entry in (207692, 207693, 207694, 207695):
        assert str(entry) in sql
    for entry in (207690, 207691):
        assert str(entry) in sql


def test_capital_city_portal_migration_repairs_pandaria_spell_chain():
    sql = MIGRATION.read_text(encoding="utf-8")

    assert "WHEN 215424 THEN 130698" in sql
    assert "WHEN 215457 THEN 130703" in sql
    assert "`IconName` = ''" in sql
    assert "`castBarCaption` = ''" in sql
    assert "(130696, 0, 870," in sql
    assert "(130702, 0, 870," in sql


def test_capital_city_portal_migration_adds_temporary_vashjir_targets():
    sql = MIGRATION.read_text(encoding="utf-8")

    assert "WHEN 207690 THEN 90244" in sql
    assert "WHEN 207691 THEN 90245" in sql
    assert "(90244, 0, 0, -4556.46, 3470.22, -101.461, 3.21141)" in sql
    assert "(90245, 0, 0, -4556.46, 3470.22, -101.461, 3.21141)" in sql
    assert "TODO: Replace this temporary Smuggler's Scar destination" in sql
