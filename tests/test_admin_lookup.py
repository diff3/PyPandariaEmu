import sys
import types

sys.modules.setdefault("pymysql", types.ModuleType("pymysql"))

from admin_panel.modules import lookup


def test_item_lookup_adds_icon_from_display_info(monkeypatch):
    monkeypatch.setattr(lookup, "_item_icon_names", lambda: {6418: "inv_misc_rune_01"})

    rows = lookup._add_item_icons(
        [{"id": 6948, "visual_id": 6418, "name": "Hearthstone", "quality": 1}]
    )

    assert rows[0]["icon_name"] == "inv_misc_rune_01"
    assert rows[0]["icon_url"] == (
        "https://wow.zamimg.com/images/wow/icons/large/inv_misc_rune_01.jpg"
    )
    assert rows[0]["quality_name"] == "Common"


def test_item_lookup_uses_question_mark_for_unknown_display(monkeypatch):
    monkeypatch.setattr(lookup, "_item_icon_names", lambda: {})

    rows = lookup._add_item_icons([{"id": 1, "visual_id": 999999, "quality": 4}])

    assert rows[0]["icon_name"] == "inv_misc_questionmark"
    assert rows[0]["quality_name"] == "Epic"
