import math
from types import SimpleNamespace

from world.position import position_service


class _FakeDbApi:
    def __init__(self, row=None):
        self.row = row or SimpleNamespace(
            guid=42,
            realm=1,
            map=1,
            zone=876,
            instance_id=0,
            position_x=100.123456,
            position_y=200.654321,
            position_z=50.987654,
            orientation=7.5,
        )
        self.saved_calls = []
        self.online_calls = []

    def get_character(self, player_id, realm_id):
        if int(player_id) != int(getattr(self.row, "guid", 0)):
            return None
        if int(realm_id) != int(getattr(self.row, "realm", 0)):
            return None
        return self.row

    def save_character_position(self, player_id, realm_id, **kwargs):
        self.saved_calls.append((int(player_id), int(realm_id), dict(kwargs)))
        return True

    def save_character_online_state(self, player_id, realm_id, **kwargs):
        self.online_calls.append((int(player_id), int(realm_id), dict(kwargs)))
        return True


def test_normalize_position_rounds_and_clamps_orientation():
    pos = position_service.Position(
        map=1,
        x=123.123456,
        y=-456.654321,
        z=78.987654,
        orientation=(math.tau * 3) + 1.23456789,
    )

    normalized = position_service.normalize_position(pos)

    assert normalized == position_service.Position(
        map=1,
        x=123.1235,
        y=-456.6543,
        z=78.9877,
        orientation=1.234568,
    )


def test_position_moved_enough_uses_distance_and_map_change():
    old = position_service.Position(map=1, x=10.0, y=10.0, z=10.0, orientation=0.0)
    near = position_service.Position(map=1, x=10.5, y=10.5, z=10.0, orientation=1.0)
    far = position_service.Position(map=1, x=12.0, y=10.0, z=10.0, orientation=0.0)
    different_map = position_service.Position(map=0, x=10.0, y=10.0, z=10.0, orientation=0.0)

    assert position_service.position_moved_enough(old, near, threshold=1.0) is False
    assert position_service.position_moved_enough(old, far, threshold=1.0) is True
    assert position_service.position_moved_enough(old, different_map, threshold=1.0) is True


def test_save_player_position_normalizes_before_write():
    db_api = _FakeDbApi()
    new_pos = position_service.Position(
        map=1,
        x=100.999991,
        y=201.000009,
        z=51.111119,
        orientation=-0.5,
    )

    ok = position_service.save_player_position(
        42,
        new_pos,
        "autosave",
        realm_id=1,
        zone=876,
        instance_id=0,
        online=1,
        player_name="Tester",
        db_api=db_api,
    )

    assert ok is True
    assert len(db_api.saved_calls) == 1
    _, _, kwargs = db_api.saved_calls[0]
    assert kwargs["x"] == 101.0
    assert kwargs["y"] == 201.0
    assert kwargs["z"] == 51.1111
    assert kwargs["orientation"] == round(math.tau - 0.5, 6)


def test_save_player_position_rejects_invalid_and_updates_online_state_only():
    db_api = _FakeDbApi()
    invalid = position_service.Position(map=1, x=0.0, y=0.0, z=float("inf"), orientation=0.0)

    ok = position_service.save_player_position(
        42,
        invalid,
        "logout",
        realm_id=1,
        online=0,
        logout_time=123,
        db_api=db_api,
    )

    assert ok is True
    assert db_api.saved_calls == []
    assert len(db_api.online_calls) == 1
