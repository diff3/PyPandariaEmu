from server.modules.database.DatabaseConnection import DatabaseConnection


class _FakeQuery:
    def __init__(self):
        self.populate_existing_called = False

    def populate_existing(self):
        self.populate_existing_called = True
        return self

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def all(self):
        return []

    def one_or_none(self):
        return None


class _FakeSession:
    def __init__(self):
        self.expire_all_called = False
        self.query_obj = _FakeQuery()

    def expire_all(self):
        self.expire_all_called = True

    def query(self, *args, **kwargs):
        return self.query_obj


def test_get_characters_for_account_forces_fresh_rows(monkeypatch):
    fake_session = _FakeSession()
    monkeypatch.setattr(DatabaseConnection, "chars", staticmethod(lambda: fake_session))

    DatabaseConnection.get_characters_for_account(1, 1)

    assert fake_session.expire_all_called is True
    assert fake_session.query_obj.populate_existing_called is True


def test_get_character_forces_fresh_row(monkeypatch):
    fake_session = _FakeSession()
    monkeypatch.setattr(DatabaseConnection, "chars", staticmethod(lambda: fake_session))

    DatabaseConnection.get_character(7, 1)

    assert fake_session.expire_all_called is True
    assert fake_session.query_obj.populate_existing_called is True
