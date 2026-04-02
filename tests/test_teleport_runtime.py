from server.modules.handlers.world.teleport.runtime import teleport_player


class _FakePlayer:
    def __init__(self, *, map_id=1, zone=13):
        self.map_id = map_id
        self.zone = zone
        self.instance_id = 7
        self.x = 1.0
        self.y = 2.0
        self.z = 3.0
        self.orientation = 4.0
        self.teleport_pending = False
        self.teleport_destination = None


def test_same_map_teleport_uses_near_flow(monkeypatch):
    calls = []

    def fake_build_login_packet(opcode_name, ctx):
        calls.append((opcode_name, int(getattr(ctx, "map_id", -1))))
        return opcode_name.encode("ascii")

    monkeypatch.setattr(
        "server.modules.handlers.world.teleport.runtime.build_login_packet",
        fake_build_login_packet,
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.teleport.runtime.resolve_zone_from_position",
        lambda map_id, x, y: 14,
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.teleport.runtime.capture_persist_position_from_session",
        lambda player: setattr(player, "_persist_captured", True),
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.teleport.runtime.mark_position_dirty",
        lambda player: setattr(player, "position_dirty", True),
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.teleport.runtime.encode_skyfire_messagechat_system_payload",
        lambda message: message.encode("utf-8"),
    )

    player = _FakePlayer(map_id=1, zone=13)
    responses = teleport_player(
        player,
        1,
        100.0,
        200.0,
        300.0,
        1.25,
        destination_name="Orgrimmar",
    )

    assert [opcode for opcode, _ in responses] == ["SMSG_MESSAGECHAT", "SMSG_MOVE_TELEPORT"]
    assert calls == []
    assert player.teleport_pending is False
    assert getattr(player, "near_teleport_pending", False) is True
    assert player.teleport_destination == "Orgrimmar"
    assert player.map_id == 1
    assert player.zone == 14
    assert player.instance_id == 0
    assert (player.x, player.y, player.z, player.orientation) == (100.0, 200.0, 300.0, 1.25)


def test_cross_map_teleport_still_uses_transfer_flow(monkeypatch):
    monkeypatch.setattr(
        "server.modules.handlers.world.teleport.runtime.build_login_packet",
        lambda opcode_name, ctx: opcode_name.encode("ascii"),
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.teleport.runtime.resolve_zone_from_position",
        lambda map_id, x, y: 0,
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.teleport.runtime.capture_persist_position_from_session",
        lambda player: None,
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.teleport.runtime.mark_position_dirty",
        lambda player: None,
    )
    monkeypatch.setattr(
        "server.modules.handlers.world.teleport.runtime.encode_skyfire_messagechat_system_payload",
        lambda message: message.encode("utf-8"),
    )

    player = _FakePlayer(map_id=0, zone=12)
    responses = teleport_player(
        player,
        1,
        10.0,
        20.0,
        30.0,
        0.5,
        destination_name="Orgrimmar",
    )

    assert [opcode for opcode, _ in responses] == ["SMSG_MESSAGECHAT", "SMSG_TRANSFER_PENDING", "SMSG_NEW_WORLD"]
    assert player.teleport_pending is True
