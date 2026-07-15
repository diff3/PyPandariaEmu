import math
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from server.modules.handlers.world.movements.types import PassengerAttachment
from server.modules.handlers.world.position.publication import (
    publish_absolute,
    publish_transport,
    publish_transport_local_from_absolute,
    publish_transport_local_offset,
)
from server.modules.handlers.world.runtime.player import Player
from server.modules.handlers.world.runtime.player_store import (
    get_player_runtime_store,
)
from server.session.world_session import MovementState


@pytest.fixture(autouse=True)
def _clear_player_store():
    store = get_player_runtime_store()
    store.clear()
    yield
    store.clear()


def _session(**overrides):
    values = {
        "char_guid": 42,
        "world_guid": 42,
        "map_id": 0,
        "instance_id": 0,
        "x": 1.0,
        "y": 2.0,
        "z": 3.0,
        "orientation": 0.25,
        "movement_state": MovementState(),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_publish_absolute_updates_movement_session_and_runtime_player():
    session = _session()
    player = get_player_runtime_store().add(Player.from_session(session))

    publish_absolute(
        session,
        map_id=1,
        instance_id=7,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.5,
    )

    for target in (session, session.movement_state, player):
        assert (target.x, target.y, target.z, target.orientation) == (
            10.0,
            20.0,
            30.0,
            1.5,
        )
    assert (session.map_id, session.instance_id) == (1, 7)
    assert (player.map_id, player.instance_id) == (1, 7)


def test_publish_transport_rotates_local_offset_then_uses_common_publisher():
    session = _session(instance_id=3)
    player = get_player_runtime_store().add(Player.from_session(session))
    attachment = PassengerAttachment(
        passenger_id=42,
        local_x=2.0,
        local_y=1.0,
        local_z=4.0,
        local_o=0.5,
    )
    transport = SimpleNamespace(
        guid=99,
        map_id=1,
        x=100.0,
        y=200.0,
        z=10.0,
        orientation=math.pi / 2.0,
    )

    published = publish_transport(session, transport, attachment)

    assert published.x == pytest.approx(99.0)
    assert published.y == pytest.approx(202.0)
    assert published.z == pytest.approx(14.0)
    assert published.orientation == pytest.approx(math.pi / 2.0 + 0.5)
    assert (player.x, player.y, player.z) == pytest.approx((99.0, 202.0, 14.0))


def test_local_offset_publication_replaces_attachment_and_updates_movement():
    session = _session()
    original = PassengerAttachment(passenger_id=42, source_map=1)
    transport = SimpleNamespace(
        guid=99,
        path_progress_ms=1234,
        passengers={42: original},
    )

    updated = publish_transport_local_offset(
        session,
        transport,
        original,
        local_x=1.0,
        local_y=2.0,
        local_z=3.0,
        local_o=0.75,
        transport_time=4567,
        transport_time2=8,
        transport_time3=9,
        seat=2,
        vehicle_id=11,
    )

    assert updated is transport.passengers[42]
    assert updated is not original
    assert (updated.local_x, updated.local_y, updated.local_z, updated.local_o) == (
        1.0,
        2.0,
        3.0,
        0.75,
    )
    movement = session.movement_state
    assert movement.has_transport_data is True
    assert movement.transport_guid == 99
    assert (movement.transport_x, movement.transport_y, movement.transport_z) == (
        1.0,
        2.0,
        3.0,
    )
    assert movement.transport_orientation == 0.75
    assert movement.transport_time == 4567
    assert movement.transport_time2 == 8
    assert movement.transport_time3 == 9
    assert movement.transport_seat == 2
    assert movement.transport_vehicle_id == 11


def test_inverse_transport_projection_preserves_world_transform_and_normalizes_orientation():
    transport = SimpleNamespace(
        guid=99,
        map_id=1,
        x=100.0,
        y=200.0,
        z=10.0,
        orientation=1.25,
        path_progress_ms=42,
    )
    original = PassengerAttachment(passenger_id=42, attached_at_ms=77)
    transport.passengers = {42: original}
    session = _session(
        map_id=1,
        x=103.25,
        y=198.5,
        z=14.75,
        orientation=0.25,
    )
    expected_world = (session.x, session.y, session.z, session.orientation)

    updated = publish_transport_local_from_absolute(session, transport, original)
    publish_transport(session, transport, updated)

    assert (session.x, session.y, session.z) == pytest.approx(expected_world[:3])
    assert session.orientation == pytest.approx(expected_world[3])
    assert 0.0 <= updated.local_o < math.tau
    assert updated.attached_at_ms == 77


def test_gameplay_modules_have_one_direct_absolute_player_position_writer():
    world_root = Path(__file__).parents[1] / "modules" / "handlers" / "world"
    direct_write = re.compile(
        r"(?:session|player|target|source_session|target_session|movement_state|state)"
        r"\.(?:map_id|instance_id|x|y|z|orientation)\s*="
    )
    offenders = []
    for path in world_root.rglob("*.py"):
        relative = path.relative_to(world_root).as_posix()
        if relative == "position/publication.py":
            continue
        for line_number, line in enumerate(path.read_text().splitlines(), 1):
            if not direct_write.search(line):
                continue
            # RuntimeTransportState owns the transport object's transform; it
            # is a producer, not a player-position representation.
            if relative == "transport_runtime.py":
                continue
            offenders.append(f"{relative}:{line_number}:{line.strip()}")
    assert offenders == []
