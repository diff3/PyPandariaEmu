#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path

from server.modules.handlers.world.movements import cache
from server.modules.handlers.world.movements.cache import _reverse_elevator_nodes_preserving_time
from server.modules.handlers.world.movements.types import MovementNode


def test_reversed_elevator_nodes_keep_monotonic_times():
    nodes = [
        MovementNode(map_id=0, x=0.0, y=0.0, z=0.0, time_ms=0),
        MovementNode(map_id=0, x=0.0, y=0.0, z=10.0, time_ms=5000),
        MovementNode(map_id=0, x=0.0, y=0.0, z=20.0, time_ms=10000),
    ]

    reversed_nodes = _reverse_elevator_nodes_preserving_time(nodes)

    assert [node.time_ms for node in reversed_nodes] == [0, 5000, 10000]
    assert [node.z for node in reversed_nodes] == [20.0, 10.0, 0.0]


def test_transport_animation_loader_reverses_positions_without_reversing_time(monkeypatch):
    monkeypatch.setattr(cache, "_dbc_file", lambda _filename: Path("/tmp/TransportAnimation.dbc"))
    monkeypatch.setattr(
        cache,
        "read_dbc",
        lambda _path, _fmt: (
            (1, 999020, 0, 0.0, 0.0, 0.0, 0),
            (2, 999020, 5000, 0.0, 0.0, 10.0, 0),
            (3, 999020, 10000, 0.0, 0.0, 20.0, 0),
        ),
    )
    monkeypatch.setattr(cache, "_inject_legacy_elevator_templates", lambda _templates: None)

    templates = cache._load_transport_animation_templates()

    template = templates[999020]
    assert [node.time_ms for node in template.nodes] == [0, 5000, 10000]
    assert [node.z for node in template.nodes] == [20.0, 10.0, 0.0]
