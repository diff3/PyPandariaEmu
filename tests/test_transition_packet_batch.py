#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import threading
from types import SimpleNamespace

from server.modules.protocol.packet_batch import (
    PacketBatch,
    bind_packet_batch_to_current_transition,
    send_packet_batch_under_lock,
)


def _session(*, generation: int, owner: str):
    return SimpleNamespace(
        world_transition_generation=generation,
        world_transition_owner=owner,
    )


def test_old_transport_batch_waiting_on_send_lock_is_discarded():
    session = _session(generation=1, owner="transport_worldport")
    batch = bind_packet_batch_to_current_transition(
        session,
        [
            ("SMSG_TRANSFER_PENDING", b"old-transfer"),
            ("SMSG_NEW_WORLD", b"old-world"),
        ],
    )
    send_lock = threading.Lock()
    sent = []
    discarded = []
    send_lock.acquire()

    worker = threading.Thread(
        target=send_packet_batch_under_lock,
        args=(session, batch, send_lock, lambda: sent.extend(batch)),
        kwargs={"on_discard": discarded.append},
    )
    worker.start()
    session.world_transition_generation = 2
    session.world_transition_owner = "ordinary_teleport"
    send_lock.release()
    worker.join(timeout=1.0)

    assert not worker.is_alive()
    assert sent == []
    assert discarded == [batch]


def test_old_transport_create_and_values_batch_is_discarded():
    session = _session(generation=4, owner="ordinary_teleport")
    old_batch = PacketBatch(
        [
            ("SMSG_UPDATE_OBJECT", b"transport-create"),
            ("SMSG_UPDATE_OBJECT", b"transport-values"),
        ],
        transition_bound=True,
        transition_generation=3,
        transition_owner="transport_worldport",
    )
    sent = []

    result = send_packet_batch_under_lock(
        session,
        old_batch,
        threading.Lock(),
        lambda: sent.extend(old_batch),
    )

    assert result is False
    assert sent == []


def test_current_transition_batch_sends_normally():
    session = _session(generation=7, owner="ordinary_teleport")
    batch = bind_packet_batch_to_current_transition(
        session,
        [("SMSG_NEW_WORLD", b"manual-world")],
    )
    sent = []

    result = send_packet_batch_under_lock(
        session,
        batch,
        threading.Lock(),
        lambda: sent.extend(batch),
    )

    assert result is True
    assert sent == [("SMSG_NEW_WORLD", b"manual-world")]


def test_ordinary_packet_list_is_not_transition_gated():
    session = _session(generation=9, owner="ordinary_teleport")
    ordinary = [("SMSG_MESSAGECHAT", b"ordinary")]
    sent = []

    result = send_packet_batch_under_lock(
        session,
        ordinary,
        threading.Lock(),
        lambda: sent.extend(ordinary),
    )

    assert result is True
    assert sent == ordinary


def test_ownership_change_after_socket_write_starts_is_not_cancelled():
    session = _session(generation=11, owner="transport_worldport")
    batch = bind_packet_batch_to_current_transition(
        session,
        [
            ("SMSG_TRANSFER_PENDING", b"started"),
            ("SMSG_NEW_WORLD", b"already-owned"),
        ],
    )
    sent = []

    def send_started_batch():
        sent.append(batch[0])
        session.world_transition_generation = 12
        session.world_transition_owner = "ordinary_teleport"
        sent.append(batch[1])

    result = send_packet_batch_under_lock(
        session,
        batch,
        threading.Lock(),
        send_started_batch,
    )

    assert result is True
    assert sent == list(batch)
