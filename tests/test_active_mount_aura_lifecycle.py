from types import SimpleNamespace

from server.modules.handlers.world.active_aura import (
    AURA_EFFECT_MOUNT,
    ActiveAura,
    aura_owner_guid,
    build_aura_update,
    find_by_effect,
    register,
    replay_response,
)
from server.modules.protocol.PacketContext import PacketContext
from server.tests.test_spells_mount_visual import _import_spells_handlers


def _session(**overrides):
    values = dict(
        char_guid=7,
        world_guid=0x0003000100000007,
        player_guid=0x0003000100000007,
        level=90,
        active_mount_aura_slot=0,
        active_mount_aura_spell_id=None,
        active_auras={},
        mount_spell=59535,
        is_mounted=True,
        current_area=1,
        zone=1,
        map_id=0,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def test_mount_aura_registry_and_wire_spell_id():
    spells = _import_spells_handlers()

    session = _session(active_auras={}, active_mount_aura_spell_id=None)
    responses = spells.apply_mount_aura(session, 59535)
    aura = find_by_effect(session, AURA_EFFECT_MOUNT)

    assert aura is not None
    assert aura.spell_id == 59535
    assert aura.cancelable is True
    assert aura.positive is True
    assert aura.duration_ms == -1
    assert (59535).to_bytes(4, "little") in responses[0][1]


def test_cancel_aura_requires_current_spell_and_slot(monkeypatch):
    spells = _import_spells_handlers()

    session = _session(active_auras={})
    spells.apply_mount_aura(session, 59535)
    calls = []
    monkeypatch.setattr(spells, "dismount", lambda owner: calls.append(owner) or [("SMSG_AURA_UPDATE", b"off")])

    stale = PacketContext(None, "CMSG", 0, "CMSG_CANCEL_AURA", b"", {"spell_id": 59535, "slot": 2})
    assert spells.handle_cancel_aura(session, stale) == (0, None)
    valid = PacketContext(None, "CMSG", 0, "CMSG_CANCEL_AURA", b"", {"spell_id": 59535, "slot": 0})
    assert spells.handle_cancel_aura(session, valid)[1] == [("SMSG_AURA_UPDATE", b"off")]
    assert calls == [session]


def test_stale_cancel_after_removal_is_harmless():
    spells = _import_spells_handlers()

    session = _session(active_auras={}, is_mounted=False, mount_spell=None)
    request = PacketContext(None, "CMSG", 0, "CMSG_CANCEL_AURA", b"", {"spell_id": 59535, "slot": 0})
    assert spells.handle_cancel_aura(session, request) == (0, None)


def test_right_clicking_generic_test_buff_removes_only_that_aura(monkeypatch):
    spells = _import_spells_handlers()
    session = _session(active_auras={}, is_mounted=True, mount_spell=59535)
    spells.apply_mount_aura(session, 59535)
    spells.apply_active_aura(session, 21562, applied_effects=("test_buff",))
    monkeypatch.setattr(spells, "dismount", lambda _owner: (_ for _ in ()).throw(AssertionError("must not dismount")))

    request = PacketContext(None, "CMSG", 0, "CMSG_CANCEL_AURA", b"", {"spell_id": 21562, "slot": 1})
    responses = spells.handle_cancel_aura(session, request)[1]

    assert responses[0][0] == "SMSG_AURA_UPDATE"
    assert find_by_effect(session, AURA_EFFECT_MOUNT) is not None
    assert 1 not in session.active_auras


def test_generic_aura_uses_skyfire_first_free_visible_slot():
    spells = _import_spells_handlers()
    session = _session(active_auras={}, is_mounted=False, mount_spell=None)

    spells.apply_active_aura(session, 21562, applied_effects=("test_buff",))

    assert set(session.active_auras) == {0}


def test_aura_uses_same_compact_player_guid_as_create_object():
    session = _session(char_guid=22, world_guid=0x0003000100000016, player_guid=0x0003000100000016, active_auras={})
    client_guid = aura_owner_guid(session)
    aura = ActiveAura(21562, 0, client_guid, applied_effects=("test_buff",), caster_level=90)

    payload = build_aura_update(session, [aura], full_replay=True)

    assert client_guid == 22
    assert payload[:4] == bytes.fromhex("40000044")
    assert payload[-1:] == bytes((0x17,))


def test_dismount_packet_targets_compact_create_object_guid_with_skyfire_xor():
    spells = _import_spells_handlers()
    session = _session(char_guid=22, world_guid=0x0003000100000016, player_guid=0x0003000100000016)

    payload = spells.build_smsg_dismount_payload(session)

    # Mask order (6,3,0,7,1,2,5,4): compact guid byte 0 is present.
    assert payload[0] == 0x20
    # Byte order (3,6,7,5,1,4,2,0), WriteByteSeq XORs each present byte.
    assert payload[1:] == bytes((0x17,))


def test_full_replay_contains_active_mount_and_sets_replay_bit():
    session = _session(active_auras={})
    aura = ActiveAura(59535, 0, session.world_guid, applied_effects=(AURA_EFFECT_MOUNT,), caster_level=90)
    register(session, aura)
    opcode, payload = replay_response(session)

    assert opcode == "SMSG_AURA_UPDATE"
    assert payload != build_aura_update(session, [aura], full_replay=False)
    assert (59535).to_bytes(4, "little") in payload


def test_applying_another_mount_replaces_the_single_mount_slot():
    spells = _import_spells_handlers()
    session = _session(active_auras={})

    spells.apply_mount_aura(session, 59535)
    spells.apply_mount_aura(session, 72286)

    assert len(session.active_auras) == 1
    assert find_by_effect(session, AURA_EFFECT_MOUNT).spell_id == 72286


def test_indoor_area_uses_canonical_dismount_and_does_not_remount(monkeypatch):
    from server.modules.handlers.world.mount import restrictions
    spells = _import_spells_handlers()

    session = _session(active_auras={})
    spells.apply_mount_aura(session, 59535)
    monkeypatch.setattr(restrictions, "area_flags", lambda area_id: restrictions.AREA_FLAG_INSIDE if area_id == 99 else 0)
    calls = []

    def remove(owner):
        calls.append(owner.current_area)
        spells.remove_mount_aura(owner)
        owner.is_mounted = False
        owner.mount_spell = None
        return [("SMSG_AURA_UPDATE", b"off")]

    monkeypatch.setattr(spells, "dismount", remove)
    session.current_area = 99
    assert restrictions.enforce_active_mount_legality(session) == [("SMSG_AURA_UPDATE", b"off")]
    session.current_area = 1
    assert restrictions.enforce_active_mount_legality(session) == []
    assert calls == [99]
