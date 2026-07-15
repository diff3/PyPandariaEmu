import sys
import types
from types import SimpleNamespace

from server.modules.handlers.world.spell_cast.effects import HearthstoneEffect, MountEffect, PetSummonEffect
from server.modules.handlers.world.spell_cast.model import SpellEffectResult
from server.modules.handlers.world.spell_cast.registry import SpellEffectRegistry
from server.modules.handlers.world.spell_cast.service import SpellCastService, SpellSource
from server.modules.protocol.packet_batch import PacketBatch


def _session():
    return SimpleNamespace(char_guid=22, world_guid=0x0003000100000016, player_guid=0x0003000100000016)


def _module(monkeypatch, name, **attrs):
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    monkeypatch.setitem(sys.modules, name, module)
    return module


def test_mount_effect_executes_gameplay_without_spell_packets(monkeypatch):
    calls = []
    spells = _module(monkeypatch, "server.modules.handlers.world.opcodes.spells", handle_mount=lambda session, spell: calls.append(spell) or [("SMSG_AURA_UPDATE", b"aura")], dismount=lambda session: [])
    import server.modules.handlers.world.opcodes as package
    monkeypatch.setattr(package, "spells", spells, raising=False)
    context = SimpleNamespace(session=_session(), spell_id=59535)

    result = MountEffect().execute(context)

    assert result.responses == [("SMSG_AURA_UPDATE", b"aura")]
    assert calls == [59535]


def test_pet_effect_reuses_existing_summon_runtime(monkeypatch):
    calls = []
    pets = _module(monkeypatch, "server.modules.handlers.world.opcodes.pets", summon_companion_pet_by_spell=lambda session, spell: calls.append(spell) or [("SMSG_UPDATE_OBJECT", b"pet")])
    import server.modules.handlers.world.opcodes as package
    monkeypatch.setattr(package, "pets", pets, raising=False)

    result = PetSummonEffect().execute(SimpleNamespace(session=_session(), spell_id=12345))

    assert result.responses == [("SMSG_UPDATE_OBJECT", b"pet")]
    assert calls == [12345]


def test_hearthstone_effect_returns_interrupt_and_only_gameplay_packets(monkeypatch):
    npc = _module(monkeypatch, "server.modules.handlers.world.opcodes.npc_interaction", execute_hearthstone_teleport=lambda session: [("SMSG_TRANSFER_PENDING", b"map"), ("SMSG_NEW_WORLD", b"world")])
    import server.modules.handlers.world.opcodes as package
    monkeypatch.setattr(package, "npc_interaction", npc, raising=False)

    result = HearthstoneEffect().execute(SimpleNamespace(session=_session(), spell_id=8690))

    assert result.status.value == "interrupt"
    assert [opcode for opcode, _ in result.responses] == ["SMSG_TRANSFER_PENDING", "SMSG_NEW_WORLD"]


def test_failed_validation_uses_canonical_cast_failed_packet():
    service = SpellCastService(SpellEffectRegistry())
    responses = service.begin_cast(_session(), spell_id=999999, source=SpellSource.SPELL)

    assert [opcode for opcode, _ in responses] == ["SMSG_CAST_FAILED"]


def test_bitpacked_cast_selects_supported_unaligned_spell_candidate():
    executed = []

    class Effect:
        def execute(self, context):
            executed.append(context.spell_id)
            return SpellEffectResult.success([("SMSG_AURA_UPDATE", b"mount")])

    registry = SpellEffectRegistry()
    registry.register(lambda context: context.spell_id == 148476, Effect())
    service = SpellCastService(registry)

    responses = service.begin_cast_candidates(
        _session(),
        spell_ids=[30432, 148476],
        source=SpellSource.SPELL,
    )

    assert executed == [148476]
    assert responses == [("SMSG_AURA_UPDATE", b"mount")]


def test_bitpacked_cast_preserves_client_cast_counter_for_later_cleanup():
    class Effect:
        def execute(self, context):
            return SpellEffectResult.success()

    registry = SpellEffectRegistry()
    registry.register(lambda context: context.spell_id == 148476, Effect())
    session = _session()
    payload = bytes.fromhex("06220100E076000008FC430200")

    SpellCastService(registry).begin_cast_candidates(
        session,
        spell_ids=[30432, 148476],
        source=SpellSource.SPELL,
        packet_payload=payload,
    )

    assert session.spell_cast_counter == 8


def test_interrupted_cast_uses_canonical_animation_cleanup_before_gameplay():
    class InterruptEffect:
        def execute(self, context):
            return SpellEffectResult.interrupt([("SMSG_TRANSFER_PENDING", b"map")])

    registry = SpellEffectRegistry()
    registry.register(lambda context: True, InterruptEffect())
    responses = SpellCastService(registry).begin_cast(_session(), spell_id=8690, source=SpellSource.ITEM, source_item_entry=6948)

    assert [opcode for opcode, _ in responses] == [
        "SMSG_SPELL_FAILURE",
        "SMSG_SPELL_FAILED_OTHER",
        "SMSG_TRANSFER_PENDING",
    ]


def test_explicit_animation_cleanup_uses_current_cast_and_spell_id():
    session = _session()
    session.spell_cast_counter = 7

    responses = SpellCastService(SpellEffectRegistry()).interrupt_cast(
        session,
        spell_id=148476,
    )

    assert [opcode for opcode, _ in responses] == [
        "SMSG_SPELL_FAILURE",
        "SMSG_SPELL_FAILED_OTHER",
    ]
    assert (148476).to_bytes(4, "little") in responses[0][1]
    assert (148476).to_bytes(4, "little") in responses[1][1]


def test_hearthstone_interrupt_preserves_worldport_packet_batch_ownership():
    class InterruptEffect:
        def execute(self, context):
            batch = PacketBatch(
                [("SMSG_TRANSFER_PENDING", b"map"), ("SMSG_NEW_WORLD", b"world")],
                transition_generation=7,
                transition_owner="hearthstone",
            )
            return SpellEffectResult.interrupt(batch)

    registry = SpellEffectRegistry()
    registry.register(lambda context: True, InterruptEffect())
    responses = SpellCastService(registry).begin_cast(_session(), spell_id=8690, source=SpellSource.ITEM, source_item_entry=6948)

    assert isinstance(responses, PacketBatch)
    assert responses.transition_generation == 7
    assert responses.transition_owner == "hearthstone"
