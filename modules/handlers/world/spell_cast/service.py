from __future__ import annotations

from enum import Enum
import struct
from typing import Any

from DSL.modules.bitsHandler import BitWriter
from server.modules.handlers.world.active_aura import aura_owner_guid
from server.modules.protocol.packet_batch import preserve_packet_batch_metadata
from .effects import build_supported_effect_registry
from .model import CastStatus, SpellCastContext


class SpellSource(str, Enum):
    SPELL = "spell"
    ITEM = "item"


class SpellCastService:
    def __init__(self, registry=None) -> None:
        self.registry = registry or build_supported_effect_registry()

    @staticmethod
    def _next_cast_count(session: Any) -> int:
        value = (int(getattr(session, "spell_cast_counter", 0) or 0) + 1) & 0xFF
        session.spell_cast_counter = value
        return value

    def begin_cast(self, session: Any, *, spell_id: int, source: SpellSource, source_item_entry: int = 0, target_guid: int = 0, cast_count: int | None = None):
        spell_id = int(spell_id or 0)
        if cast_count is None:
            cast_count = self._next_cast_count(session)
        else:
            cast_count = int(cast_count) & 0xFF
            session.spell_cast_counter = cast_count
        caster_guid = aura_owner_guid(session)
        context = SpellCastContext(session, spell_id, cast_count, caster_guid, int(target_guid or caster_guid), source, int(source_item_entry))
        if spell_id <= 0:
            return self._failure(context, 1)
        try:
            from server.modules.handlers.world.taxi_runtime import is_taxi_active
            if is_taxi_active(session):
                return self._failure(context, 1)
        except Exception:
            pass
        effect = self.registry.resolve(context)
        if effect is None:
            return self._failure(context, 1)
        result = effect.execute(context)
        responses = list(result.responses)
        if result.status is CastStatus.FAILURE:
            responses = self._cast_failed(context, result.reason) + responses
        elif result.status is CastStatus.INTERRUPT:
            responses = self._interrupt(context, result.reason) + responses
        return preserve_packet_batch_metadata(result.responses, responses)

    def begin_cast_candidates(
        self,
        session: Any,
        *,
        spell_ids,
        source: SpellSource,
        source_item_entry: int = 0,
        target_guid: int = 0,
        packet_payload: bytes = b"",
    ):
        """Resolve a supported spell from packet-layout candidates, then cast it.

        MoP cast packets are bit-packed and may place the spell id at an
        unaligned byte offset. Candidate probing deliberately does not allocate
        a cast counter; only the selected canonical cast does that.
        """
        candidates: list[int] = []
        for value in spell_ids or ():
            value = int(value or 0)
            if 0 < value <= 500000 and value not in candidates:
                candidates.append(value)

        caster_guid = aura_owner_guid(session)
        resolved = None
        for spell_id in candidates:
            probe = SpellCastContext(
                session,
                spell_id,
                0,
                caster_guid,
                int(target_guid or caster_guid),
                source,
                int(source_item_entry),
            )
            if self.registry.resolve(probe) is not None:
                resolved = spell_id
                break

        packet_cast_count = None
        if resolved is not None and packet_payload:
            marker = int(resolved).to_bytes(4, "little")
            offset = bytes(packet_payload).find(marker)
            if offset > 0:
                packet_cast_count = int(packet_payload[offset - 1])

        return self.begin_cast(
            session,
            spell_id=int(resolved or (candidates[0] if candidates else 0)),
            source=source,
            source_item_entry=source_item_entry,
            target_guid=target_guid,
            cast_count=packet_cast_count,
        )

    def _failure(self, context: SpellCastContext, reason: int):
        return self._cast_failed(context, reason)

    def interrupt_cast(self, session: Any, *, spell_id: int, reason: int = 0, cast_count: int | None = None):
        """Emit SkyFire 5.4.8's canonical client animation cleanup."""
        caster_guid = aura_owner_guid(session)
        context = SpellCastContext(
            session,
            int(spell_id or 0),
            int(
                getattr(session, "spell_cast_counter", 0)
                if cast_count is None
                else cast_count
            ) & 0xFF,
            caster_guid,
            caster_guid,
            SpellSource.SPELL,
            0,
        )
        if context.spell_id <= 0:
            return []
        return self._interrupt(context, int(reason))

    @staticmethod
    def _cast_failed(context: SpellCastContext, reason: int):
        return [("SMSG_CAST_FAILED", struct.pack("<IIBB", context.spell_id, int(reason), context.cast_count, 0xC0))]

    @staticmethod
    def _guid_bytes(payload: bytearray, raw: bytes, order):
        for index in order:
            if raw[index]:
                payload.append(raw[index] ^ 1)

    def _interrupt(self, context: SpellCastContext, reason: int):
        raw = int(context.caster_guid).to_bytes(8, "little")
        bits = BitWriter()
        for index in (7, 3, 6, 2, 1, 5, 0, 4): bits.write_bits(bool(raw[index]), 1)
        failure = bytearray(bits.getvalue())
        self._guid_bytes(failure, raw, (2, 6, 7, 0, 3, 1))
        failure.extend(struct.pack("<BIB", context.cast_count, context.spell_id, int(reason) & 0xFF))
        self._guid_bytes(failure, raw, (4, 5))
        bits = BitWriter()
        for index in (7, 0, 5, 6, 1, 4, 3, 2): bits.write_bits(bool(raw[index]), 1)
        other = bytearray(bits.getvalue())
        self._guid_bytes(other, raw, (0, 1)); other.append(int(reason) & 0xFF)
        self._guid_bytes(other, raw, (7, 5, 6)); other.extend(struct.pack("<IB", context.spell_id, context.cast_count))
        self._guid_bytes(other, raw, (4, 2, 3))
        return [("SMSG_SPELL_FAILURE", bytes(failure)), ("SMSG_SPELL_FAILED_OTHER", bytes(other))]


_SERVICE: SpellCastService | None = None


def get_spell_cast_service() -> SpellCastService:
    global _SERVICE
    if _SERVICE is None:
        _SERVICE = SpellCastService()
    return _SERVICE
