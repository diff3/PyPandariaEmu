from __future__ import annotations

from .model import SpellCastContext, SpellEffectResult
from .registry import SpellEffectRegistry


class MountEffect:
    def execute(self, context: SpellCastContext) -> SpellEffectResult:
        from server.modules.handlers.world.opcodes import spells

        session = context.session
        pending_cancel_spell = int(getattr(session, "pending_mount_cancel_spell", 0) or 0)
        if pending_cancel_spell:
            session.pending_mount_cancel_spell = None
            if pending_cancel_spell == context.spell_id and not bool(getattr(session, "is_mounted", False)):
                return SpellEffectResult.success()
        if int(getattr(session, "mount_spell", 0) or 0) == context.spell_id and bool(getattr(session, "is_mounted", False)):
            return SpellEffectResult.success(spells.dismount(session))
        return SpellEffectResult.success(spells.handle_mount(session, context.spell_id))


class PetSummonEffect:
    def execute(self, context: SpellCastContext) -> SpellEffectResult:
        from server.modules.handlers.world.opcodes import pets

        return SpellEffectResult.success(pets.summon_companion_pet_by_spell(context.session, context.spell_id))


class HearthstoneEffect:
    def execute(self, context: SpellCastContext) -> SpellEffectResult:
        from server.modules.handlers.world.opcodes import npc_interaction

        return SpellEffectResult.interrupt(npc_interaction.execute_hearthstone_teleport(context.session))


def build_supported_effect_registry() -> SpellEffectRegistry:
    from server.modules.handlers.world.pet.pet_service import battle_pet_by_spell

    registry = SpellEffectRegistry()
    def is_supported_mount(ctx):
        from server.modules.handlers.world.opcodes import spells
        return bool(spells.is_mount_spell(ctx.spell_id))

    registry.register(is_supported_mount, MountEffect())
    registry.register(lambda ctx: battle_pet_by_spell(ctx.spell_id) is not None, PetSummonEffect())
    registry.register(lambda ctx: ctx.spell_id == 8690, HearthstoneEffect())
    return registry
