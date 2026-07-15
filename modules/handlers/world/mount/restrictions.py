"""Central mount-permission evaluation driven by resolved world metadata."""

from __future__ import annotations

from typing import Any

from server.modules.handlers.world.position.area_service import area_flags

AREA_FLAG_INSIDE = 0x02000000
AREA_FLAG_NO_FLY_ZONE = 0x20000000


def mount_illegal_reason(session: Any, *, flying: bool = False) -> str | None:
    if bool(getattr(session, "mounting_forbidden", False)):
        return "explicit-session-restriction"
    area_id = int(getattr(session, "current_area", 0) or getattr(session, "zone", 0) or 0)
    zone_id = int(getattr(session, "zone", 0) or 0)
    forbidden = set(int(value) for value in (getattr(session, "no_mount_area_ids", ()) or ()))
    if area_id in forbidden or zone_id in forbidden:
        return "explicit-area-restriction"
    flags = area_flags(area_id) | area_flags(zone_id)
    if flags & AREA_FLAG_INSIDE:
        return "indoor-area"
    if flying and flags & AREA_FLAG_NO_FLY_ZONE:
        return "no-fly-area"
    allowed_maps = getattr(session, "mount_allowed_map_ids", None)
    if allowed_maps is not None and int(getattr(session, "map_id", 0) or 0) not in set(allowed_maps):
        return "map-restriction"
    return None


def enforce_active_mount_legality(session: Any) -> list[tuple[str, bytes]]:
    from server.modules.handlers.world.active_aura import AURA_EFFECT_MOUNT, find_by_effect
    from server.modules.handlers.world.mount.mount_service import is_flying_mount_spell
    from server.modules.handlers.world.opcodes import spells

    aura = find_by_effect(session, AURA_EFFECT_MOUNT)
    if aura is None:
        return []
    reason = mount_illegal_reason(session, flying=is_flying_mount_spell(int(aura.spell_id)))
    if reason is None:
        return []
    from shared.Logger import Logger

    Logger.info("[Mount] automatic aura removal guid=%s spell=%s reason=%s", int(getattr(session, "char_guid", 0) or 0), int(aura.spell_id), reason)
    return list(spells.dismount(session))
