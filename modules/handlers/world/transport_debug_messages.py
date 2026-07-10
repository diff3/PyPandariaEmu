from __future__ import annotations

from typing import Any


def enabled() -> bool:
    try:
        from server.modules.handlers.world.feature_config import (
            transport_debug_messages_enabled,
        )

        return bool(transport_debug_messages_enabled())
    except Exception:
        return False


def _message_key(session: Any, stage: str, transfer_id: str | None) -> tuple[str, str]:
    token = str(transfer_id or getattr(session, "transport_debug_transfer_id", "") or "none")
    return token, str(stage)


def build_message(
    session: Any,
    stage: str,
    text: str,
    *,
    transfer_id: str | None = None,
    once: bool = True,
) -> tuple[str, bytes] | None:
    """Build one player-only diagnostic without affecting transport state."""
    if not enabled():
        return None
    key = _message_key(session, stage, transfer_id)
    emitted = getattr(session, "transport_debug_message_stages", None)
    if not isinstance(emitted, set):
        emitted = set()
        session.transport_debug_message_stages = emitted
    if once and key in emitted:
        return None
    if once:
        emitted.add(key)

    from server.modules.handlers.world.chat.codec import (
        encode_skyfire_messagechat_system_payload,
    )

    return "SMSG_MESSAGECHAT", encode_skyfire_messagechat_system_payload(str(text))


def send_message(
    session: Any,
    stage: str,
    text: str,
    *,
    transfer_id: str | None = None,
    once: bool = True,
) -> bool:
    response = build_message(
        session,
        stage,
        text,
        transfer_id=transfer_id,
        once=once,
    )
    if response is None:
        return False
    sender = getattr(session, "send_response", None)
    if not callable(sender):
        return False
    sender([response])
    return True
