from __future__ import annotations

from server.modules.protocol.PacketContext import PacketContext
from server.modules.protocol.ServerOutput import log_decoded_packet
from server.modules.interpretation.utils import to_safe_json


def log_cmsg(ctx: PacketContext) -> dict:
    decoded = ctx.decoded or {}
    log_decoded_packet("worldserver", ctx.name, to_safe_json(decoded), label=f"[CMSG] {ctx.name}")
    return decoded
