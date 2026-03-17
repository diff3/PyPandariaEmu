#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import zlib
from pathlib import Path
from typing import Optional

from shared.Logger import Logger


class AddonsBuilder:
    ADDON_CRC_FALLBACK = 917963673

    @staticmethod
    def build_fields(addons_dir: Optional[str | Path], fallback_blob: bytes) -> dict:
        if addons_dir:
            fields = AddonsBuilder._build_addons_from_dir(Path(addons_dir))
            if fields:
                Logger.info(
                    f"[ADDONS] Using live scan ({len(fields.get('addons', []))} addons) from {addons_dir}"
                )
                return fields
        fields = AddonsBuilder._parse_addons_blob(fallback_blob)
        Logger.info(
            f"[ADDONS] Using fallback blob ({len(fields.get('addons', []))} addons)"
        )
        return fields

    @staticmethod
    def _build_addons_from_dir(addons_dir: Path) -> dict | None:
        if not addons_dir.exists():
            Logger.warning(f"[ADDONS] AddOns dir not found: {addons_dir}")
            return None

        addons = []
        for entry in sorted(addons_dir.iterdir(), key=lambda p: p.name.lower()):
            if not entry.is_dir():
                continue
            addons.append(
                {
                    "name": entry.name,
                    "enabled": 1,
                    "crc": AddonsBuilder.ADDON_CRC_FALLBACK,
                    "unk": 0,
                }
            )

        if not addons:
            Logger.warning(f"[ADDONS] No addons found in {addons_dir}")
            return None

        payload = AddonsBuilder._pack_addons_payload(addons)
        addons_crc = zlib.crc32(payload) & 0xFFFFFFFF
        uncompressed = payload + addons_crc.to_bytes(4, "little")
        compressed = zlib.compress(uncompressed)

        return {
            "addonSize": len(compressed) + 4,
            "addons_uncompressed_size": len(uncompressed),
            "addons_count": len(addons),
            "addons": addons,
            "addons_crc": addons_crc,
        }

    @staticmethod
    def _pack_addons_payload(addons: list[dict]) -> bytes:
        out = bytearray()
        out.extend(len(addons).to_bytes(4, "little"))
        for addon in addons:
            name = (addon.get("name") or "").encode("ascii", errors="replace")
            out.extend(name)
            out.append(0)
            out.append(int(addon.get("enabled", 0)) & 0xFF)
            out.extend(int(addon.get("crc", 0)).to_bytes(4, "little"))
            out.extend(int(addon.get("unk", 0)).to_bytes(4, "little"))
        return bytes(out)

    @staticmethod
    def _parse_addons_blob(blob: bytes) -> dict:
        if len(blob) < 4:
            raise ValueError("addons blob too short")

        expected_len = int.from_bytes(blob[:4], "little")
        compressed = blob[4:]

        data = zlib.decompress(compressed)
        if expected_len and expected_len != len(data):
            Logger.warning(
                f"[ADDONS] Uncompressed size mismatch: {expected_len} != {len(data)}"
            )

        if len(data) < 8:
            raise ValueError("addons data too short")

        count = int.from_bytes(data[:4], "little")
        idx = 4
        addons = []

        for _ in range(count):
            end = data.find(b"\x00", idx)
            if end == -1:
                raise ValueError("addons data missing name terminator")

            name = data[idx:end].decode("ascii", errors="replace")
            idx = end + 1

            if idx + 9 > len(data):
                raise ValueError("addons data truncated")

            enabled = data[idx]
            idx += 1
            crc = int.from_bytes(data[idx:idx + 4], "little")
            idx += 4
            unk = int.from_bytes(data[idx:idx + 4], "little")
            idx += 4

            addons.append(
                {
                    "name": name,
                    "enabled": enabled,
                    "crc": crc,
                    "unk": unk,
                }
            )

        trailer = 0
        if idx + 4 <= len(data):
            trailer = int.from_bytes(data[idx:idx + 4], "little")
            idx += 4

        if idx != len(data):
            Logger.warning(
                f"[ADDONS] Trailing bytes after addons list: {len(data) - idx}"
            )

        recompressed = zlib.compress(data)

        return {
            "addonSize": len(recompressed) + 4,
            "addons_uncompressed_size": len(data),
            "addons_count": len(addons),
            "addons": addons,
            "addons_crc": trailer,
        }
