#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from protocols.wow.mop.v18414.modules.database.DatabaseConnection import DatabaseConnection
from typing import Optional

import re

_EQUIPMENT_SLOTS = 23
_ITEM_TEMPLATE_CACHE: dict[int, tuple[int, int]] = {}

def _parse_equipment_cache(cache: str) -> Optional[list[dict]]:
    if not cache:
        return None
    values = [int(x) for x in re.findall(r"-?\d+", cache)]
    if len(values) < 3:
        return None

    def _triples(seq, offset):
        trimmed = seq[offset:]
        max_items = min(len(trimmed), _EQUIPMENT_SLOTS * 3)
        max_items -= max_items % 3
        if max_items <= 0:
            return []
        return [trimmed[i:i + 3] for i in range(0, max_items, 3)]

    def _pairs(seq, offset):
        trimmed = seq[offset:]
        max_items = min(len(trimmed), _EQUIPMENT_SLOTS * 2)
        max_items -= max_items % 2
        if max_items <= 0:
            return []
        return [trimmed[i:i + 2] for i in range(0, max_items, 2)]

    def _score_triples(triples, order):
        if not triples:
            return -1
        display_idx, inv_idx, enchant_idx = order
        score = 0
        for t in triples:
            display = t[display_idx]
            inv_type = t[inv_idx]
            enchant = t[enchant_idx]
            if 0 <= inv_type <= 30:
                score += 4
            if 0 <= display <= 200000:
                score += 2
            if display != 0:
                score += 1
            if 0 <= enchant <= 100000:
                score += 1
        return score

    def _score_pairs(pairs, order):
        if not pairs:
            return -1
        display_idx, inv_idx = order
        score = 0
        for p in pairs:
            display = p[display_idx]
            inv_type = p[inv_idx]
            if 0 <= inv_type <= 30:
                score += 4
            if 0 <= display <= 200000:
                score += 2
            if display != 0:
                score += 1
        return score

    triple_orders = [(0, 1, 2), (0, 2, 1), (1, 0, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0)]
    pair_orders = [(0, 1), (1, 0)]

    best_kind = None
    best_offset = 0
    best_order = None
    best_score = -1

    for offset in (0, 1, 2):
        triples = _triples(values, offset)
        for order in triple_orders:
            score = _score_triples(triples, order)
            if score > best_score:
                best_kind, best_score, best_offset, best_order = "triples", score, offset, order

    for offset in (0, 1):
        pairs = _pairs(values, offset)
        for order in pair_orders:
            score = _score_pairs(pairs, order)
            if score > best_score:
                best_kind, best_score, best_offset, best_order = "pairs", score, offset, order

    if best_kind is None:
        return None

    entries: list[dict] = []
    if best_kind == "triples":
        triples = _triples(values, best_offset)
        display_idx, inv_idx, enchant_idx = best_order
        for t in triples:
            entries.append(
                {"enchant": t[enchant_idx], "int_type": t[inv_idx], "display_id": t[display_idx]}
            )
    else:
        pairs = _pairs(values, best_offset)
        display_idx, inv_idx = best_order
        for p in pairs:
            entries.append({"enchant": 0, "int_type": p[inv_idx], "display_id": p[display_idx]})

    entries = _apply_item_template_info(entries)

    while len(entries) < _EQUIPMENT_SLOTS:
        entries.append({"enchant": 0, "int_type": 0, "display_id": 0})

    return entries

def _apply_item_template_info(entries: list[dict]) -> list[dict]:
    entry_ids = {
        e.get("display_id")
        for e in entries
        if e.get("display_id") and (e.get("int_type") or 0) == 0
    }
    if not entry_ids:
        return entries

    template_map = _resolve_item_template_map(list(entry_ids))
    if not template_map:
        return entries

    for entry in entries:
        if (entry.get("int_type") or 0) != 0:
            continue
        item_entry = entry.get("display_id")
        if not item_entry:
            continue
        mapped = template_map.get(item_entry)
        if not mapped:
            continue
        display_id, inv_type = mapped
        if display_id:
            entry["display_id"] = display_id
        if inv_type is not None:
            entry["int_type"] = inv_type
    return entries

def _resolve_item_template_map(entries: list[int]) -> dict[int, tuple[int, int]]:
    if not entries:
        return {}
    missing = [entry for entry in entries if entry not in _ITEM_TEMPLATE_CACHE]
    if missing:
        fetched = DatabaseConnection.get_item_template_map(missing)
        if fetched:
            _ITEM_TEMPLATE_CACHE.update(fetched)
    return {entry: _ITEM_TEMPLATE_CACHE.get(entry) for entry in entries if entry in _ITEM_TEMPLATE_CACHE}