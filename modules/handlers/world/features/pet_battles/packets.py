#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
import struct

from DSL.modules.bitsHandler import BitWriter


def _session_guid(session) -> int:
    return int(
        getattr(session, "world_guid", 0)
        or getattr(session, "player_guid", 0)
        or getattr(session, "char_guid", 0)
        or 0
    ) & 0xFFFFFFFFFFFFFFFF


def _guid_bytes(guid: int) -> list[int]:
    value = int(guid) & 0xFFFFFFFFFFFFFFFF
    return [(value >> (index * 8)) & 0xFF for index in range(8)]


@dataclass(frozen=True)
class _PetBattleInitPet:
    guid: int
    species_id: int
    creature_id: int
    display_id: int
    nickname: str
    level: int
    quality: int
    power: int
    max_health: int
    current_health: int
    speed: int
    xp: int
    flags: int


def _write_single_bit(writer: BitWriter, value: int) -> None:
    if hasattr(writer, "write_bit"):
        writer.write_bit(int(value))
        return
    writer.write_bits(int(value), 1)


def _writer_bytes(writer: BitWriter) -> bytes:
    if hasattr(writer, "getvalue"):
        return bytes(writer.getvalue())
    if hasattr(writer, "flush"):
        return bytes(writer.flush())
    raise AttributeError("BitWriter has neither getvalue() nor flush()")


def _write_guid_mask(writer: BitWriter, guid_bytes: list[int], order: tuple[int, ...]) -> None:
    for index in order:
        _write_single_bit(writer, 1 if int(guid_bytes[index]) else 0)


def _append_guid_bytes(payload: bytearray, guid_bytes: list[int], order: tuple[int, ...]) -> None:
    for index in order:
        value = int(guid_bytes[index]) & 0xFF
        if value:
            payload.append(value)


def _append_guid_byte_seq(payload: bytearray, guid_bytes: list[int], order: tuple[int, ...]) -> None:
    for index in order:
        value = int(guid_bytes[index]) & 0xFF
        if value:
            payload.append((value ^ 0x01) & 0xFF)


def _u8(value: int) -> bytes:
    return struct.pack("<B", int(value) & 0xFF)


def _u16(value: int) -> bytes:
    return struct.pack("<H", int(value) & 0xFFFF)


def _u32(value: int) -> bytes:
    return struct.pack("<I", int(value) & 0xFFFFFFFF)


def _resolve_init_pets() -> tuple[_PetBattleInitPet, _PetBattleInitPet]:
    fallback_player = _PetBattleInitPet(
        guid=0x00000000000004B4,
        species_id=1204,
        creature_id=70082,
        display_id=0,
        nickname="",
        level=25,
        quality=3,
        power=1400,
        max_health=1400,
        current_health=1400,
        speed=260,
        xp=0,
        flags=0,
    )
    fallback_enemy = _PetBattleInitPet(
        guid=0x0000000000000027,
        species_id=39,
        creature_id=7394,
        display_id=0,
        nickname="",
        level=25,
        quality=3,
        power=1300,
        max_health=1350,
        current_health=1350,
        speed=250,
        xp=0,
        flags=0,
    )

    try:
        from server.modules.handlers.world.pet import pet_service

        pet_service.load_battle_pets(None)
        all_pets = list(getattr(pet_service, "ALL_BATTLE_PETS", ()) or ())
        if not all_pets:
            return fallback_player, fallback_enemy

        player_source = all_pets[0]
        enemy_source = all_pets[1] if len(all_pets) > 1 else all_pets[0]
        guid_for_species = getattr(pet_service, "battle_pet_guid_for_species", None)

        def _pet_from_source(source, *, default_guid: int) -> _PetBattleInitPet:
            resolved_guid = int(guid_for_species(int(source.species_id))) if callable(guid_for_species) else int(default_guid)
            display_id = int(getattr(source, "display_id", 0) or 0)
            creature_id = int(getattr(source, "creature_id", 0) or 0)
            return _PetBattleInitPet(
                guid=resolved_guid if resolved_guid > 0 else int(default_guid),
                species_id=int(getattr(source, "species_id", 0) or 0),
                creature_id=creature_id,
                display_id=display_id,
                nickname="",
                level=25,
                quality=3,
                power=1400,
                max_health=1400,
                current_health=1400,
                speed=260,
                xp=0,
                flags=0,
            )

        player_pet = _pet_from_source(player_source, default_guid=fallback_player.guid)
        enemy_pet = _pet_from_source(enemy_source, default_guid=fallback_enemy.guid)
        return player_pet, enemy_pet
    except Exception:
        return fallback_player, fallback_enemy


def _build_pet_battle_team_bits(writer: BitWriter) -> None:
    trap_status = 1
    has_front_pet = 0
    has_round_time_sec = 0
    character_guid = [0] * 8
    pet_guid_bytes = [0] * 8

    _write_single_bit(writer, trap_status)
    writer.write_bits(1, 2)
    _write_single_bit(writer, character_guid[2])

    writer.write_bits(0, 21)
    _write_single_bit(writer, 1 if pet_guid_bytes[3] else 0)
    writer.write_bits(0, 21)
    _write_single_bit(writer, 1 if pet_guid_bytes[0] else 0)
    _write_single_bit(writer, 0)
    _write_guid_mask(writer, pet_guid_bytes, (5, 1))
    writer.write_bits(3, 20)
    _write_single_bit(writer, 0)
    writer.write_bits(0, 7)
    _write_guid_mask(writer, pet_guid_bytes, (2, 4))
    _write_single_bit(writer, 0)
    _write_single_bit(writer, 0)
    _write_single_bit(writer, 0)
    _write_guid_mask(writer, pet_guid_bytes, (6, 7))

    _write_single_bit(writer, has_front_pet)
    _write_single_bit(writer, has_round_time_sec)
    _write_guid_mask(writer, character_guid, (5, 3, 4, 6, 7, 0, 1))


def _append_pet_battle_team_bytes(payload: bytearray, pet: _PetBattleInitPet) -> None:
    guid_bytes = _guid_bytes(int(pet.guid))
    character_guid = [0] * 8

    payload += _u8(0)
    for ability_index in range(3):
        payload += _u32(0)
        payload += _u8(ability_index)
        payload += _u8(0)
        payload += _u16(0)
        payload += _u16(0)

    payload += _u32(0)
    _append_guid_bytes(payload, guid_bytes, (4,))
    payload += _u16(pet.level)
    _append_guid_bytes(payload, guid_bytes, (7,))
    payload += _u16(pet.quality)
    _append_guid_bytes(payload, guid_bytes, (6,))
    payload += _u32(pet.power)
    _append_guid_bytes(payload, guid_bytes, (0,))
    payload += _u32(pet.max_health)
    _append_guid_bytes(payload, guid_bytes, (5,))
    _append_guid_bytes(payload, guid_bytes, (2,))
    payload += _u32(pet.speed)
    payload += _u32(pet.current_health)
    _append_guid_bytes(payload, guid_bytes, (3,))
    payload += _u32(0)
    _append_guid_bytes(payload, guid_bytes, (1,))
    payload += _u32(0)
    payload += _u16(pet.xp)
    payload += _u8(pet.flags)
    payload += str(pet.nickname or "").encode("utf-8")
    payload += _u32(pet.species_id)

    payload += _u32(0)
    payload += _u32(0)
    _append_guid_bytes(payload, character_guid, (5, 7, 6, 1, 4, 0))
    payload += _u8(0)
    payload += _u8(6)
    _append_guid_bytes(payload, character_guid, (3, 2))


def build_pet_battle_queue_status_payload(session, *, status: int) -> bytes:
    guid_bytes = _guid_bytes(_session_guid(session))
    writer = BitWriter()

    for index in (7, 2, 6, 1):
        _write_single_bit(writer, 1 if guid_bytes[index] else 0)
    _write_single_bit(writer, 0)  # hasAverageWaitTime
    _write_single_bit(writer, 1 if guid_bytes[4] else 0)
    writer.write_bits(0, 22)
    _write_single_bit(writer, 1 if guid_bytes[0] else 0)
    _write_single_bit(writer, 0)  # hasClientWaitTime
    for index in (3, 5):
        _write_single_bit(writer, 1 if guid_bytes[index] else 0)

    payload = bytearray(_writer_bytes(writer))
    payload += bytes([guid_bytes[2], guid_bytes[4]])
    payload += struct.pack("<I", 0)  # CliRideTicket.Time
    payload += bytes([guid_bytes[3]])
    payload += struct.pack("<I", int(status) & 0xFFFFFFFF)
    payload += bytes([guid_bytes[6]])
    payload += bytes([guid_bytes[1]])
    payload += struct.pack("<I", 0)  # CliRideTicket.Type
    payload += bytes([guid_bytes[5], guid_bytes[7]])
    payload += struct.pack("<I", 0)  # CliRideTicket.Id
    payload += bytes([guid_bytes[0]])

    for _ in range(3):
        payload += struct.pack("<I", 1)  # SlotResult

    return bytes(payload)


def build_battle_pet_location_finalize_payload(session) -> bytes:
    x = float(getattr(session, "x", 0.0) or 0.0)
    y = float(getattr(session, "y", 0.0) or 0.0)
    z = float(getattr(session, "z", 0.0) or 0.0)

    payload = bytearray()
    payload += struct.pack("<f", x)
    payload += struct.pack("<f", y)

    for _ in range(2):
        payload += struct.pack("<f", y)
        payload += struct.pack("<f", x)
        payload += struct.pack("<f", z)

    payload += struct.pack("<f", z)

    writer = BitWriter()
    _write_single_bit(writer, 0)  # hasOrientation
    _write_single_bit(writer, 0)  # hasLocationResult
    payload += _writer_bytes(writer)
    return bytes(payload)


def build_client_control_update_payload(session, *, allow_move: bool) -> bytes:
    guid_bytes = _guid_bytes(_session_guid(session))
    writer = BitWriter()

    for index in (2, 7):
        _write_single_bit(writer, 1 if guid_bytes[index] else 0)
    _write_single_bit(writer, 1 if allow_move else 0)
    for index in (0, 3, 6, 5, 1, 4):
        _write_single_bit(writer, 1 if guid_bytes[index] else 0)

    payload = bytearray(_writer_bytes(writer))
    _append_guid_byte_seq(payload, guid_bytes, (1, 5, 7, 4, 2, 6, 3, 0))
    return bytes(payload)


def build_active_mover_restore_payload(session) -> bytes:
    from server.modules.handlers.world.login.packets import build_login_packet

    return build_login_packet("SMSG_MOVE_SET_ACTIVE_MOVER", session) or b""


def resolve_init_pet_debug_info() -> dict[str, int]:
    player_pet, enemy_pet = _resolve_init_pets()
    return {
        "player_pet_guid": int(player_pet.guid),
        "player_species_id": int(player_pet.species_id),
        "player_creature_id": int(player_pet.creature_id),
        "enemy_pet_guid": int(enemy_pet.guid),
        "enemy_species_id": int(enemy_pet.species_id),
        "enemy_creature_id": int(enemy_pet.creature_id),
    }


def build_battle_pet_update_init_payload(session, *, battle_id: int) -> bytes:
    """Build a minimal battle-session init modeled after SkyFire wild battles."""
    _ = session
    _ = int(battle_id)

    player_pet, _enemy_pet = _resolve_init_pets()
    enemy_pet = _PetBattleInitPet(
        guid=int(player_pet.guid),
        species_id=int(player_pet.species_id),
        creature_id=int(player_pet.creature_id),
        display_id=int(player_pet.display_id),
        nickname=str(player_pet.nickname),
        level=int(player_pet.level),
        quality=int(player_pet.quality),
        power=int(player_pet.power),
        max_health=int(player_pet.max_health),
        current_health=int(player_pet.current_health),
        speed=int(player_pet.speed),
        xp=int(player_pet.xp),
        flags=int(player_pet.flags),
    )
    wild_battle_pet_guid_bytes = _guid_bytes(0xF130000000000001)

    writer = BitWriter()

    for _index in range(3):
        writer.write_bits(0, 21)
        writer.write_bits(0, 21)

    _build_pet_battle_team_bits(writer)
    _build_pet_battle_team_bits(writer)

    _write_single_bit(writer, 1)  # hasForfeitPenalty
    _write_single_bit(writer, 0)  # CanAwardXP
    _write_single_bit(writer, 0)  # IsPvP
    _write_single_bit(writer, 0)  # hasDisplayId
    _write_single_bit(writer, 0)  # hasCreatureId
    _write_single_bit(writer, 1)  # hasWaitingForFrontPetsMaxSecs
    _write_single_bit(writer, 1)  # wild guid present
    _write_guid_mask(writer, wild_battle_pet_guid_bytes, (2, 4, 5, 1, 3, 6, 7, 0))
    _write_single_bit(writer, 0)  # hasPvPMaxRoundTime
    _write_single_bit(writer, 0)  # no extra battlepetstate

    payload = bytearray(_writer_bytes(writer))
    _append_pet_battle_team_bytes(payload, player_pet)
    _append_pet_battle_team_bytes(payload, enemy_pet)
    payload += _u8(10)  # forfeit penalty
    payload += _u8(1)
    _append_guid_bytes(payload, wild_battle_pet_guid_bytes, (5, 4, 3, 2, 7, 0, 1, 6))
    payload += _u32(0)
    payload += _u16(30)
    return bytes(payload)
