#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass, field
from typing import Optional, Dict, Any
import time


@dataclass
class WorldLoginContext:
    # --------------------------------------------------
    # Identity / session-derived
    # --------------------------------------------------
    account_id: Optional[int] = None
    account_name: Optional[str] = None
    realm_id: Optional[int] = None

    # Login / character identity
    player_guid: Optional[int] = None      # login GUID from CMSG_PLAYER_LOGIN
    char_guid: Optional[int] = None        # DB low guid
    world_guid: Optional[int] = None        # full uint64 world GUID
    

    # --------------------------------------------------
    # Character screen / auth
    # --------------------------------------------------
    realms: list = field(default_factory=list)

    client_cache_version: int = 5
    tutorial_flags: list[int] = field(default_factory=lambda: [0] * 16)
    timezone: str = "Etc/UTC"

    # --------------------------------------------------
    # Account data
    # --------------------------------------------------
    account_data_times: list[int] = field(default_factory=lambda: [0] * 8)
    account_data_mask: int = 0xFF

    server_time: int = field(default_factory=lambda: int(time.time()))
    game_time: int = field(default_factory=lambda: int(time.time()))

    # --------------------------------------------------
    # Feature / system flags
    # --------------------------------------------------
    feature_system_status: Dict[str, Any] = field(default_factory=lambda: {
        "complaint_system_status": 0,
        "voice_enabled": 0,
        "voice_available": 0,
        "browser_enabled": 0,
        "item_restoration_button_enabled": 0,
        "browser_available": 0,
        "voice_chat_enabled": 0,
        "scroll_of_resurrection_enabled": 0,
        "quick_ticket_system_enabled": 0,
        "quick_ticket_system_available": 0,
        "battlefield_status": 0,
        "battlefield_available": 0,
    })

    motd: str = "Welcome to PyPandaria"
    pvp_season: int = 0
    pvp_prev_season: int = 0

    world_server_info: Dict[str, Any] = field(default_factory=dict)

    # --------------------------------------------------
    # World / map / position
    # --------------------------------------------------
    map_id: int = 0
    zone: int = 0
    instance_id: int = 0

    bind_map_id: int = 0
    bind_area_id: int = 0

    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    orientation: float = 0.0

    # --------------------------------------------------
    # Movement / speeds (MoP defaults)
    # --------------------------------------------------
    walk_speed: float = 2.5
    run_speed: float = 7.0
    run_back_speed: float = 4.5
    swim_speed: float = 4.7
    swim_back_speed: float = 2.5
    fly_speed: float = 7.0
    fly_back_speed: float = 4.5
    turn_speed: float = 3.1415926
    pitch_speed: float = 3.1415926

    # --------------------------------------------------
    # Gameplay / state
    # --------------------------------------------------
    level: int = 1
    class_id: int = 0
    race: int = 0
    gender: int = 0

    money: int = 0
    health: int = 1
    player_bytes: int = 0
    player_bytes2: int = 0
    player_flags: int = 0

    known_spells: list = field(default_factory=list)
    action_buttons: list = field(default_factory=lambda: [0] * 120)

    factions: Dict[str, Any] = field(default_factory=dict)
    achievements: Dict[str, Any] = field(default_factory=dict)
    talent_data: Dict[str, Any] = field(default_factory=dict)

    phase_data: Dict[str, Any] = field(default_factory=dict)
    world_states: Dict[str, Any] = field(default_factory=dict)
    single_world_state: Dict[str, Any] = field(default_factory=dict)
    weather: Dict[str, Any] = field(default_factory=dict)

    # --------------------------------------------------
    # Time sync
    # --------------------------------------------------
    time_sync_seq: int = 0

    # --------------------------------------------------
    # Construction helpers
    # --------------------------------------------------
    @classmethod
    def from_session(cls, session):
        return cls(
            account_id=session.account_id,
            account_name=session.account_name,
            realm_id=session.realm_id,

            player_guid=session.player_guid,
            char_guid=session.char_guid,
            world_guid=session.world_guid,   # <<< DETTA SAKNADES

            map_id=session.map_id,
            zone=session.zone,
            instance_id=session.instance_id,

            x=session.x,
            y=session.y,
            z=session.z,
            orientation=session.orientation,

            server_time=session.server_time,

            walk_speed=session.walk_speed,
            run_speed=session.run_speed,
            run_back_speed=session.run_back_speed,
            swim_speed=session.swim_speed,
            swim_back_speed=session.swim_back_speed,
            fly_speed=session.fly_speed,
            fly_back_speed=session.fly_back_speed,
            turn_speed=session.turn_speed,
            pitch_speed=session.pitch_speed,

            level=session.level,
            class_id=session.class_id,
            race=session.race,
            gender=session.gender,

            money=session.money,
            health=session.health,
            player_bytes=session.player_bytes,
            player_bytes2=session.player_bytes2,
            player_flags=session.player_flags,

            known_spells=session.known_spells,
            action_buttons=session.action_buttons,
        )
