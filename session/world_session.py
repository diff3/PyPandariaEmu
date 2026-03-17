#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List


class LoginState(str, Enum):
    AUTHED = "AUTHED"
    CHAR_SCREEN = "CHAR_SCREEN"
    PLAYER_LOGIN = "PLAYER_LOGIN"
    LOADING_SCREEN = "LOADING_SCREEN"
    WORLD_BOOTSTRAP = "WORLD_BOOTSTRAP"
    IN_WORLD = "IN_WORLD"


@dataclass
class WorldSession:
    # --------------------------------------------------
    # Identity / auth
    # --------------------------------------------------
    # --------------------------------------------------
    # Client / cache
    # --------------------------------------------------
    client_cache_version: int = 0
    account_data_times: Dict = field(default_factory=dict)
    account_data: Dict = field(default_factory=dict)
    account_data_mask: int = 0
    server_time: int = 0
    motd = "Hello World"

    

    # --------------------------------------------------
    # Tutorial / UI
    # --------------------------------------------------
    tutorial_flags: List[int] = field(default_factory=lambda: [0] * 8)

    # --------------------------------------------------
    # Feature / system flags
    # --------------------------------------------------
    feature_system_status: int = 0
    world_server_info: Dict = field(default_factory=dict)

    # --------------------------------------------------
    # Time / world
    # --------------------------------------------------
    time_speed: float = 1.0
    time_offset: int = 0

    # --------------------------------------------------
    # Currency
    # --------------------------------------------------
    currency_cap: Dict = field(default_factory=dict)
    currency_weekly_cap: Dict = field(default_factory=dict)

    # --------------------------------------------------
    # Player / movement
    # --------------------------------------------------
    active_mover_guid: Optional[int] = None
    phase_mask: int = 0

    # --------------------------------------------------
    # Weather / world state
    # --------------------------------------------------
    weather_state: int = 0
    account_id: Optional[int] = None
    account_name: Optional[str] = None
    player_name: Optional[str] = None
    realm_id: Optional[int] = None

    # --------------------------------------------------
    # GUIDs
    # --------------------------------------------------
    player_guid: Optional[int] = None   # login GUID (48-bit)
    world_guid: Optional[int] = None    # full 64-bit PLAYER guid
    char_guid: Optional[int] = None     # low DB guid

    # --------------------------------------------------
    # World / position
    # --------------------------------------------------
    map_id: int = 0
    zone: int = 0
    instance_id: int = 0

    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    orientation: float = 0.0

    # --------------------------------------------------
    # Movement / speeds
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
    # Gameplay
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

    known_spells: List[int] = field(default_factory=list)
    action_buttons: List[int] = field(default_factory=lambda: [0] * 120)

    # --------------------------------------------------
    # World state
    # --------------------------------------------------
    phase_data: Dict[str, Any] = field(default_factory=dict)
    world_states: Dict[str, Any] = field(default_factory=dict)
    single_world_state: Dict[str, Any] = field(default_factory=dict)
    weather: Dict[str, Any] = field(default_factory=dict)

    # --------------------------------------------------
    # Time / sync
    # --------------------------------------------------
    # server_time: int = field(default_factory=lambda: int(time.time()))
    time_sync_seq: int = 0
    login_state: Optional[LoginState] = None
    loading_screen_visible: bool = False
    loading_screen_done: bool = False
    post_loading_sent: bool = False
    player_object_sent: bool = False
    pending_account_data_requests: List[int] = field(default_factory=list)
    teleport_pending: bool = False
    teleport_destination: Optional[str] = None
    skyfire_login_stage: int = 0
