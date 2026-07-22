#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

from server.modules.handlers.world.position.position_service import (
    PositionPersistenceField,
)
from server.modules.handlers.world.player_visibility.service import (
    VisiblePlayerGuidsField,
)
from server.modules.handlers.world.runtime.player_store import PlayerGeometryField


class LoginState(str, Enum):
    AUTHED = "AUTHED"
    CHAR_SCREEN = "CHAR_SCREEN"
    PLAYER_LOGIN = "PLAYER_LOGIN"
    LOADING_SCREEN = "LOADING_SCREEN"
    WORLD_BOOTSTRAP = "WORLD_BOOTSTRAP"
    IN_WORLD = "IN_WORLD"


@dataclass
class MovementState:
    """Connection-local movement protocol snapshot.

    ``Player`` owns absolute character geometry.  The coordinates below are a
    derived cache of the last accepted/published transform used by movement
    parsing and serialization.  Transport fields are the wire projection of
    the authoritative passenger attachment owned by transport runtime.

    No field in this object is authoritative character gameplay state.
    """

    # Derived cache: last accepted absolute Player transform.
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    orientation: float = 0.0

    # Protocol state: last accepted movement flags.
    flags: int = 0
    flags2: int = 0

    # Protocol/serialization clocks.  Client time is inbound protocol state;
    # timestamp_ms and server_movement_timestamp_ms provide monotonic outbound
    # values for movement serialization.
    timestamp_ms: int = 0
    client_timestamp_ms: int = 0
    server_movement_timestamp_ms: int = 0

    # Derived validation/serialization cache.
    last_valid_orientation: float = 0.0

    # Protocol sequence state.
    counter: int = 0

    # Protocol state: optional fall block from the accepted movement packet.
    has_fall_data: bool = False
    fall_time: int = 0
    fall_vertical_speed: float = 0.0
    fall_horizontal_speed: float = 0.0
    fall_sin_angle: float = 0.0
    fall_cos_angle: float = 0.0

    # Protocol state and derived flag helpers for vertical movement.
    pitch: float = 0.0
    is_ascending: bool = False
    is_descending: bool = False

    # Transport state: connection-local wire projection of the canonical
    # RuntimeTransportState passenger attachment.  These fields are consumed
    # by movement serialization and are not the authoritative attachment.
    has_transport_data: bool = False
    transport_guid: int = 0
    transport_x: float = 0.0
    transport_y: float = 0.0
    transport_z: float = 0.0
    transport_orientation: float = 0.0
    transport_o: float = 0.0  # compatibility alias for local orientation
    transport_time: int = 0
    transport_time2: int = 0
    transport_time3: int = 0
    transport_seat: int = -1
    transport_vehicle_id: int = 0


@dataclass(eq=False)
class WorldSession:
    """A client connection and its protocol/login state.

    Gameplay services still expose several compatibility attributes on this
    object. Persistent position bookkeeping is deliberately service-owned and
    surfaced here only through descriptors while callers are migrated.
    """

    world_socket: Any = None
    remote_addr: Any = None
    selected_character: Any = None
    active: bool = False
    last_activity: float = 0.0
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
    game_time: int = 0
    motd: str = ""
    addons: List[Dict[str, Any]] = field(default_factory=list)
    addon_trailing_value: int = 0
    banned_addons: List[Dict[str, Any]] = field(default_factory=list)

    

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
    imprisoned: bool = False

    # --------------------------------------------------
    # Weather / world state
    # --------------------------------------------------
    weather_state: int = 0
    account_id: Optional[int] = None
    account_name: Optional[str] = None
    player_name: Optional[str] = None
    realm_id: Optional[int] = None
    global_state: Any = None
    region: Any = None

    # --------------------------------------------------
    # GUIDs
    # --------------------------------------------------
    player_guid: Optional[int] = None   # login GUID (48-bit)
    world_guid: Optional[int] = None    # full 64-bit PLAYER guid
    char_guid: Optional[int] = None     # low DB guid

    # --------------------------------------------------
    # World / position
    # --------------------------------------------------
    map_id: int = PlayerGeometryField("map_id")
    zone: int = 0
    current_area: int = 0
    instance_id: int = PlayerGeometryField("instance_id")

    x: float = PlayerGeometryField("x")
    y: float = PlayerGeometryField("y")
    z: float = PlayerGeometryField("z")
    orientation: float = PlayerGeometryField("orientation")
    movement_state: MovementState = field(default_factory=MovementState)

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
    can_fly: bool = False
    is_flying: bool = False

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
    unit_flags: int = 0
    mount_display_id: int = 0
    equipment_cache_raw: List[int] = field(default_factory=list)
    explored_zones_raw: str = ""
    map_cheat_enabled: bool = False
    current_chair: Optional[int] = None
    current_seat: Optional[int] = None
    bind_map_id: int = 0
    bind_area_id: int = 0
    bind_x: float = 0.0
    bind_y: float = 0.0
    bind_z: float = 0.0
    bind_o: float = 0.0
    gossip_npc_guid: Optional[int] = None
    gossip_npc_flags: int = 0
    inventory_state: Any = None
    inventory_items: Dict[Any, Any] = field(default_factory=dict)
    inventory_by_guid: Dict[int, Any] = field(default_factory=dict)
    inventory_dirty: bool = False

    known_spells: List[int] = field(default_factory=list)
    language: int = 0
    known_languages_mask: int = 0
    action_buttons: List[int] = field(default_factory=lambda: [0] * 132)
    is_mounted: bool = False
    mount_spell: Optional[int] = None
    mount_owns_flight_capability: bool = False
    active_mount_aura_spell_id: Optional[int] = None
    active_mount_aura_slot: int = 0
    active_fly_aura_spell_id: Optional[int] = None
    active_fly_aura_slot: int = 1

    # --------------------------------------------------
    # World state
    # --------------------------------------------------
    phase_data: Dict[str, Any] = field(default_factory=dict)
    world_states: Dict[str, Any] = field(default_factory=dict)
    single_world_state: Dict[str, Any] = field(default_factory=dict)
    weather: Dict[str, Any] = field(default_factory=dict)
    active_area_triggers: set[int] = field(default_factory=set)
    area_trigger_teleport_cooldown_until: float = 0.0

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
    send_response: Any = None
    pending_account_data_requests: List[int] = field(default_factory=list)
    teleport_pending: bool = False
    worldport_ack_pending: bool = False
    teleport_destination: Optional[str] = None
    near_teleport_pending: bool = False
    near_teleport_generation: int = 0
    world_transition_generation: int = 0
    world_transition_loading_generation: int = 0
    world_transition_bootstrap_generation: int = 0
    world_transition_bootstrap_status: str = "IDLE"
    world_transition_owner: Optional[str] = None
    world_transition_ignore_worldport_ack: bool = False
    transport_transfer_pending: bool = False
    pending_transport_transfer: Optional[Dict[str, Any]] = None
    post_bootstrap_transport_reattach_request: Optional[Dict[str, Any]] = None
    pending_world_attachment_restore: Optional[Dict[str, Any]] = None
    chat_joined: bool = False
    chat_motd_sent: bool = False
    auto_reply_msg: str = ""
    is_afk: bool = False
    is_dnd: bool = False
    skyfire_login_stage: int = 0
    visible_guids = VisiblePlayerGuidsField()
    gameobjects_visible: bool = True
    loaded_gameobjects: set[int] = field(default_factory=set)
    loaded_gameobject_entries: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    npcs_visible: bool = False
    npc_auto_stream: bool = False
    loaded_npcs: set[int] = field(default_factory=set)
    npc_flags_by_guid: Dict[int, int] = field(default_factory=dict)
    npc_entries_by_guid: Dict[int, int] = field(default_factory=dict)
    npc_positions_by_guid: Dict[int, tuple] = field(default_factory=dict)
    npc_names_by_guid: Dict[int, str] = field(default_factory=dict)
    taxi_cheat_enabled: bool = False
    taxi_state: Any = None
    taxi_controls_locked: bool = False
    player_travel_state: str = "NORMAL"
    last_gameobject_stream_at: float = 0.0
    last_npc_stream_at: float = 0.0
    last_position_save_at = PositionPersistenceField("last_position_save_at")
    position_dirty = PositionPersistenceField("position_dirty")
    persist_map_id = PositionPersistenceField("persist_map_id")
    persist_zone = PositionPersistenceField("persist_zone")
    persist_instance_id = PositionPersistenceField("persist_instance_id")
    persist_x = PositionPersistenceField("persist_x")
    persist_y = PositionPersistenceField("persist_y")
    persist_z = PositionPersistenceField("persist_z")
    persist_orientation = PositionPersistenceField("persist_orientation")
    last_saved_map_id = PositionPersistenceField("last_saved_map_id")
    last_saved_zone = PositionPersistenceField("last_saved_zone")
    last_saved_instance_id = PositionPersistenceField("last_saved_instance_id")
    last_saved_x = PositionPersistenceField("last_saved_x")
    last_saved_y = PositionPersistenceField("last_saved_y")
    last_saved_z = PositionPersistenceField("last_saved_z")
    last_saved_orientation = PositionPersistenceField("last_saved_orientation")
