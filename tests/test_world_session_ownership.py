from server.modules.handlers.world.position.position_service import (
    persistence_state_for,
)
from server.modules.handlers.world.position.publication import publish_absolute
from server.modules.handlers.world.active_aura import (
    ActiveAura,
    attach_runtime_owner,
    register,
    registry,
)
from server.modules.handlers.world.runtime.player import Player
from server.modules.handlers.world.runtime.player_store import (
    attach_selected_character,
    resolve_player_runtime,
)
from server.modules.handlers.world.player_visibility import (
    get_player_visibility_service,
)
from server.session.world_session import WorldSession


def test_position_persistence_state_is_service_owned_with_compatible_access():
    session = WorldSession()

    session.persist_map_id = 530
    session.persist_x = 12.5
    session.position_dirty = True

    state = persistence_state_for(session)
    assert state.persist_map_id == 530
    assert state.persist_x == 12.5
    assert state.position_dirty is True
    assert "persist_map_id" not in vars(session)
    assert "position_dirty" not in vars(session)


def test_position_persistence_state_is_isolated_per_connection():
    first = WorldSession()
    second = WorldSession()

    first.last_saved_map_id = 1

    assert first.last_saved_map_id == 1
    assert second.last_saved_map_id == 0


def test_selected_character_is_an_explicit_connection_reference():
    session = WorldSession()
    character = object()

    session.selected_character = character

    assert session.selected_character is character


def test_runtime_resolution_prefers_explicit_selected_character():
    player = _player()
    session = WorldSession(char_guid=999, selected_character=player)

    assert resolve_player_runtime(session) is player
    assert resolve_player_runtime(player) is player


def _player() -> Player:
    return Player(
        runtime_guid=42,
        map_id=1,
        instance_id=0,
        x=0.0,
        y=0.0,
        z=0.0,
        orientation=0.0,
        rotation=(0.0, 0.0, 0.0, 1.0),
        scale=1.0,
        character_guid=42,
    )


def test_active_aura_registry_is_owned_by_selected_runtime_player():
    session = WorldSession(selected_character=_player())
    aura = ActiveAura(spell_id=123, slot=0, caster_guid=42)

    register(session, aura)

    assert session.selected_character.active_auras == {0: aura}
    assert "active_auras" not in vars(session)


def test_pre_world_auras_move_when_runtime_player_is_attached():
    session = WorldSession()
    aura = ActiveAura(spell_id=123, slot=0, caster_guid=42)
    register(session, aura)
    player = _player()

    session.selected_character = player
    attach_runtime_owner(session, player)

    assert player.active_auras == {0: aura}
    assert registry(session) is player.active_auras
    assert "active_auras" not in vars(session)


def test_visible_player_guids_are_owned_by_visibility_service():
    session = WorldSession()

    session.visible_guids.add(42)

    assert get_player_visibility_service().known_guids(session) == {42}
    assert "visible_guids" not in vars(session)


def test_visible_player_guids_are_isolated_per_connection():
    first = WorldSession()
    second = WorldSession()

    first.visible_guids.add(42)

    assert first.visible_guids == {42}
    assert second.visible_guids == set()


def test_selected_player_is_authoritative_for_character_geometry():
    session = WorldSession(
        map_id=1,
        instance_id=7,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=0.5,
    )
    player = Player.from_session(session)

    attach_selected_character(session, player)
    session.map_id = 530
    session.x = 11.0
    player.orientation = 1.5

    assert player.map_id == 530
    assert player.x == 11.0
    assert session.orientation == 1.5
    assert not any(name.startswith("_bootstrap_") for name in vars(session))


def test_rotation_and_scale_exist_only_on_runtime_player():
    session = WorldSession()
    player = _player()
    attach_selected_character(session, player)

    assert not hasattr(session, "rotation")
    assert not hasattr(session, "scale")
    assert player.rotation == (0.0, 0.0, 0.0, 1.0)
    assert player.scale == 1.0


def test_position_publication_updates_authoritative_player_and_protocol_cache():
    session = WorldSession()
    player = _player()
    attach_selected_character(session, player)

    publish_absolute(
        session,
        map_id=530,
        instance_id=11,
        x=10.0,
        y=20.0,
        z=30.0,
        orientation=1.5,
    )

    assert (player.map_id, player.instance_id) == (530, 11)
    assert (player.x, player.y, player.z, player.orientation) == (
        10.0,
        20.0,
        30.0,
        1.5,
    )
    assert (
        session.movement_state.x,
        session.movement_state.y,
        session.movement_state.z,
        session.movement_state.orientation,
    ) == (10.0, 20.0, 30.0, 1.5)
