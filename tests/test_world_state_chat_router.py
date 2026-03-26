from types import SimpleNamespace

from server.modules.handlers.world.chat.router import ChatRouter
from server.modules.handlers.world.state.global_state import GlobalState
from server.modules.handlers.world.state.region_manager import RegionManager


def test_region_manager_returns_stable_region_instances():
    manager = RegionManager()

    first = manager.get_region(1)
    second = manager.get_region(1)
    third = manager.get_region(0)

    assert first is second
    assert first is not third
    assert first.map_id == 1
    assert third.map_id == 0


def test_chat_router_uses_world_scope_by_default():
    router = ChatRouter()
    global_state = GlobalState()
    region = RegionManager().get_region(1)
    session = SimpleNamespace(global_state=global_state, region=region)

    targets = router.get_targets(session, "say")

    assert targets is global_state.chat_channels["world"]
    assert targets == set()


def test_chat_router_can_switch_say_to_region_by_config_only():
    router = ChatRouter()
    global_state = GlobalState()
    region = RegionManager().get_region(530)
    session = SimpleNamespace(global_state=global_state, region=region)
    region.players.add("player-a")

    router.chat_scope["say"] = "region"
    targets = router.get_targets(session, "say")

    assert targets is region.players
    assert "player-a" in targets
