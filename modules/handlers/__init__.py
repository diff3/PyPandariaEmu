"""Handler package."""


def __getattr__(name: str):
    if name == "build_player_login_packets":
        from .world.login import build_player_login_packets

        return build_player_login_packets
    raise AttributeError(name)
