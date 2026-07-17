from __future__ import annotations

from dataclasses import dataclass

from server.modules.handlers.world.teleport.map_transfer import TeleportDestination


@dataclass(frozen=True)
class PrisonLocation:
    name: str
    destination: TeleportDestination


# Holding cells are kept here so adding one never requires changing command or
# teleport lifecycle code.  These positions are the two authored Deeprun Tram
# ticket-office endpoints on map 369.
PRISON_LOCATIONS: tuple[PrisonLocation, ...] = (
    PrisonLocation(
        name="Stormwind Deeprun Holding Cell",
        destination=TeleportDestination(
            map_id=369,
            x=-19.6312,
            y=40.0752,
            z=-4.29736,
            orientation=4.79965,
            name="Stormwind Deeprun Holding Cell",
        ),
    ),
    PrisonLocation(
        name="Ironforge Deeprun Holding Cell",
        destination=TeleportDestination(
            map_id=369,
            x=-20.9837,
            y=2459.93,
            z=-4.297,
            orientation=1.57042,
            name="Ironforge Deeprun Holding Cell",
        ),
    ),
)


def is_imprisoned(session) -> bool:
    return bool(getattr(session, "imprisoned", False))


def can_player_teleport(session, *, allow_imprisoned: bool = False) -> bool:
    return bool(allow_imprisoned) or not is_imprisoned(session)


def imprison(session) -> None:
    session.imprisoned = True


def release(session) -> None:
    session.imprisoned = False
