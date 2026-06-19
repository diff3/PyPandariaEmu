#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Single owner for DBC movement templates and instances."""

from __future__ import annotations

import time

from shared.Logger import Logger

from server.modules.handlers.world.feature_config import transport_movement_debug_enabled

from .cache import get_movement_cache
from .evaluator import evaluate_template
from .types import (
    MovementInstance,
    MovementLifecycleEvent,
    MovementLifecycleEventType,
    MovementRuntimeState,
    MovementTemplate,
    MovementTransform,
    MovementVisibilityState,
    PassengerAttachment,
    PassengerTransferState,
)

def transport_time_ms() -> int:
    """
    Absolute global transport clock.

    IMPORTANT:
    Must survive process restarts and remain
    stable across world/map servers.
    """
    return int(time.time() * 1000.0)


def monotonic_time_ms() -> int:
    """
    Local monotonic process clock.

    IMPORTANT:
    Only use for local timers, scheduler deltas,
    retry logic and session-scoped systems.
    """
    return int(time.monotonic() * 1000.0)


class MovementManager:
    def __init__(self) -> None:
        self.instances: dict[int, MovementRuntimeState] = {}
        self.templates: dict[str, MovementTemplate] = {}
        self.instance_by_template: dict[str, int] = {}
        self.event_history: dict[int, tuple[MovementLifecycleEvent, ...]] = {}

    def load_templates(self) -> None:
        get_movement_cache().load()




    def tick_taxi_instance(
        self,
        instance_id: int,
        *,
        local_elapsed_ms: int,
    ) -> MovementTransform | None:
        """
        Special metod för Taxi som använder lokal tid (tid sedan start)
        istället för global server-tid.
        """
        state = self.instances.get(int(instance_id))
        if state is None:
            return None
        
        template = self.templates.get(str(state.instance.template_id))
        if template is None:
            return None

        # Här är nyckeln: Vi ignorerar state.instance.started_at_ms
        # och använder direkt local_elapsed_ms som "phase"
        # evaluate_template förväntar sig ofta "now". Vi måste lura den.
        
        # Om evaluate_template gör: phase = now - started_at
        # Då måste vi skicka in "now" så att (now - started_at) = local_elapsed_ms
        # => now = local_elapsed_ms + started_at
        
        fake_now = local_elapsed_ms + int(state.instance.started_at_ms)
        
        return self.evaluate(
            template,
            server_time_ms=fake_now, # Lura systemet att "nu" är detta
            phase_offset_ms=int(state.instance.phase_offset_ms),
        )


    def reset_for_tests(self) -> None:
        self.instances.clear()
        self.templates.clear()
        self.instance_by_template.clear()
        self.event_history.clear()

    def register_instance(
        self,
        instance_id: int,
        template: MovementTemplate,
        *,
        phase_offset_ms: int = 0,
    ) -> MovementInstance | None:
        instance_key = int(instance_id)
        template_key = str(template.template_id)
        self.templates[template_key] = template
        if instance_key in self.instances:
            Logger.info("[MovementManager] duplicate instance rejected id=0x%016X", instance_key)
            return self.instances[instance_key].instance
        existing_instance = self.instance_by_template.get(template_key)
        if existing_instance is not None:
            Logger.info(
                "[MovementManager] duplicate template rejected template=%s existing=0x%016X requested=0x%016X",
                template_key,
                int(existing_instance) & 0xFFFFFFFFFFFFFFFF,
                instance_key & 0xFFFFFFFFFFFFFFFF,
            )
            return None
        instance = MovementInstance(
            instance_id=instance_key,
            template_id=template_key,
            # started_at_ms=int(time.monotonic() * 1000.0),
            started_at_ms=transport_time_ms(),
            phase_offset_ms=int(phase_offset_ms),
        )
        self.instances[instance_key] = MovementRuntimeState(instance=instance)
        self.instance_by_template[template_key] = instance_key
        if transport_movement_debug_enabled():
            Logger.info(
                "[MovementManager] instance registered id=0x%016X template=%s",
                instance_key,
                template.template_id,
            )
        self._emit_event(
            self.instances[instance_key],
            MovementLifecycleEventType.SPAWN,
            phase_ms=0,
            node_index=0,
            message="registered",
        )
        self.instances[instance_key].spawned = True
        self.tick_instance(instance_key)
        return instance

    def transport_time_ms() -> int:
        """
        Global deterministic transport clock.

        IMPORTANT:
        Must remain stable across process restarts
        and world server sessions.
        """
        return int(time.time() * 1000.0)


    def evaluate(
        self,
        template: MovementTemplate,
        *,
        server_time_ms: int | None = None,
        phase_offset_ms: int = 0,
    ) -> MovementTransform:

        now = (
            transport_time_ms()
            if server_time_ms is None
            else int(server_time_ms)
        )

        return evaluate_template(
            template,
            now,
            phase_offset_ms=int(phase_offset_ms),
        )

    def evaluate_instance_old(
        self,
        instance_id: int,
        *,
        server_time_ms: int | None = None,
    ) -> MovementTransform | None:
        state = self.instances.get(int(instance_id))
        if state is None:
            return None
        template = self.templates.get(str(state.instance.template_id))
        if template is None:
            Logger.warning(
                "[MovementManager] missing template instance=0x%016X template=%s",
                int(instance_id) & 0xFFFFFFFFFFFFFFFF,
                state.instance.template_id,
            )
            return None
        return self.evaluate(
            template,
            server_time_ms=server_time_ms,
            phase_offset_ms=int(state.instance.phase_offset_ms),
        )
    
    def evaluate_instance(
        self,
        instance_id: int,
        *,
        server_time_ms: int | None = None,
    ) -> MovementTransform | None:

        state = self.instances.get(int(instance_id))

        if state is None:
            return None

        template = self.templates.get(
            str(state.instance.template_id)
        )

        if template is None:
            return None

        now = (
            transport_time_ms()
            if server_time_ms is None
            else int(server_time_ms)
        )

        return evaluate_template(
            template,
            now,
            phase_offset_ms=int(
                state.instance.phase_offset_ms
            ),
        )
    
    def tick_instance(
        self,
        instance_id: int,
        *,
        server_time_ms: int | None = None,
    ) -> MovementTransform | None:
        state = self.instances.get(int(instance_id))
        transform = self.evaluate_instance(int(instance_id), server_time_ms=server_time_ms)
        if state is None or transform is None:
            return transform

        previous = str(state.lifecycle_state)
        new_lifecycle = str(transform.state or "ACTIVE")
        self._validate_lifecycle_transition(state, previous, new_lifecycle)
        state.previous_lifecycle_state = previous
        state.lifecycle_state = new_lifecycle
        state.last_event = str(transform.event or "")
        state.last_phase_ms = int(transform.phase_ms)
        state.evaluated_transform = transform
        state.transfer_destination_map = self._transfer_destination_map(
            state.instance.template_id,
            int(transform.next_node_index),
        )
        self._detect_lifecycle_events(state, transform)
        self._update_visibility_state(state)
        if previous != state.lifecycle_state and transport_movement_debug_enabled():
            Logger.info(
                "[MovementManager] lifecycle instance=0x%016X %s->%s event=%s",
                int(instance_id) & 0xFFFFFFFFFFFFFFFF,
                previous,
                state.lifecycle_state,
                state.last_event,
            )
        return transform

    def tick(self, server_time_ms: int | None = None) -> None:
        for instance_id in tuple(self.instances):
            self.tick_instance(int(instance_id), server_time_ms=server_time_ms)

    def tick_all(self) -> None:
        self.tick()

    def runtime_state(self, instance_id: int) -> MovementRuntimeState | None:
        return self.instances.get(int(instance_id))

    def get_state(self, instance_id: int) -> MovementRuntimeState | None:
        return self.runtime_state(int(instance_id))

    def get_transform(self, instance_id: int) -> MovementTransform | None:
        state = self.instances.get(int(instance_id))
        if state is None:
            return None
        return state.evaluated_transform

    def visibility_state(self, instance_id: int) -> MovementVisibilityState:
        state = self.instances.get(int(instance_id))
        if state is None:
            return MovementVisibilityState.DESPAWNED
        try:
            return MovementVisibilityState(str(state.visibility_state))
        except ValueError:
            Logger.warning(
                "[MovementManager] invalid visibility state instance=0x%016X state=%s",
                int(instance_id) & 0xFFFFFFFFFFFFFFFF,
                str(state.visibility_state),
            )
            return MovementVisibilityState.DESPAWNED

    def is_visible(self, instance_id: int) -> bool:
        visibility = self.visibility_state(int(instance_id))
        return visibility in (
            MovementVisibilityState.ACTIVE,
            MovementVisibilityState.WAITING,
        )

    def unregister_instance(self, instance_id: int) -> None:
        state = self.instances.pop(int(instance_id), None)
        if state is None:
            return
        self.instance_by_template.pop(str(state.instance.template_id), None)
        phase_ms = int(state.last_phase_ms if state.last_phase_ms >= 0 else 0)
        node_index = int(state.last_node_index if state.last_node_index >= 0 else 0)
        self._emit_event(
            state,
            MovementLifecycleEventType.DESPAWN,
            phase_ms=phase_ms,
            node_index=node_index,
            message="unregistered",
        )
        state.previous_visibility_state = str(state.visibility_state)
        state.visibility_state = MovementVisibilityState.DESPAWNED.value
        self.event_history[int(instance_id)] = state.lifecycle_events
        Logger.info(
            "[MovementManager] instance unregistered id=0x%016X template=%s",
            int(instance_id) & 0xFFFFFFFFFFFFFFFF,
            state.instance.template_id,
        )

    def attach_passenger(
        self,
        instance_id: int,
        passenger_id: int,
        *,
        local_x: float = 0.0,
        local_y: float = 0.0,
        local_z: float = 0.0,
        local_o: float = 0.0,
        source_map: int = 0,
    ) -> bool:
        try:
            from server.modules.handlers.world.transport_runtime import (
                attach_transport_passenger,
                runtime_transport_state_for_guid,
            )

            if runtime_transport_state_for_guid(int(instance_id)) is not None:
                return attach_transport_passenger(
                    int(instance_id),
                    int(passenger_id),
                    local_x=float(local_x),
                    local_y=float(local_y),
                    local_z=float(local_z),
                    local_o=float(local_o),
                    source_map=int(source_map),
                )
        except Exception:
            pass

        state = self.instances.get(int(instance_id))
        if state is None:
            Logger.warning(
                "[MovementManager] invalid passenger attach instance=0x%016X passenger=%s reason=unknown_instance",
                int(instance_id) & 0xFFFFFFFFFFFFFFFF,
                int(passenger_id),
            )
            return False
        if state.passengers is None:
            state.passengers = {}
        if int(passenger_id) in state.passengers:
            Logger.warning(
                "[MovementManager] duplicate passenger attach instance=0x%016X passenger=%s",
                int(instance_id) & 0xFFFFFFFFFFFFFFFF,
                int(passenger_id),
            )
        state.passengers[int(passenger_id)] = PassengerAttachment(
            passenger_id=int(passenger_id),
            local_x=float(local_x),
            local_y=float(local_y),
            local_z=float(local_z),
            local_o=float(local_o),
            source_map=int(source_map),
            attached_at_ms=int(time.monotonic() * 1000.0),
        )
        Logger.info(
            "[MovementManager] passenger attach instance=0x%016X passenger=%s count=%s",
            int(instance_id) & 0xFFFFFFFFFFFFFFFF,
            int(passenger_id),
            len(state.passengers),
        )
        return True

    def detach_passenger(self, instance_id: int, passenger_id: int) -> bool:
        try:
            from server.modules.handlers.world.transport_runtime import (
                detach_transport_passenger,
                runtime_transport_state_for_guid,
            )

            if runtime_transport_state_for_guid(int(instance_id)) is not None:
                return detach_transport_passenger(int(instance_id), int(passenger_id))
        except Exception:
            pass

        state = self.instances.get(int(instance_id))
        if state is None or state.passengers is None:
            Logger.warning(
                "[MovementManager] detach without attach instance=0x%016X passenger=%s reason=unknown_instance",
                int(instance_id) & 0xFFFFFFFFFFFFFFFF,
                int(passenger_id),
            )
            return False
        existed = int(passenger_id) in state.passengers
        if not existed:
            Logger.warning(
                "[MovementManager] detach without attach instance=0x%016X passenger=%s",
                int(instance_id) & 0xFFFFFFFFFFFFFFFF,
                int(passenger_id),
            )
        state.passengers.pop(int(passenger_id), None)
        Logger.info(
            "[MovementManager] passenger detach instance=0x%016X passenger=%s count=%s",
            int(instance_id) & 0xFFFFFFFFFFFFFFFF,
            int(passenger_id),
            len(state.passengers),
        )
        return existed

    def passenger_attachment(
        self,
        instance_id: int,
        passenger_id: int,
    ) -> PassengerAttachment | None:
        try:
            from server.modules.handlers.world.transport_runtime import (
                runtime_transport_state_for_guid,
                transport_passenger_attachment,
            )

            if runtime_transport_state_for_guid(int(instance_id)) is not None:
                return transport_passenger_attachment(int(instance_id), int(passenger_id))
        except Exception:
            pass

        state = self.instances.get(int(instance_id))
        if state is None or state.passengers is None:
            return None
        return state.passengers.get(int(passenger_id))

    def begin_passenger_transfer(
        self,
        source_instance_id: int,
        destination_instance_id: int,
        passenger_id: int,
        *,
        target_map_id: int,
    ) -> PassengerTransferState | None:
        try:
            from server.modules.handlers.world.transport_runtime import (
                begin_transport_passenger_transfer,
                runtime_transport_state_for_guid,
            )

            if runtime_transport_state_for_guid(int(source_instance_id)) is not None:
                return begin_transport_passenger_transfer(
                    int(source_instance_id),
                    int(destination_instance_id),
                    int(passenger_id),
                    target_map_id=int(target_map_id),
                )
        except Exception:
            pass

        source = self.instances.get(int(source_instance_id))
        if source is None or source.passengers is None:
            Logger.warning(
                "[MovementManager] transfer without valid source instance=0x%016X passenger=%s",
                int(source_instance_id) & 0xFFFFFFFFFFFFFFFF,
                int(passenger_id),
            )
            return None
        attachment = source.passengers.pop(int(passenger_id), None)
        if attachment is None:
            Logger.warning(
                "[MovementManager] transfer without attach instance=0x%016X passenger=%s",
                int(source_instance_id) & 0xFFFFFFFFFFFFFFFF,
                int(passenger_id),
            )
            return None
        if source.pending_transfers is None:
            source.pending_transfers = {}
        transfer = PassengerTransferState(
            passenger_id=int(passenger_id),
            source_instance_id=int(source_instance_id),
            destination_instance_id=int(destination_instance_id),
            target_map_id=int(target_map_id),
            local_x=float(attachment.local_x),
            local_y=float(attachment.local_y),
            local_z=float(attachment.local_z),
            local_o=float(attachment.local_o),
            # started_at_ms=int(time.monotonic() * 1000.0),
            started_at_ms=transport_time_ms(),

        )
        source.pending_transfers[int(passenger_id)] = transfer
        Logger.info(
            "[MovementManager] passenger transfer begin source=0x%016X dest=0x%016X passenger=%s map=%s",
            int(source_instance_id) & 0xFFFFFFFFFFFFFFFF,
            int(destination_instance_id) & 0xFFFFFFFFFFFFFFFF,
            int(passenger_id),
            int(target_map_id),
        )
        return transfer

    def complete_passenger_transfer(
        self,
        source_instance_id: int,
        passenger_id: int,
    ) -> PassengerTransferState | None:
        try:
            from server.modules.handlers.world.transport_runtime import (
                complete_transport_passenger_transfer,
                runtime_transport_state_for_guid,
            )

            if runtime_transport_state_for_guid(int(source_instance_id)) is not None:
                return complete_transport_passenger_transfer(
                    int(source_instance_id),
                    int(passenger_id),
                )
        except Exception:
            pass

        source = self.instances.get(int(source_instance_id))
        if source is None or source.pending_transfers is None:
            Logger.warning(
                "[MovementManager] transfer complete without pending source=0x%016X passenger=%s",
                int(source_instance_id) & 0xFFFFFFFFFFFFFFFF,
                int(passenger_id),
            )
            return None
        transfer = source.pending_transfers.pop(int(passenger_id), None)
        if transfer is None:
            Logger.warning(
                "[MovementManager] transfer complete missing passenger source=0x%016X passenger=%s",
                int(source_instance_id) & 0xFFFFFFFFFFFFFFFF,
                int(passenger_id),
            )
            return None
        self.attach_passenger(
            int(transfer.destination_instance_id),
            int(passenger_id),
            local_x=float(transfer.local_x),
            local_y=float(transfer.local_y),
            local_z=float(transfer.local_z),
            local_o=float(transfer.local_o),
            source_map=int(transfer.target_map_id),
        )
        Logger.info(
            "[MovementManager] passenger transfer complete source=0x%016X dest=0x%016X passenger=%s",
            int(source_instance_id) & 0xFFFFFFFFFFFFFFFF,
            int(transfer.destination_instance_id) & 0xFFFFFFFFFFFFFFFF,
            int(passenger_id),
        )
        return transfer

    def transfer_destination_map(self, instance_id: int) -> int | None:
        state = self.instances.get(int(instance_id))
        if state is None:
            return None
        return state.transfer_destination_map

    def latest_events(self, instance_id: int) -> tuple[MovementLifecycleEvent, ...]:
        state = self.instances.get(int(instance_id))
        if state is None:
            return self.event_history.get(int(instance_id), ())
        return tuple(state.lifecycle_events)

    def complete_transfer(self, instance_id: int) -> bool:
        state = self.instances.get(int(instance_id))
        if state is None:
            return False
        if not state.transfer_active:
            Logger.warning(
                "[MovementManager] invalid transfer complete instance=0x%016X reason=no_active_transfer",
                int(instance_id) & 0xFFFFFFFFFFFFFFFF,
            )
            return False
        state.transfer_active = False
        self._emit_event(
            state,
            MovementLifecycleEventType.TRANSFER_COMPLETE,
            phase_ms=max(0, int(state.last_phase_ms)),
            node_index=max(0, int(state.last_node_index)),
            target_map_id=state.transfer_destination_map,
            message="transfer-complete",
        )
        return True

    def stats(self) -> dict[str, int]:
        cache = get_movement_cache()
        cache.load()
        return {
            "instances": len(self.instances),
            "transport_templates": len(cache.transport_animation),
            "taxi_templates": len(cache.taxi_paths),
        }

    def _transfer_destination_map(self, template_id: str, next_node_index: int) -> int | None:
        template = self.templates.get(str(template_id))
        if template is None:
            return None
        if int(next_node_index) < 0 or int(next_node_index) >= len(template.nodes):
            return None
        return int(template.nodes[int(next_node_index)].map_id)

    def _detect_lifecycle_events(
        self,
        state: MovementRuntimeState,
        transform: MovementTransform,
    ) -> None:
        node_index = int(transform.node_index)
        previous_node = int(state.last_node_index)

        if previous_node >= 0 and node_index != previous_node:
            self._emit_event(
                state,
                MovementLifecycleEventType.ARRIVED,
                phase_ms=int(transform.phase_ms),
                node_index=node_index,
                message="node-change",
            )

            self._emit_event(
                state,
                MovementLifecycleEventType.DEPARTED,
                phase_ms=int(transform.phase_ms),
                node_index=previous_node,
                message="node-change",
            )

        state.last_node_index = node_index

        is_transfer = str(transform.event) == "transfer"
        was_transfer = bool(state.transfer_active)

        if is_transfer and not was_transfer:
            if state.transfer_destination_map is None:
                Logger.warning(
                    "[MovementManager] invalid transfer node instance=0x%016X node=%s phase=%s",
                    int(state.instance.instance_id) & 0xFFFFFFFFFFFFFFFF,
                    node_index,
                    int(transform.phase_ms),
                )
                return

            state.transfer_active = True

            self._emit_event(
                state,
                MovementLifecycleEventType.TRANSFER_BEGIN,
                phase_ms=int(transform.phase_ms),
                node_index=node_index,
                target_map_id=state.transfer_destination_map,
                message="transfer-begin",
            )

        if not is_transfer and was_transfer:
            state.transfer_active = False

            self._emit_event(
                state,
                MovementLifecycleEventType.TRANSFER_COMPLETE,
                phase_ms=int(transform.phase_ms),
                node_index=node_index,
                target_map_id=state.transfer_destination_map,
                message="transfer-exit",
            )

    def _update_visibility_state(self, state: MovementRuntimeState) -> None:
        previous = str(
            state.visibility_state or MovementVisibilityState.ACTIVE.value
        )
        current = self._visibility_state_for_runtime(state)
        state.previous_visibility_state = previous
        state.visibility_state = current.value
        if previous == state.visibility_state:
            return
        if transport_movement_debug_enabled():
            Logger.info(
                "[MovementVisibility] instance=0x%016X %s->%s lifecycle=%s event=%s",
                int(state.instance.instance_id) & 0xFFFFFFFFFFFFFFFF,
                previous,
                state.visibility_state,
                str(state.lifecycle_state),
                str(state.last_event),
            )

    def _visibility_state_for_runtime(
        self,
        state: MovementRuntimeState,
    ) -> MovementVisibilityState:
        if not state.spawned:
            return MovementVisibilityState.DESPAWNED
        lifecycle = str(state.lifecycle_state or "")
        if lifecycle == "DESPAWNED":
            return MovementVisibilityState.DESPAWNED
        if state.transfer_active or lifecycle == "TRANSFER_PENDING":
            return MovementVisibilityState.TRANSFERRING
        if lifecycle in ("DOCKED", "WAITING"):
            return MovementVisibilityState.WAITING
        return MovementVisibilityState.ACTIVE

    def _emit_event(
        self,
        state: MovementRuntimeState,
        event_type: MovementLifecycleEventType,
        *,
        phase_ms: int,
        node_index: int,
        target_map_id: int | None = None,
        message: str = "",
    ) -> None:
        previous = state.lifecycle_events[-1] if state.lifecycle_events else None
        if (
            previous is not None
            and previous.event_type == event_type
            and int(previous.phase_ms) == int(phase_ms)
            and int(previous.node_index) == int(node_index)
        ):
            Logger.debug(
                "[MovementManager] duplicate lifecycle event suppressed instance=0x%016X event=%s",
                int(state.instance.instance_id) & 0xFFFFFFFFFFFFFFFF,
                event_type.value,
            )
            return
        event = MovementLifecycleEvent(
            event_type=event_type,
            instance_id=int(state.instance.instance_id),
            phase_ms=int(phase_ms),
            node_index=int(node_index),
            target_map_id=target_map_id,
            message=str(message),
        )
        state.lifecycle_events = (*state.lifecycle_events[-15:], event)
        self.event_history[int(state.instance.instance_id)] = state.lifecycle_events
        if transport_movement_debug_enabled():
            Logger.info(
                "[MovementEvent] instance=0x%016X event=%s phase=%s node=%s target_map=%s %s",
                int(state.instance.instance_id) & 0xFFFFFFFFFFFFFFFF,
                event.event_type.value,
                int(event.phase_ms),
                int(event.node_index),
                "none" if event.target_map_id is None else int(event.target_map_id),
                str(event.message),
            )

    def _validate_lifecycle_transition(
        self,
        state: MovementRuntimeState,
        previous: str,
        current: str,
    ) -> None:
        if previous == current:
            return
        if not state.spawned and current != "ACTIVE":
            Logger.warning(
                "[MovementManager] invalid lifecycle transition instance=0x%016X %s->%s reason=not_spawned",
                int(state.instance.instance_id) & 0xFFFFFFFFFFFFFFFF,
                previous,
                current,
            )
        state.spawned = True


_MANAGER = MovementManager()


def get_movement_manager() -> MovementManager:
    return _MANAGER
