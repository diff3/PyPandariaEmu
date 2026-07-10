from __future__ import annotations

from pathlib import Path

import yaml

from shared.ConfigLoader import ConfigLoader
from server.modules.handlers.world import feature_config


def test_worldserver_override_enables_experimental_geometry_shadow():
    ConfigLoader.clear_runtime_config()
    try:
        config = ConfigLoader.reload_config()
        assert bool(config["World"]["ExperimentalGeometryShadow"]) is True
        assert feature_config.experimental_geometry_shadow_enabled() is True
    finally:
        ConfigLoader.clear_runtime_config()


def test_experimental_geometry_shadow_can_be_enabled_from_yaml_override(tmp_path: Path):
    override_path = tmp_path / "shadow_override.yaml"
    override_path.write_text(
        yaml.safe_dump({"World": {"ExperimentalGeometryShadow": True}}, sort_keys=False),
        encoding="utf-8",
    )

    ConfigLoader.clear_runtime_config()
    try:
        config = ConfigLoader.reload_config(str(override_path))
        assert bool(config["World"]["ExperimentalGeometryShadow"]) is True
        assert feature_config.experimental_geometry_shadow_enabled() is True
    finally:
        ConfigLoader.clear_runtime_config()


def test_gameobject_collision_mode_can_be_selected_from_yaml(tmp_path: Path):
    override_path = tmp_path / "collision_mode_override.yaml"
    override_path.write_text(
        yaml.safe_dump({"World": {"GameObjectCollisionMode": "shadow_authoritative"}}, sort_keys=False),
        encoding="utf-8",
    )

    ConfigLoader.clear_runtime_config()
    try:
        ConfigLoader.reload_config(str(override_path))
        assert feature_config.gameobject_collision_mode() == "shadow_authoritative"
    finally:
        ConfigLoader.clear_runtime_config()


def test_geometry_contact_separation_epsilon_can_be_selected_from_yaml(tmp_path: Path):
    override_path = tmp_path / "geometry_contact_override.yaml"
    override_path.write_text(
        yaml.safe_dump({"World": {"GeometryContactSeparationEpsilon": 0.075}}, sort_keys=False),
        encoding="utf-8",
    )

    ConfigLoader.clear_runtime_config()
    try:
        ConfigLoader.reload_config(str(override_path))
        assert feature_config.geometry_contact_separation_epsilon() == 0.075
    finally:
        ConfigLoader.clear_runtime_config()
