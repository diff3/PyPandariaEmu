# Server

AuthServer and WorldServer for the current `PyPandariaEmu` workspace.

## Overview

This repository contains:

- `authserver` for SRP/login flow and realm list
- `worldserver` for world login, packet handling and game-side logic
- shared handler, opcode, database and crypto code under `server/modules`

The servers use the in-repo DSL runtime for packet decode/encode. They no longer depend on dynamic protocol/bootstrap loading.

## Configuration

Shared defaults:

- [/home/magnus/projects/PyPandariaEmu/config/default.yaml](/home/magnus/projects/PyPandariaEmu/config/default.yaml)

Auth server:

- [/home/magnus/projects/PyPandariaEmu/config/authserver.yaml](/home/magnus/projects/PyPandariaEmu/config/authserver.yaml)

World server:

- [/home/magnus/projects/PyPandariaEmu/config/worldserver.yaml](/home/magnus/projects/PyPandariaEmu/config/worldserver.yaml)

Key output settings for both auth and world:

- `output.raw`
- `output.decode`
- `output.dsl_warnings`
- `output.blacklist`

`blacklist` only hides output. It does not block packet handling.

## Data Paths

The runtime data layout is now centralized under project `data/`:

- `data/def`
- `data/json`
- `data/debug`
- `data/captures`

AuthServer and WorldServer both use config-driven paths through shared path helpers.

## Logging

Each server has its own log file and startup resets it:

- authserver -> `authserver.log`
- worldserver -> `worldserver.log`
- shared DSL file logging -> `dsl.log`

These are controlled from config:

- `authserver.logging.write_to_log`
- `authserver.logging.log_file`
- `worldserver.logging.write_to_log`
- `worldserver.logging.log_file`
- `dsl.write_to_log`
- `dsl.log_file`

## Startup

Run from project root:

```bash
python authserver.py
python worldserver.py
```

Current startup style is intentionally concise:

- banner first
- DSL watcher / runtime status
- database init
- cache preload
- listen socket

## Notes

- DSL runtime load now reports a final ready line instead of per-definition spam
- DSL internal debug output is disabled by default
- DSL warnings can be shown or hidden per server with `output.dsl_warnings`
- missing `.def` messages are shortened to filename form, for example `Missing file MSG_MOVE_FALL_LAND.def`
