# PyPandaria Server

Minimal World/Auth server implementation using BinaryPacketsDSL.

## Overview

This server handles:

- Authentication (AuthServer)
- World connections (WorldServer)
- Game logic (handlers, movement, chat, etc.)

It is designed to work together with external components and is NOT standalone.

---

## ⚠️ Requirements

This project depends on other repositories:

- BinaryPacketsDSL (DSL engine)
- SwitchboardProxy (network proxy)
- shared (common utilities)

You MUST install all components via the template project.

---

## Recommended Setup

Use the template repository:

    git clone https://github.com/diff3/template.git MyProject
    cd MyProject

Then install dependencies:

    git clone https://github.com/diff3/BinaryPacketsDSL.git DSL
    git clone https://github.com/diff3/SwitchboardProxy.git proxy
    git clone https://github.com/diff3/PyPandaria.git server
    git clone https://github.com/diff3/shared.git shared

---

## Structure

    server/
    ├── authserver.py
    ├── worldserver.py
    ├── data/
    │   └── def/        # DSL definitions (used by runtime)
    ├── modules/
    │   ├── handlers/   # Opcode handlers
    │   ├── opcodes/    # Opcode maps
    │   ├── database/   # DB layer
    │   └── ...
    └── session/

---

## Running

From the template root:

    source .env

Start servers:

    ./authserver.py
    ./worldserver.py

Proxy (recommended):

    ./proxyserver.py

---

## Notes

- DSL definitions are loaded from:

      server/data/def

- The server does NOT use dynamic protocol loading anymore.
- All protocol-specific logic lives inside this repository.
- Proxy can be used to inspect and modify traffic in real time.

---

## Philosophy

- DSL = parsing/encoding engine
- server = game logic
- proxy = network control
- shared = reusable utilities

This separation keeps each component simple, modular, and replaceable.
