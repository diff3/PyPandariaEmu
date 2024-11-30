# PyPandariaEmu



A Python AuthServer for World of Warcraft - Mists of Pandaria

PyPandariaEmu is a custom authentication server designed for World of Warcraft - Mists of Pandaria, version 5.4.8. It is compatible with the older [Skyfire 5.4.8](https://codeberg.org/ProjectSkyfire/SkyFire_548) server.



### Requirements

You need to compile SkyFire from source using the commit `2760b4ffa7`. To switch to this commit, use the following command before compiling:  
```bash
git checkout 2760b4ffa7
```



### Description

This AuthServer handles authentication but does not replace the WorldServer. You will still need the WorldServer component from SkyFire.

    1. Provide database login credentials for the Skyfire server.
    2. Patch the wow.exe client as you would when setting up Skyfire.



### Disclaimer

This project is intended as a learning tool and does not aim to create a fully functional server.