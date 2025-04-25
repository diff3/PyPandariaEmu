# PyPandariaEmu

A Python-based authentication server for legacy MMO protocol version 5.4.8.

This project is designed to interoperate with the authentication flow of legacy server software, originally derived from [Skyfire 5.4.8](https://codeberg.org/ProjectSkyfire/SkyFire_548).

---

### Requirements

You will need a matching server core compiled from source, specifically commit `2760b4ffa7`.  
To switch to this commit before building:

```bash
git checkout 2760b4ffa7
```

### Description

This tool implements a basic AuthServer that:
	1.	Accepts incoming authentication requests.
	2.	Interfaces with a compatible login database.
	3.	Assists in exploring and understanding the client/server handshake of legacy MMO protocols.

This AuthServer does not replace the game server (WorldServer); a complete setup still requires a compatible core component.



### Usage
	1.	Configure your database connection in the provided config file.
	2.	Launch the AuthServer using Python 3.x.
	3.	Use with a properly routed client for educational purposes only.

### Disclaimer

This project is intended solely for educational and protocol research purposes.
It is not affiliated with or endorsed by any game publisher or vendor.
No game assets or proprietary code are included or distributed.

Use responsibly and within the bounds of applicable software agreements and local law.