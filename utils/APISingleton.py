import asyncio
import websockets
import json
from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader

class APISingleton:
    """
    Singleton class for handling API communication across all servers.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(APISingleton, cls).__new__(cls)
            cls._instance.api_uri = f"ws://{ConfigLoader.load_config()['apiserver']['host']}:{ConfigLoader.load_config()['apiserver']['port']}"
            cls._instance.websocket = None
            asyncio.run(cls._instance.connect_to_api())
        return cls._instance

    async def connect_to_api(self):
        """Connects to the API Server for sending logs and commands."""
        try:
            self.websocket = await websockets.connect(self.api_uri)
            Logger.info("Connected to API Server.")
        except Exception as e:
            Logger.error(f"Failed to connect to API Server: {e}")

    async def send_log(self, level, message):
        """Sends log messages to the API Server."""
        if self.websocket:
            log_data = json.dumps({"level": level, "message": message})
            await self.websocket.send(log_data)

# Example usage:
# api_client = APISingleton()
# asyncio.run(api_client.send_log("INFO", "This is a test log."))
