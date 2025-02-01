import asyncio
import websockets
import json
from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader

# Load config
config = ConfigLoader.load_config()
API_HOST = config['apiserver']['host']
API_PORT = config['apiserver']['port']

async def handle_client(websocket):
    """
    Handles incoming WebSocket connections.
    Listens for log messages and prints them.
    """
    Logger.info(f"New client connected from {websocket.remote_address}")
    
    try:
        async for message in websocket:
            log_data = json.loads(message)
            log_level = log_data.get("level", "INFO")
            log_message = log_data.get("message", "")

            # Print received log message
            Logger.info(log_level, f"[API] {log_message}\n")

    except websockets.exceptions.ConnectionClosed:
        Logger.info(f"Client disconnected: {websocket.remote_address}")

async def start_api_server():
    """
    Starts the API server for handling WebSocket connections.
    """
    Logger.info(f"Starting API Server on {API_HOST}:{API_PORT}")
    async with websockets.serve(handle_client, API_HOST, API_PORT):
        await asyncio.Future()  # Keeps the server running

if __name__ == "__main__":
    try:
        asyncio.run(start_api_server())
    except KeyboardInterrupt:
        Logger.info("API Server shutting down...")
