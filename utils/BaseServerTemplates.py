
import socket
from utils.Logger import Logger
import threading
import traceback

class BaseProxy:
    DIRECTION_CLIENT_SERVER = "Client --> Server"
    DIRECTION_SERVER_CLIENT = "Server --> Client"
    
    
    """
    Basklass för proxyservern. Stödjer en gemensam flagga för att stoppa servern.
    """
    def __init__(self, local_host: str, local_port: int, remote_host: str, remote_port: int, stop_event: threading.Event):
        self.local_host = local_host
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.stop_event = stop_event

    def start(self) -> None:
        """
        Startar proxyservern och lyssnar på inkommande anslutningar.
        """
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.local_host, self.local_port))
            server_socket.listen(5)
            Logger.info(f"{self.__class__.__name__} listening on {self.local_host}:{self.local_port}")

            while not self.stop_event.is_set():
                try:
                    server_socket.settimeout(1.0)  # Timeout för att kontrollera stop_event
                    client_socket, addr = server_socket.accept()
                    Logger.success(f"Accepted connection from {addr}")
                    threading.Thread(target=self.handle_connection, args=(client_socket,)).start()
                except socket.timeout:
                    continue  # Kontrollera flaggan igen efter timeout
        except Exception as e:
            error_details = traceback.format_exc()
            Logger.error(f"Error in {self.__class__.__name__}: {e}\n{error_details}")
        finally:
            server_socket.close()
            Logger.success(f"{self.__class__.__name__} stopped.")

    def handle_connection(self, client_socket: socket.socket) -> None:
        """
        Hanterar en anslutning mellan klient och fjärrserver.
        """
        Logger.info(f"{self.__class__.__name__} listening on {self.local_host}:{self.local_port}")
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.remote_host, self.remote_port))

            client_to_server = threading.Thread(target=self.forward_data, args=(client_socket, server_socket, self.DIRECTION_CLIENT_SERVER))
            server_to_client = threading.Thread(target=self.forward_data, args=(server_socket, client_socket, self.DIRECTION_SERVER_CLIENT))

            client_to_server.start()
            server_to_client.start()

            client_to_server.join()
            server_to_client.join()
        except Exception as e:
            error_details = traceback.format_exc()
            Logger.error(f"Connection error in {self.__class__.__name__}: {e}\n{error_details}")
        finally:
            client_socket.close()
            server_socket.close()

    def forward_data(self, source_socket: socket.socket, destination_socket: socket.socket, direction: str) -> None:
        """
        Vidarebefordrar data mellan två sockets.
        """
        raise NotImplementedError("Subclasses must implement forward_data")


class BaseServer:
    """
    Base class for standalone servers (e.g., AuthServer, WorldServer).
    Handles incoming client connections and processes requests.
    """

    def __init__(self, local_host, local_port, stop_event=None):
        """
        Initializes the standalone server.

        Args:
            local_host (str): The host address for the server.
            local_port (int): The port to listen on.
            stop_event (threading.Event, optional): Event to signal shutdown.
        """
        self.local_host = local_host
        self.local_port = local_port
        self.stop_event = stop_event or threading.Event()
        self.server_socket = None

    def start_server(self):
        """
        Starts a standalone server that listens and processes client connections.
        """
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.local_host, self.local_port))
        self.server_socket.listen(5)
        Logger.info(f"Server listening at {self.local_host}:{self.local_port}")

        while not self.stop_event.is_set():
            try:
                self.server_socket.settimeout(1.0)  # <-- Gör att accept() inte blockerar evigt
                client_socket, addr = self.server_socket.accept()
                Logger.success(f"Accepted connection from {addr}")
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.start()
            except socket.timeout:
                continue  # Fortsätt loopen så att vi kan kolla `stop_event`
            except Exception as e:
                Logger.error(f"Error in server: {e}")
        
        Logger.info("Stopping server...")
        self.server_socket.close()  # Stäng socket vid avstängning

    def handle_client(self, client_socket):
        """
        Placeholder for client handling.
        This must be implemented in subclasses.
        """
        raise NotImplementedError("Subclasses must implement handle_client()")
