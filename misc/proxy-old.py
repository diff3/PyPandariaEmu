import socket
import threading

# Function to handle a client connection
def handle_client(client_socket):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect(('192.168.1.30', 9101))

    def forward(src, dest):
        while True:
            data = src.recv(1024)
            if not data:
                break
            dest.sendall(data)

    # Create two threads for bidirectional communication
    client_to_server = threading.Thread(target=forward, args=(client_socket, server_socket))
    server_to_client = threading.Thread(target=forward, args=(server_socket, client_socket))

    client_to_server.start()
    server_to_client.start()

    client_to_server.join()
    server_to_client.join()

    # Close both sockets when done
    client_socket.close()
    server_socket.close()

# Function to start the proxy server
def start_proxy(proxy_port):
    proxy_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_server.bind(('0.0.0.0', proxy_port))
    proxy_server.listen(5)
    print(f"Proxy listening on port {proxy_port}")

    while True:
        client_socket, addr = proxy_server.accept()
        print(f"Accepted connection from {addr}")
        
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

# Start the proxy on port 3000 and forward data to the WoW server at port 3724
start_proxy(9100)

