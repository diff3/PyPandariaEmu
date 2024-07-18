import socket
import threading
from utils.authcodes import AuthResult, LoginResult, is_accepted_client_build, get_build_info

# Definiera autentiseringskoderna
AUTH_LOGON_CHALLENGE = 0x00
AUTH_LOGON_PROOF = 0x01
AUTH_RECONNECT_CHALLENGE = 0x02
AUTH_RECONNECT_PROOF = 0x03
REALM_LIST = 0x10
XFER_INITIATE = 0x30
XFER_DATA = 0x31
XFER_ACCEPT = 0x32
XFER_RESUME = 0x33
XFER_CANCEL = 0x34

# Funktion för att få namn på autentiseringskoder
def get_auth_opcode_name(opcode):
    if opcode == AUTH_LOGON_CHALLENGE:
        return "AUTH_LOGON_CHALLENGE"
    elif opcode == AUTH_LOGON_PROOF:
        return "AUTH_LOGON_PROOF"
    elif opcode == AUTH_RECONNECT_CHALLENGE:
        return "AUTH_RECONNECT_CHALLENGE"
    elif opcode == AUTH_RECONNECT_PROOF:
        return "AUTH_RECONNECT_PROOF"
    elif opcode == REALM_LIST:
        return "REALM_LIST"
    elif opcode == XFER_INITIATE:
        return "XFER_INITIATE"
    elif opcode == XFER_DATA:
        return "XFER_DATA"
    elif opcode == XFER_ACCEPT:
        return "XFER_ACCEPT"
    elif opcode == XFER_RESUME:
        return "XFER_RESUME"
    elif opcode == XFER_CANCEL:
        return "XFER_CANCEL"
    else:
        return f"Unknown Opcode: {opcode}"

# Modifiera parse_data för att inkludera autentiseringskoder
def parse_data(data):
    try:
        text_data = data.decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        text_data = repr(data)
    return text_data

def get_build_version(data):
    if len(data) > 4:
        build = int.from_bytes(data[4:8], byteorder='little')
        if is_accepted_client_build(build):
            build_info = get_build_info(build)
            return f"{build_info.major_version}.{build_info.minor_version}.{build_info.bugfix_version}{build_info.hotfix_version} (Build {build})"
    return "Unknown Build"

def forward_data(source, destination, direction):
    while True:
        data = source.recv(4096)
        if len(data) == 0:
            break
        opcode = data[0]
        auth_opcode_name = get_auth_opcode_name(opcode)
        text_data = parse_data(data)
        build_version = get_build_version(data)
        
        # Print the structured output
        # print(f"{direction}")
        print(f"{direction} : OPCODE : {auth_opcode_name}")
        print(f"   Data: {data}")
#        print(f"   Decoded data: {text_data}")
#        print(f"   Build version: {build_version}")
        
        destination.sendall(data)

def handle_client(client_socket, remote_host, remote_port):
    # Connect to the actual server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((remote_host, remote_port))
    
    # Create threads to forward data in both directions
    client_to_server = threading.Thread(target=forward_data, args=(client_socket, server_socket, "Client to Server"))
    server_to_client = threading.Thread(target=forward_data, args=(server_socket, client_socket, "Server to Client"))
    
    client_to_server.start()
    server_to_client.start()
    
    client_to_server.join()
    server_to_client.join()
    
    client_socket.close()
    server_socket.close()

def start_proxy(local_host, local_ports, remote_host, remote_port):
    for local_port in local_ports:
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.bind((local_host, local_port))
        proxy_socket.listen(5)
        
        print(f"Proxy listening on {local_host}:{local_port}")
        
        threading.Thread(target=accept_connections, args=(proxy_socket, remote_host, remote_port)).start()

def accept_connections(proxy_socket, remote_host, remote_port):
    while True:
        client_socket, addr = proxy_socket.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, remote_host, remote_port))
        client_handler.start()

if __name__ == "__main__":
    local_host = "0.0.0.0"
    # local_ports = [3722]
    local_ports = [8084]
    remote_host = "192.168.11.30"
    # remote_port = 3724
    remote_port = 8085
    
    start_proxy(local_host, local_ports, remote_host, remote_port)

