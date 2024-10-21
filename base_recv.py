from socket import *
import threading
import util.socket_tool as socket_tool

# Handle communication between server and each client
def handle_client(client_socket, client_address):
    print(f"New connection: {client_address}")
    while True:
        try:
            message = socket_tool.recv_message(client_socket)
            if not message:
                break
            elif message == "exit":
                client_socket.close()
                break
            print(f"Received from {client_address}: {message}")
        except:
            client_socket.close()
            break

def start_server():
    server_ip = 'localhost'  # Listens on all interfaces
    server_port = 12345  # The port the server listens on

    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(5)  # Can handle up to 5 clients simultaneously

    print(f"Server is listening on {server_ip}:{server_port}")

    while True:
        client_socket, client_address = server_socket.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        thread.start()

# Run the server
if __name__ == "__main__":
    start_server()
