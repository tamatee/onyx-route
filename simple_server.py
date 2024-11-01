import socket
from utils.socket_tool import *
from termcolor import colored

def main():
    # Configuration
    HOST = '127.0.0.1'
    PORT = 54321  # You can change this port if needed

    try:
        # Create server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(colored(f"Destination server listening on {HOST}:{PORT}", 'green'))

        while True:
            # Accept client connections
            client_socket, addr = server_socket.accept()
            print(colored(f"Connection from {addr}", 'yellow'))

            try:
                while True:
                    # Receive message
                    message = recv_message_with_length_prefix(client_socket)
                    if not message:
                        break

                    # Decode and print received message
                    print(colored(f"\nReceived message: {message.decode('utf-8')}", 'cyan'))

                    # Send response back
                    response = f"Server received: {message.decode('utf-8')}"
                    send_message_with_length_prefix(client_socket, response.encode('utf-8'))

            except Exception as e:
                print(colored(f"Error handling client: {e}", 'red'))
            finally:
                client_socket.close()

    except Exception as e:
        print(colored(f"Server error: {e}", 'red'))
    finally:
        server_socket.close()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\nShutting down server...", 'red'))