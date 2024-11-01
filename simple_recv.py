import socket as sc
import sys
import os
import signal
from termcolor import colored
from utils.socket_tool import *

signal.signal(signal.SIGINT, signal_handler)

def handle_message(message):
    """
    Handle received message, attempting UTF-8 decode only for text messages
    
    Args:
        message (bytes): Received message
        
    Returns:
        str: Decoded message if possible, or hex representation if binary
    """
    try:
        # Try to decode as UTF-8
        return message.decode('utf-8')
    except UnicodeDecodeError:
        # If decoding fails, assume it's binary data and show hex
        return f"<Binary data: {message[:20].hex()}...>"

def main():
    global dest_socket  # Make accessible to signal handler
    
    # Initialize the socket
    dest_socket = sc.socket(sc.AF_INET, sc.SOCK_STREAM)
    dest_ip = '127.0.0.1'
    dest_port = 54321
    
    try:
        dest_socket.bind((dest_ip, dest_port))
        
        # Status for connection
        print(colored(f"Server is listening on {dest_ip}:{dest_port}", "green"))
        print(colored("Waiting for a connection...", "red"))
        dest_socket.listen(1)
        
        # Accept the connection
        clientsocket, addr = dest_socket.accept()
        print(colored("Accepted a connection!", "green"))
        
        # Main loop to listen for messages
        while True:
            try:
                # Receive message
                message = recv_message_with_length_prefix(clientsocket)
                if not message:
                    print(colored("\nConnection closed by client", "red"))
                    break
                
                # Handle the message
                display_msg = handle_message(message)
                print(colored(f"\nAnonymous Message: {display_msg}", 'yellow'))
                
                # Get response
                print(colored("Please type a response: ", "red"), end="")
                response = input()
                
                if response.upper() == "QUIT":
                    print(colored("\nClosing connection...", "red"))
                    break
                
                # Send response
                if not send_message_with_length_prefix(clientsocket, response.encode('utf-8')):
                    print(colored("\nFailed to send response", "red"))
                    break
                    
            except ConnectionError:
                print(colored("\nConnection lost", "red"))
                break
            except Exception as e:
                print(colored(f"\nError: {e}", "red"))
                print(colored("Continuing to listen...", "yellow"))
                continue
                
    except Exception as e:
        print(colored(f"Server error: {e}", "red"))
    finally:
        try:
            clientsocket.close()
        except:
            pass
        try:
            dest_socket.close()
        except:
            pass
        print(colored("\nServer shut down", "red"))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\nShutting down server...", "red"))
        sys.exit(0)