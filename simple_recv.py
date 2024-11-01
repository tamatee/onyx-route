import socket as sc
import sys
import os
import signal
from termcolor import colored
from utils.socket_tool import *
import binascii

def signal_handler(sig, frame):
    print(colored("\nShutting down server...", "red"))
    sys.exit(0)

def handle_message(message):
    """
    Handle received message with detailed debugging
    """
    try:
        # Show raw message details
        print(colored("\n[DEBUG] Raw message details:", "blue"))
        print(colored(f"Message length: {len(message)} bytes", "blue"))
        print(colored(f"Message hex: {message.hex()[:64]}{'...' if len(message) > 32 else ''}", "blue"))
        
        # Try UTF-8 decode
        try:
            decoded = message.decode('utf-8').strip()
            print(colored("[DEBUG] Successfully decoded as UTF-8", "green"))
            print(colored(f"Decoded content: '{decoded}'", "cyan"))
            return decoded
        except UnicodeDecodeError:
            print(colored("[DEBUG] Failed UTF-8 decode, treating as binary", "yellow"))
            return f"<Binary data: {message.hex()[:32]}...>"
    except Exception as e:
        print(colored(f"[DEBUG] Error handling message: {e}", "red"))
        return "<Error processing message>"

def main():
    # Initialize the socket
    dest_socket = sc.socket(sc.AF_INET, sc.SOCK_STREAM)
    dest_socket.setsockopt(sc.SOL_SOCKET, sc.SO_REUSEADDR, 1)
    dest_ip = '127.0.0.1'
    dest_port = 54321
    
    try:
        dest_socket.bind((dest_ip, dest_port))
        print(colored(f"[INFO] Server is listening on {dest_ip}:{dest_port}", "green"))
        print(colored("[INFO] Waiting for a connection...", "yellow"))
        
        dest_socket.listen(1)
        clientsocket, addr = dest_socket.accept()
        print(colored(f"\n[INFO] Accepted connection from {addr}", "green"))
        print(colored("[DEBUG] Connection established successfully", "blue"))
        
        # Connection handling loop
        while True:
            try:
                # Receive message with length prefix
                print(colored("\n[INFO] Waiting for message...", "yellow"))
                message = recv_message_with_length_prefix(clientsocket)
                
                if not message:
                    print(colored("\n[INFO] Connection closed by client", "red"))
                    break
                
                # Process and display message
                print(colored("\n[DEBUG] Message received:", "blue"))
                print(colored(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}", "blue"))
                print(colored(f"Message size: {len(message)} bytes", "blue"))
                
                # Handle the message
                display_msg = handle_message(message)
                print(colored("\n[INFO] Anonymous Message:", "green"))
                print(colored(f"{display_msg}", "yellow"))
                
                # Get response
                print(colored("\n[INFO] Type response (or QUIT to close): ", "yellow"), end="")
                response = input()
                
                if response.upper() == "QUIT":
                    print(colored("\n[INFO] Closing connection...", "red"))
                    break
                
                # Prepare and send response
                response_bytes = response.encode('utf-8')
                print(colored("\n[DEBUG] Sending response:", "blue"))
                print(colored(f"Response length: {len(response_bytes)} bytes", "blue"))
                print(colored(f"Response content: '{response}'", "blue"))
                
                if not send_message_with_length_prefix(clientsocket, response_bytes):
                    print(colored("\n[ERROR] Failed to send response", "red"))
                    break
                
                print(colored("[DEBUG] Response sent successfully", "green"))
                
            except ConnectionError as e:
                print(colored(f"\n[ERROR] Connection error: {e}", "red"))
                break
            except Exception as e:
                print(colored(f"\n[ERROR] Unexpected error: {e}", "red"))
                continue
                
    except KeyboardInterrupt:
        print(colored("\n[INFO] Server shutdown requested", "yellow"))
    except Exception as e:
        print(colored(f"\n[ERROR] Server error: {e}", "red"))
    finally:
        try:
            clientsocket.close()
        except:
            pass
        try:
            dest_socket.close()
        except:
            pass
        print(colored("\n[INFO] Server shut down", "red"))

if __name__ == "__main__":
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Add imports needed for debugging
    import time
    
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[INFO] Shutting down server...", "red"))
        sys.exit(0)