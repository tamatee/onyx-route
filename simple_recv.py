import socket as sc
import sys
import os
import signal
from termcolor import colored
from utils.socket_tool import *

signal.signal(signal.SIGINT, signal_handler)

# Initialize the socket
dest_socket = sc.socket(sc.AF_INET, sc.SOCK_STREAM)
dest_ip = 'localhost' #loopback only for now
dest_port = 12345
dest_socket.bind((dest_ip, dest_port))

# Status for connection
print(colored(f"Server is listening on {dest_ip}:{dest_port}" , "green"))
print(colored("Waiting for a connection...","red"))
dest_socket.listen(1)

# accept the connection
clientsocket, addr = dest_socket.accept()

# accept status
print(colored("Accepted a connection!","red"))

# Main loop to listen for messages
while True:
    try:
        message = recv_message_with_length_prefix(clientsocket)
        if message == b"":
            print(colored("Connection closed by client", "red"))
            sys.exit(0)
        print(colored("Anonymous Message: " + message.decode('utf-8'),'yellow'),end="\n")
        print(colored("Please type a response: ","red"), end="")
        revmessage = input()
        if revmessage == "QUIT":
            try:
                clientsocket.shutdown(sc.SHUT_RDWR)
                socket.shutdown(sc.SHUT_RDWR)
            except socket.error as e:
                pass
            sys.exit(0)
        bytessent = send_message_with_length_prefix(clientsocket, revmessage.encode('utf-8'))
        if bytessent == 0:
            try:
                clientsocket.shutdown(socket.SHUT_RDWR)
                dest_socket.shutdown(socket.SHUT_RDWR)
            except socket.error as e:
                pass
            print(colored("\n\nLost connection to client. Closing...\n", "red"))
    except Exception as e:
        print(colored(f"Error: {e}", "red"))
        print(colored("Connection error or client disconnected", "red"))
        sys.exit(1)