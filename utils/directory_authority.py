from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
import socket
import random
import sys
from termcolor import colored
from .socket_tool import *
from .padding_tool import *
from .packing_tool import *

def main():
    RSA_KEY_SIZE = 2048  # Change this to match our key size
    NUM_NODES = 3
    DA_IP = "127.0.0.1"
    DA_PORT = 12345

    relay_nodes = {}
    exit_nodes = {}

    try:
        # Read private key
        with open('keys/private.pem', 'rb') as f:
            da_mykey = RSA.import_key(f.read())

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((DA_IP, DA_PORT))
        s.listen(5)
        print(colored(f"Directory Authority listening on {DA_IP}:{DA_PORT}", 'green'))

        while True:
            (clientsocket, addr) = s.accept()
            request_type = clientsocket.recv(1)
            
            if request_type == b'n':  # relay node
                data = recvn(clientsocket, 8)  # Address
                if not data:
                    clientsocket.close()
                    continue
                node_addr = data
                
                data = recv_message_with_length_prefix(clientsocket)  # Public key
                if not data:
                    clientsocket.close()
                    continue
                    
                try:
                    key = RSA.import_key(data)
                    relay_nodes[node_addr] = key
                    port = unpackHostPort(node_addr)[1]
                    print(colored(f"Registered relay node on port {port}", 'green'))
                except Exception as e:
                    print(f"Error importing relay node key: {e}")
                    
            elif request_type == b'e':  # exit node
                data = recvn(clientsocket, 8)  # Address
                if not data:
                    clientsocket.close()
                    continue
                node_addr = data
                
                data = recv_message_with_length_prefix(clientsocket)  # Public key
                if not data:
                    clientsocket.close()
                    continue
                    
                try:
                    key = RSA.import_key(data)
                    exit_nodes[node_addr] = key
                    port = unpackHostPort(node_addr)[1]
                    print(colored(f"Registered exit node on port {port}", 'green'))
                except Exception as e:
                    print(f"Error importing exit node key: {e}")

            elif request_type == b'r':  # route request
                try:
                    aes_enc = recv_message_with_length_prefix(clientsocket)
                    if not aes_enc:
                        clientsocket.close()
                        continue

                    cipher = PKCS1_OAEP.new(da_mykey)
                    aes_key = cipher.decrypt(aes_enc)

                    if len(relay_nodes) < NUM_NODES-1 or len(exit_nodes) < 1:
                        print(colored("Error: Not enough nodes available", 'red'))
                        clientsocket.close()
                        continue

                    # Select nodes for route
                    relay_list = random.sample(list(relay_nodes.items()), NUM_NODES-1)
                    exit = random.sample(list(exit_nodes.items()), 1)

                    # Construct route
                    route_message = b""
                    for addr, key in relay_list:
                        route_message += addr
                        route_message += key.export_key()
                    route_message += exit[0][0]
                    route_message += exit[0][1].export_key()

                    # Encrypt and send route
                    aes_obj = AES.new(aes_key, AES.MODE_CBC, b"0"*16)
                    padded_message = pad_message(route_message)
                    blob = aes_obj.encrypt(padded_message)
                    send_message_with_length_prefix(clientsocket, blob)
                    print(colored("Sent route to client", 'green'))

                except Exception as e:
                    print(colored(f"Error processing route request: {e}", 'red'))

            clientsocket.close()

    except Exception as e:
        print(colored(f"Fatal error: {e}", 'red'))

def construct_route(relays, exit):
   """สร้างข้อความเส้นทางจาก relay nodes และ exit node"""
   message = b""
   # เพิ่ม relay nodes
   for addr, key in relays:
       message += addr + key
   # เพิ่ม exit node
   message += exit[0][0] + exit[0][1]
   return message

if __name__ == "__main__":
   try:
       main()
   except KeyboardInterrupt:
       print(colored("\nShutting down Directory Authority...", 'red'))
       sys.exit(0)
   except Exception as e:
       print(colored(f"Fatal error: {e}", 'red'))
       sys.exit(1)