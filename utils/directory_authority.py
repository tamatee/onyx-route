# directory_authority.py
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto import Random
import socket
import random
import sys
import hashlib
import traceback
from termcolor import colored
from .socket_tool import *
from .padding_tool import *
from .packing_tool import *

def main():
    NUM_NODES = 3
    DA_IP = "127.0.0.1"
    DA_PORT = 12345

    relay_nodes = {}
    exit_nodes = {}

    try:
        # Read ECC private key
        with open('keys/ecc_private.pem', 'rb') as f:
            da_mykey = ECC.import_key(f.read())

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((DA_IP, DA_PORT))
        s.listen(5)
        print(colored(f"Directory Authority listening on {DA_IP}:{DA_PORT}", 'green'))

        while True:
            try:
                (clientsocket, addr) = s.accept()
                request_type = clientsocket.recv(1)
                
                if request_type == b'n' or request_type == b'e':  # Node registration
                    try:
                        print(colored(f"Receiving {b'exit' if request_type == b'e' else b'relay'} node registration", 'blue'))
                        # Receive address (8 bytes)
                        data = recvn(clientsocket, 8)
                        if not data:
                            print(colored("Error: Empty address data received", 'red'))
                            clientsocket.close()
                            continue
                        node_addr = data
                        
                        # Receive public key
                        data = recv_message_with_length_prefix(clientsocket)
                        if not data:
                            print(colored("Error: Empty public key data received", 'red'))
                            clientsocket.close()
                            continue
                            
                        try:
                            key = ECC.import_key(data)
                            if request_type == b'n':
                                relay_nodes[node_addr] = key
                                port = unpackHostPort(node_addr)[1]
                                print(colored(f"Registered relay node on port {port}", 'green'))
                            else:
                                exit_nodes[node_addr] = key
                                port = unpackHostPort(node_addr)[1]
                                print(colored(f"Registered exit node on port {port}", 'green'))
                        except Exception as e:
                            print(colored(f"Error importing node key: {e}", 'red'))
                            
                    except Exception as e:
                        print(colored(f"Error in node registration: {e}", 'red'))
                        traceback.print_exc()

                elif request_type == b'r':  # Route request
                    try:
                        print(colored("Processing route request...", 'blue'))
                        # Receive client's message
                        encrypted_data = recv_message_with_length_prefix(clientsocket)
                        if not encrypted_data:
                            print(colored("Error: Empty route request received", 'red'))
                            clientsocket.close()
                            continue

                        print(colored(f"Debug - Received encrypted data length: {len(encrypted_data)}", 'blue'))
                        
                        # Extract client's public key
                        pub_key_end = encrypted_data.find(b'-----END PUBLIC KEY-----') + len(b'-----END PUBLIC KEY-----')
                        if pub_key_end == -1:
                            print(colored("Error: Invalid public key format", 'red'))
                            clientsocket.close()
                            continue
                            
                        print(colored(f"Debug - Public key length: {pub_key_end}", 'blue'))
                        
                        try:
                            client_pub_key = ECC.import_key(encrypted_data[:pub_key_end])
                        except Exception as e:
                            print(colored(f"Error importing client public key: {e}", 'red'))
                            clientsocket.close()
                            continue

                        remaining_data = encrypted_data[pub_key_end:]
                        print(colored(f"Debug - Remaining data length: {len(remaining_data)}", 'blue'))
                        
                        # Validate remaining data
                        if len(remaining_data) < 32:  # Minimum: 16 bytes nonce + 16 bytes tag
                            print(colored("Error: Insufficient remaining data", 'red'))
                            clientsocket.close()
                            continue
                            
                        # Extract components
                        nonce = remaining_data[:16]
                        tag = remaining_data[-16:]
                        ciphertext = remaining_data[16:-16]
                        
                        print(colored("Debug - Components:", 'blue'))
                        print(colored(f"Nonce length: {len(nonce)}", 'blue'))
                        print(colored(f"Tag length: {len(tag)}", 'blue'))
                        print(colored(f"Ciphertext length: {len(ciphertext)}", 'blue'))

                        # Derive shared key
                        shared_point = da_mykey.d * client_pub_key.pointQ
                        shared_key = shared_point.x.to_bytes()[:32]
                        
                        key_hash = hashlib.sha256(shared_key).hexdigest()[:8]
                        print(colored(f"Debug - Shared key hash: {key_hash}", 'blue'))
                        
                        # Decrypt client's message
                        aes = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
                        try:
                            aes_key_and_nonce = aes.decrypt_and_verify(ciphertext, tag)
                            
                            if len(aes_key_and_nonce) != 48:  # 32 bytes key + 16 bytes nonce
                                raise ValueError(f"Invalid decrypted length: {len(aes_key_and_nonce)}")
                                
                            aes_key = aes_key_and_nonce[:32]
                            route_nonce = aes_key_and_nonce[32:]
                            
                            # Check available nodes
                            if len(relay_nodes) < NUM_NODES-1 or len(exit_nodes) < 1:
                                print(colored("Error: Insufficient nodes available", 'red'))
                                print(colored(f"Relay nodes: {len(relay_nodes)}, Exit nodes: {len(exit_nodes)}", 'red'))
                                clientsocket.close()
                                continue

                            # Generate route
                            relay_list = random.sample(list(relay_nodes.items()), NUM_NODES-1)
                            exit = random.sample(list(exit_nodes.items()), 1)
                            
                            # Construct route message
                            route_message = b""
                            print(colored("\nConstructing route message...", 'blue'))
                            
                            # Add relay nodes
                            for i, (addr, key) in enumerate(relay_list, 1):
                                route_message += addr  # addr is already bytes
                                key_bytes = key.export_key(format='PEM')
                                if isinstance(key_bytes, str):
                                    key_bytes = key_bytes.encode('utf-8')
                                route_message += key_bytes
                                print(colored(f"Added relay node {i}, current length: {len(route_message)}", 'blue'))
                            
                            # Add exit node
                            route_message += exit[0][0]  # addr is already bytes
                            exit_key_bytes = exit[0][1].export_key(format='PEM')
                            if isinstance(exit_key_bytes, str):
                                exit_key_bytes = exit_key_bytes.encode('utf-8')
                            route_message += exit_key_bytes
                            print(colored(f"Added exit node, final length: {len(route_message)}", 'blue'))

                            # Encrypt route
                            aes_obj = AES.new(aes_key, AES.MODE_GCM, nonce=route_nonce)
                            ciphertext, tag = aes_obj.encrypt_and_digest(route_message)
                            response = ciphertext + tag
                            
                            print(colored("\nSending encrypted route:", 'blue'))
                            print(colored(f"Ciphertext length: {len(ciphertext)}", 'blue'))
                            print(colored(f"Tag length: {len(tag)}", 'blue'))
                            print(colored(f"Total response length: {len(response)}", 'blue'))

                            # Send encrypted route
                            if send_message_with_length_prefix(clientsocket, response):
                                print(colored("Successfully sent route to client", 'green'))
                            else:
                                print(colored("Failed to send route to client", 'red'))

                        except ValueError as e:
                            print(colored(f"Decryption error: {e}", 'red'))
                            print(colored(f"Ciphertext hex: {ciphertext.hex()[:32]}...", 'red'))
                            print(colored(f"Tag hex: {tag.hex()}", 'red'))
                            clientsocket.close()
                            continue

                    except Exception as e:
                        print(colored(f"Error processing route request: {e}", 'red'))
                        traceback.print_exc()

                clientsocket.close()

            except Exception as e:
                print(colored(f"Error handling client connection: {e}", 'red'))
                try:
                    clientsocket.close()
                except:
                    pass

    except Exception as e:
        print(colored(f"Fatal error: {e}", 'red'))
        sys.exit(1)

def construct_route(relays, exit_node):
    """Construct route message from relay nodes and exit node"""
    route_message = b""
    
    try:
        # Add relay nodes
        for addr, key in relays:
            if isinstance(addr, str):
                addr = addr.encode('utf-8')
            key_bytes = key.export_key(format='PEM')
            if isinstance(key_bytes, str):
                key_bytes = key_bytes.encode('utf-8')
            route_message += addr + key_bytes
        
        # Add exit node
        exit_addr, exit_key = exit_node
        if isinstance(exit_addr, str):
            exit_addr = exit_addr.encode('utf-8')
        exit_key_bytes = exit_key.export_key(format='PEM')
        if isinstance(exit_key_bytes, str):
            exit_key_bytes = exit_key_bytes.encode('utf-8')
        route_message += exit_addr + exit_key_bytes
        
        return route_message
        
    except Exception as e:
        print(colored(f"Error constructing route: {e}", 'red'))
        raise

# Add this helper function
def ensure_bytes(data):
    """Ensure data is in bytes format"""
    if isinstance(data, str):
        return data.encode('utf-8')
    elif isinstance(data, bytes):
        return data
    else:
        raise TypeError(f"Data must be string or bytes, not {type(data)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\nShutting down Directory Authority...", 'red'))
        sys.exit(0)
    except Exception as e:
        print(colored(f"Fatal error: {e}", 'red'))
        sys.exit(1)