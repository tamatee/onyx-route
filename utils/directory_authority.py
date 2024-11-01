from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto import Random
import socket
import random
import sys
import os
import time
from termcolor import colored
from .socket_tool import *
from .packing_tool import *
from .ecc_encryption import ECCTools

class DirectoryAuthority:
    def __init__(self, ip="127.0.0.1", port=12345, num_nodes=3):
        self.ip = ip
        self.port = port
        self.num_nodes = num_nodes
        self.relay_nodes = {}  # addr -> (public_key, timestamp)
        self.exit_nodes = {}   # addr -> (public_key, timestamp)
        self.private_key = None
        self.public_key = None
        self.debug = True
        
    def debug_log(self, message, color='blue'):
        """Debug logging helper"""
        if self.debug:
            print(colored(f"[DEBUG] {message}", color))

    def register_node(self, addr, public_key_bytes, is_exit):
        """Register a new node with the directory"""
        try:
            # Debug the received data
            self.debug_log(f"Registering {'exit' if is_exit else 'relay'} node")
            self.debug_log(f"Address length: {len(addr)}")
            self.debug_log(f"Public key data length: {len(public_key_bytes)}")
            
            # Create key copy
            addr_key = bytes(addr)
            host, port = unpackHostPort(addr)
            
            try:
                # Parse the public key
                public_key = ECCTools.public_key_from_bytes(public_key_bytes)
                self.debug_log("Successfully parsed public key")
            except Exception as e:
                self.debug_log(f"Failed to parse public key: {e}", "red")
                return False

            timestamp = time.time()
            
            # Store the node information
            if is_exit:
                self.exit_nodes[addr_key] = (public_key, timestamp)
                node_type = "exit"
            else:
                self.relay_nodes[addr_key] = (public_key, timestamp)
                node_type = "relay"
            
            self.debug_log(f"Successfully registered {node_type} node at {host}:{port}")
            self.debug_log(f"Current relay nodes: {len(self.relay_nodes)}")
            self.debug_log(f"Current exit nodes: {len(self.exit_nodes)}")
            
            # List all registered nodes
            self.debug_log("\nCurrently registered relay nodes:")
            for n_addr, (_, ts) in self.relay_nodes.items():
                h, p = unpackHostPort(n_addr)
                self.debug_log(f"  {h}:{p} (age: {time.time() - ts:.1f}s)")
            
            self.debug_log("\nCurrently registered exit nodes:")
            for n_addr, (_, ts) in self.exit_nodes.items():
                h, p = unpackHostPort(n_addr)
                self.debug_log(f"  {h}:{p} (age: {time.time() - ts:.1f}s)")
            
            return True
            
        except Exception as e:
            self.debug_log(f"Error in register_node: {e}", "red")
            import traceback
            self.debug_log(traceback.format_exc())
            return False

    def handle_route_request(self, clientsocket):
        """Handle a route request from a client"""
        try:
            self.debug_log("Handling route request...")
            
            # Receive encrypted data
            encrypted_package = recv_message_with_length_prefix(clientsocket)
            if not encrypted_package:
                self.debug_log("Empty encrypted package received", "red")
                return False
                
            self.debug_log(f"Received encrypted package of length: {len(encrypted_package)}")
            
            try:
                # Parse the encrypted package
                ephemeral_key_size = len(ECCTools.key_to_bytes(self.public_key))
                tag_size = 16
                nonce_size = 12
                
                ephemeral_public_bytes = encrypted_package[:ephemeral_key_size]
                encrypted_data = encrypted_package[ephemeral_key_size:-tag_size-nonce_size]
                tag = encrypted_package[-tag_size-nonce_size:-nonce_size]
                nonce = encrypted_package[-nonce_size:]
                
                # Decrypt the AES key and nonce
                decrypted_data = ECCTools.decrypt_message(
                    self.private_key,
                    ephemeral_public_bytes,
                    encrypted_data,
                    tag,
                    nonce
                )
                
                aes_key = decrypted_data[:32]
                aes_nonce = decrypted_data[32:]
                self.debug_log("Successfully decrypted key package")
                
                # Generate route
                route_data = self.generate_route()
                self.debug_log(f"Generated route data of length: {len(route_data)}")
                
                # Encrypt route with AES-GCM
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
                ciphertext, tag = cipher.encrypt_and_digest(route_data)
                
                # Send encrypted route
                response = ciphertext + tag
                if not send_message_with_length_prefix(clientsocket, response):
                    self.debug_log("Failed to send encrypted route", "red")
                    return False
                    
                self.debug_log(f"Successfully sent encrypted route of length: {len(response)}")
                return True
                
            except Exception as e:
                self.debug_log(f"Error processing route request: {e}", "red")
                return False
                
        except Exception as e:
            self.debug_log(f"Error in handle_route_request: {e}", "red")
            return False

    def run(self):
        """Run the directory authority server"""
        server_socket = None
        try:
            self.load_keys()
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.ip, self.port))
            server_socket.listen(5)
            
            print(colored(f"Directory Authority listening on {self.ip}:{self.port}", 'green'))
            
            while True:
                try:
                    clientsocket, address = server_socket.accept()
                    clientsocket.settimeout(10)  # 10 second timeout
                    self.debug_log(f"Accepted connection from {address}")
                    
                    try:
                        request_type = clientsocket.recv(1)
                        self.debug_log(f"Received request type: {request_type}")
                        
                        if request_type == b'n' or request_type == b'e':  # node registration
                            # Receive address
                            node_addr = recvn(clientsocket, 8)
                            if not node_addr:
                                self.debug_log("Failed to receive node address", "red")
                                continue
                            
                            # Receive public key
                            public_key_data = recv_message_with_length_prefix(clientsocket)
                            if not public_key_data:
                                self.debug_log("Failed to receive public key data", "red")
                                continue
                                
                            self.debug_log(f"Received public key data length: {len(public_key_data)}")
                            
                            # Register the node
                            if self.register_node(node_addr, public_key_data, request_type == b'e'):
                                clientsocket.send(b'OK')
                                self.debug_log("Sent OK to node")
                            else:
                                clientsocket.send(b'ER')
                                self.debug_log("Sent error to node", "red")
                            
                        elif request_type == b'r':  # route request
                            self.handle_route_request(clientsocket)
                            
                    finally:
                        clientsocket.close()
                        
                except Exception as e:
                    self.debug_log(f"Error handling client connection: {e}", "red")
                    import traceback
                    self.debug_log(traceback.format_exc())
                    
        finally:
            if server_socket:
                server_socket.close()

    def load_keys(self):
        """Load or generate ECC key pair"""
        try:
            if not os.path.exists('keys'):
                os.makedirs('keys')
                
            private_key_path = 'keys/ecc_private.pem'
            public_key_path = 'keys/ecc_public.pem'
            
            if os.path.exists(private_key_path) and os.path.exists(public_key_path):
                with open(private_key_path, 'rb') as f:
                    private_key_data = f.read()
                with open(public_key_path, 'rb') as f:
                    public_key_data = f.read()
                    
                self.private_key = ECCTools.private_key_from_bytes(private_key_data)
                self.public_key = ECCTools.public_key_from_bytes(public_key_data)
                self.debug_log("Loaded existing ECC keys successfully")
                return
                
            # Generate new keys
            self.debug_log("Generating new ECC keys...", "yellow")
            self.private_key, self.public_key = ECCTools.generate_keypair()
            
            # Save the keys
            with open(private_key_path, 'wb') as f:
                f.write(ECCTools.key_to_bytes(self.private_key).encode('utf-8'))
            with open(public_key_path, 'wb') as f:
                f.write(ECCTools.key_to_bytes(self.public_key).encode('utf-8'))
            
            self.debug_log("Generated and saved new ECC keys successfully", "green")
            
        except Exception as e:
            self.debug_log(f"Error in load_keys: {e}", "red")
            raise

    def generate_route(self):
        """Generate a random route through the network"""
        self.debug_log("Starting route generation...")
        
        # Don't cleanup nodes during route generation to avoid race conditions
        self.debug_log(f"Available relay nodes: {len(self.relay_nodes)}")
        self.debug_log(f"Available exit nodes: {len(self.exit_nodes)}")
        
        if len(self.relay_nodes) < self.num_nodes-1:
            raise ValueError(f"Not enough relay nodes: have {len(self.relay_nodes)}, need {self.num_nodes-1}")
        if len(self.exit_nodes) < 1:
            raise ValueError(f"No exit nodes available")
            
        relay_items = list(self.relay_nodes.items())
        exit_items = list(self.exit_nodes.items())
        
        selected_relays = random.sample(relay_items, self.num_nodes-1)
        selected_exit = random.choice(exit_items)
        
        self.debug_log("Selected route:")
        route_data = b""
        
        for addr, (key, _) in selected_relays:
            host, port = unpackHostPort(addr)
            self.debug_log(f"  Relay: {host}:{port}")
            route_data += addr
            route_data += ECCTools.key_to_bytes(key).encode('utf-8')
            
        exit_host, exit_port = unpackHostPort(selected_exit[0])
        self.debug_log(f"  Exit: {exit_host}:{exit_port}")
        route_data += selected_exit[0]
        route_data += ECCTools.key_to_bytes(selected_exit[1][0]).encode('utf-8')
        
        return route_data

def main():
    print(colored("Starting Directory Authority...", "green"))
    try:
        authority = DirectoryAuthority()
        authority.run()
    except KeyboardInterrupt:
        print(colored("\nShutting down Directory Authority...", "red"))
        sys.exit(0)
    except Exception as e:
        print(colored(f"Fatal error: {e}", "red"))
        sys.exit(1)

if __name__ == "__main__":
    import signal
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    main()