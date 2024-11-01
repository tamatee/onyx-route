from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto import Random
import hashlib
from .socket_tool import *
from .padding_tool import *
from .packing_tool import *
from .ecc_encryption import ECCTools
from .timing_tool import ProcessTimer
import socket
import sys
from termcolor import colored

class TorClient:
    def __init__(self, da_ip='127.0.0.1', da_port=12345, dest_host='127.0.0.1', dest_port=54321):
        self.da_ip = da_ip
        self.da_port = da_port
        self.dest_host = dest_host
        self.dest_port = dest_port
        self.timer = ProcessTimer()
        self.debug = True

    def debug_log(self, message, color='blue'):
        """Debug logging helper"""
        if self.debug:
            print(colored(message, color))

    def wrap_message_for_hop(self, message, public_key):
        """Wrap a message for a single hop using ECC"""
        if isinstance(message, str):
            message = message.encode('utf-8')
            
        # Generate encryption parameters
        aes_key = Random.get_random_bytes(32)
        nonce = Random.get_random_bytes(12)
        
        # First, encrypt the message with AES-GCM
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        
        # Then encrypt the AES key and nonce using ECC
        ephem_pub_key, enc_key_data, key_tag, key_nonce = ECCTools.encrypt_message(
            public_key,
            aes_key + nonce
        )
        
        # Combine all components
        wrapped = (
            ephem_pub_key +           # Ephemeral public key
            enc_key_data +            # Encrypted AES key + nonce
            key_tag +                 # Tag for key encryption
            key_nonce +               # Nonce for key encryption
            ciphertext +              # Encrypted message
            tag                       # Tag for message encryption
        )
        
        return wrapped, aes_key, nonce

    def prepare_circuit(self, hoplist, destination):
        """Prepare the circuit through the Tor network"""
        self.debug_log("Preparing circuit...")
        
        # Start with the destination address
        current_message = packHostPort(self.dest_host, self.dest_port)
        aes_keys = []
        nonces = []
        
        # Wrap message for each hop in reverse order
        for i, (host, port, public_key) in enumerate(reversed(hoplist)):
            self.debug_log(f"Wrapping for hop {len(hoplist) - i}: {host}:{port}")
            
            # Add previous hop address if not first hop
            if i != 0:
                prev_host, prev_port, _ = hoplist[len(hoplist) - i]
                current_message = packHostPort(prev_host, prev_port) + current_message
            
            # Wrap the message
            wrapped_message, aes_key, nonce = self.wrap_message_for_hop(current_message, public_key)
            current_message = wrapped_message
            aes_keys.insert(0, aes_key)
            nonces.insert(0, nonce)
            
            # Debug info
            key_hash = hashlib.sha256(aes_key).hexdigest()[:8]
            nonce_hash = hashlib.sha256(nonce).hexdigest()[:8]
            self.debug_log(f"Layer {len(hoplist) - i} - Key hash: {key_hash}, Nonce hash: {nonce_hash}")
        
        return current_message, aes_keys, nonces

    def handle_response(self, response, aes_keys, nonces):
        """Handle and decrypt response from the network"""
        try:
            current_response = response
            
            # Decrypt each layer
            for i, (aes_key, nonce) in enumerate(zip(aes_keys, nonces)):
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                
                # Split response into ciphertext and tag
                ciphertext = current_response[:-16]
                tag = current_response[-16:]
                
                # Decrypt this layer
                current_response = cipher.decrypt_and_verify(ciphertext, tag)
                
            return current_response
            
        except Exception as e:
            self.debug_log(f"Error handling response: {e}", 'red')
            raise

    def run(self):
        """Run the Tor client"""
        try:
            # Get route from Directory Authority
            self.debug_log("Getting route from Directory Authority...")
            hoplist = self.get_route()
            
            # Connect to first node
            first_hop = hoplist[0]
            self.debug_log(f"Connecting to first hop: {first_hop[0]}:{first_hop[1]}")
            
            next_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            next_sock.settimeout(10)
            next_sock.connect((first_hop[0], first_hop[1]))
            
            # Create initial circuit
            self.debug_log("Creating circuit...")
            wrapped_message, aes_keys, nonces = self.prepare_circuit(hoplist, destination=None)
            
            # Send initial setup message
            if not send_message_with_length_prefix(next_sock, wrapped_message):
                raise Exception("Failed to send initial setup message")
            
            print(colored("\nConnection established through Tor network!", 'green'))
            print(colored("Type 'QUIT' to exit", 'yellow'))
            
            # Main communication loop
            while True:
                print(colored("\nCLIENT: Type message to send:", 'yellow'))
                message = input()
                
                if message.upper() == 'QUIT':
                    break
                    
                try:
                    # Encrypt message for all layers
                    current_message = message.encode('utf-8')
                    for i, (aes_key, nonce) in enumerate(zip(aes_keys, nonces)):
                        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                        current_message, tag = cipher.encrypt_and_digest(current_message)
                        current_message += tag
                        
                    # Send encrypted message
                    if not send_message_with_length_prefix(next_sock, current_message):
                        raise Exception("Failed to send message")
                        
                    # Receive and decrypt response
                    response = recv_message_with_length_prefix(next_sock)
                    if not response:
                        raise Exception("No response received")
                        
                    # Handle the response
                    decrypted_response = self.handle_response(response, aes_keys, nonces)
                    
                    print(colored("\nCLIENT: Response from server:", 'green'))
                    print(colored(decrypted_response.decode('utf-8'), 'blue'))
                    
                except Exception as e:
                    print(colored(f"\nError during communication: {e}", 'red'))
                    break
            
            print(colored("Closing connection...", 'red'))
            
        except Exception as e:
            print(colored(f"Error: {e}", 'red'))
        finally:
            try:
                next_sock.close()
            except:
                pass

    def get_route(self):
        """Get route from Directory Authority"""
        try:
            # Load Directory Authority's public key
            with open('keys/ecc_public.pem', 'rb') as f:
                da_key_data = f.read()
                da_pub_key = ECCTools.public_key_from_bytes(da_key_data)

            # Connect to Directory Authority
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.da_ip, self.da_port))
            s.send(b'r')  # Request route

            # Create encryption parameters
            aes_key = Random.get_random_bytes(32)
            nonce = Random.get_random_bytes(12)
            key_and_nonce = aes_key + nonce

            # Encrypt parameters using ECC
            ephem_pub_key, encrypted_data, tag, enc_nonce = ECCTools.encrypt_message(
                da_pub_key,
                key_and_nonce
            )

            # Send encrypted request
            combined_message = ephem_pub_key + encrypted_data + tag + enc_nonce
            if not send_message_with_length_prefix(s, combined_message):
                raise Exception("Failed to send route request")

            # Receive encrypted route
            encrypted_route = recv_message_with_length_prefix(s)
            if not encrypted_route:
                raise Exception("No response from Directory Authority")

            # Decrypt route
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            route_ciphertext = encrypted_route[:-16]
            route_tag = encrypted_route[-16:]
            route_data = cipher.decrypt_and_verify(route_ciphertext, route_tag)

            s.close()
            
            # Process route data
            nodes = process_route(route_data)
            if not nodes:
                raise Exception("Failed to process route data")
                
            self.debug_log(f"Received route with {len(nodes)} nodes")
            return nodes

        except Exception as e:
            print(colored(f"Error getting route: {e}", 'red'))
            raise

def main():
    try:
        client = TorClient()
        client.run()
    except KeyboardInterrupt:
        print(colored("\nClosing client...", 'red'))
    except Exception as e:
        print(colored(f"Fatal error: {e}", 'red'))