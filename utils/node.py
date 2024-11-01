from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto import Random
import socket
import threading
import hashlib
import signal
import sys
from termcolor import colored
from .socket_tool import *
from .packing_tool import *
from .ecc_encryption import ECCTools

class TorNode:
    def __init__(self, port=None, is_exit=False):
        self.port = port or 7000
        self.ip = "127.0.0.1"
        self.da_ip = "127.0.0.1"
        self.da_port = 12345
        self.is_exit = is_exit
        self.private_key = None
        self.public_key = None
        
    def generate_keys(self):
        """Generate new ECC key pair"""
        self.private_key, self.public_key = ECCTools.generate_keypair()
        print(colored("Generated new ECC key pair", 'green'))
        
        # Debug: verify key format
        pub_key_str = ECCTools.key_to_bytes(self.public_key)
        print(colored(f"Debug: Generated public key format check: {pub_key_str[:50]}...", 'blue'))
        
    def register_with_da(self):
        """Register with Directory Authority"""
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                # Create socket
                da_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                da_sock.settimeout(10)  # 10 second timeout
                
                # Connect to Directory Authority
                print(colored(f"Connecting to DA at {self.da_ip}:{self.da_port}", 'blue'))
                da_sock.connect((self.da_ip, self.da_port))
                
                # Send node type identifier
                node_type = b'e' if self.is_exit else b'n'
                print(colored(f"Sending node type: {node_type}", 'blue'))
                da_sock.send(node_type)
                
                # Send address
                addr = packHostPort(self.ip, self.port)
                print(colored(f"Sending address (length: {len(addr)})", 'blue'))
                if da_sock.send(addr) != len(addr):
                    raise Exception("Failed to send complete address")
                
                # Prepare public key data
                pub_key_str = ECCTools.key_to_bytes(self.public_key)
                pub_key_bytes = pub_key_str.encode('utf-8')
                print(colored(f"Sending public key (length: {len(pub_key_bytes)})", 'blue'))
                print(colored(f"Public key preview: {pub_key_bytes[:50]}...", 'blue'))
                
                # Send public key with length prefix
                if not send_message_with_length_prefix(da_sock, pub_key_bytes):
                    raise Exception("Failed to send public key")
                
                # Wait for acknowledgment
                print(colored("Waiting for acknowledgment...", 'blue'))
                response = da_sock.recv(2)
                if not response:
                    raise Exception("No acknowledgment received")
                
                if response != b'OK':
                    raise Exception(f"Unexpected response from DA: {response}")
                
                print(colored(f"Successfully registered with Directory Authority", 'green'))
                da_sock.close()
                return
                
            except Exception as e:
                print(colored(f"Registration attempt {retry_count + 1} failed: {e}", 'yellow'))
                retry_count += 1
                if retry_count < max_retries:
                    print(colored("Retrying registration...", 'yellow'))
                    time.sleep(1)  # Wait before retry
                else:
                    print(colored(f"Failed to register with DA after {max_retries} attempts", 'red'))
                    raise
            finally:
                try:
                    da_sock.close()
                except:
                    pass
                    
    def handle_connection(self, clientsocket):
        """Handle incoming connection and message routing"""
        try:
            print(colored("Receiving initial setup message...", 'blue'))
            # Receive initial setup message
            message = recv_message_with_length_prefix(clientsocket)
            if not message:
                print(colored("Empty message received", 'red'))
                return

            print(colored(f"Received message length: {len(message)}", 'blue'))

            # Extract ECC components and decrypt
            try:
                ephemeral_key_size = len(ECCTools.key_to_bytes(self.public_key))
                tag_size = 16
                nonce_size = 12

                print(colored("Parsing message components...", 'blue'))
                ephemeral_public_bytes = message[:ephemeral_key_size]
                encrypted_data = message[ephemeral_key_size:-tag_size-nonce_size]
                tag = message[-tag_size-nonce_size:-nonce_size]
                nonce = message[-nonce_size:]

                print(colored("Attempting message decryption...", 'blue'))
                decrypted_data = ECCTools.decrypt_message(
                    self.private_key,
                    ephemeral_public_bytes,
                    encrypted_data,
                    tag,
                    nonce
                )
                print(colored("Successfully decrypted message", 'green'))
            except Exception as e:
                print(colored(f"Decryption error: {e}", 'red'))
                import traceback
                print(colored(traceback.format_exc(), 'red'))
                return

            # Extract next hop information
            try:
                next_addr = decrypted_data[:8]
                next_message = decrypted_data[8:]
                next_host, next_port = unpackHostPort(next_addr)
                print(colored(f"Next hop: {next_host}:{next_port}", 'blue'))
            except Exception as e:
                print(colored(f"Error extracting next hop: {e}", 'red'))
                return

            if not self.is_exit:
                # Relay node behavior
                try:
                    print(colored("Operating as relay node", 'blue'))
                    next_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    next_sock.settimeout(10)  # 10 second timeout

                    print(colored(f"Connecting to next hop {next_host}:{next_port}", 'blue'))
                    next_sock.connect((next_host, next_port))

                    # Forward the message
                    if not send_message_with_length_prefix(next_sock, next_message):
                        print(colored("Failed to forward message", 'red'))
                        return

                    # Generate AES key and nonce for this hop
                    aes_key = Random.get_random_bytes(32)
                    aes_nonce = Random.get_random_bytes(16)
                    print(colored("Generated encryption parameters for relay", 'blue'))

                    self.handle_relay_communication(clientsocket, next_sock, aes_key, aes_nonce)
                except Exception as e:
                    print(colored(f"Relay error: {e}", 'red'))
                finally:
                    try:
                        next_sock.close()
                    except:
                        pass
            else:
                # Exit node behavior
                try:
                    print(colored("Operating as exit node", 'blue'))
                    dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    dest_sock.settimeout(10)  # 10 second timeout

                    print(colored(f"Connecting to destination {next_host}:{next_port}", 'blue'))
                    dest_sock.connect((next_host, next_port))

                    # Generate AES key and nonce for this hop
                    aes_key = Random.get_random_bytes(32)
                    aes_nonce = Random.get_random_bytes(16)
                    print(colored("Generated encryption parameters for exit node", 'blue'))

                    self.handle_exit_communication(clientsocket, dest_sock, aes_key, aes_nonce)
                except Exception as e:
                    print(colored(f"Exit node error: {e}", 'red'))
                finally:
                    try:
                        dest_sock.close()
                    except:
                        pass

        except Exception as e:
            print(colored(f"Connection handling error: {e}", 'red'))
            import traceback
            print(colored(traceback.format_exc(), 'red'))
        finally:
            try:
                clientsocket.close()
            except:
                pass

    def handle_initial_message(self, message):
        """Handle initial setup message with improved error handling"""
        try:
            print(colored("Processing initial setup message...", 'blue'))

            # Get the ephemeral key size for message parsing
            ephemeral_key_size = len(ECCTools.key_to_bytes(self.public_key))
            tag_size = 16
            nonce_size = 12

            # Extract message components
            if len(message) < ephemeral_key_size + tag_size + nonce_size:
                raise ValueError("Message too short")

            components = {
                'ephemeral_public_key': message[:ephemeral_key_size],
                'encrypted_data': message[ephemeral_key_size:-tag_size-nonce_size],
                'tag': message[-tag_size-nonce_size:-nonce_size],
                'nonce': message[-nonce_size:]
            }

            print(colored("Attempting message decryption...", 'blue'))
            decrypted_data = ECCTools.decrypt_message(
                self.private_key,
                components['ephemeral_public_key'],
                components['encrypted_data'],
                components['tag'],
                components['nonce']
            )

            # Extract next hop information
            if len(decrypted_data) < 8:
                raise ValueError("Decrypted data too short")

            next_addr = decrypted_data[:8]
            next_message = decrypted_data[8:]

            host, port = unpackHostPort(next_addr)
            print(colored(f"Next hop: {host}:{port}", 'green'))

            return host, port, next_message

        except Exception as e:
            print(colored(f"Error processing initial message: {e}", 'red'))
            raise

    def handle_connection(self, clientsocket):
        """Handle incoming connection with improved encryption"""
        try:
            # Receive initial setup message
            message = recv_message_with_length_prefix(clientsocket)
            if not message:
                print(colored("Empty message received", 'red'))
                return

            # Process initial message
            try:
                next_host, next_port, next_message = self.handle_initial_message(message)
            except Exception as e:
                print(colored(f"Failed to process initial message: {e}", 'red'))
                return

            if not self.is_exit:
                # Relay node behavior
                try:
                    print(colored("Operating as relay node", 'blue'))
                    next_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    next_sock.connect((next_host, next_port))

                    if not send_message_with_length_prefix(next_sock, next_message):
                        raise Exception("Failed to forward message")

                    # Generate new encryption parameters
                    aes_key = Random.get_random_bytes(32)
                    nonce = Random.get_random_bytes(12)

                    self.handle_relay_communication(clientsocket, next_sock, aes_key, nonce)

                finally:
                    try:
                        next_sock.close()
                    except:
                        pass
            else:
                # Exit node behavior
                try:
                    print(colored("Operating as exit node", 'blue'))
                    dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    dest_sock.connect((next_host, next_port))

                    # Generate new encryption parameters
                    aes_key = Random.get_random_bytes(32)
                    nonce = Random.get_random_bytes(12)

                    self.handle_exit_communication(clientsocket, dest_sock, aes_key, nonce)

                finally:
                    try:
                        dest_sock.close()
                    except:
                        pass

        except Exception as e:
            print(colored(f"Connection handling error: {e}", 'red'))
            import traceback
            print(colored(traceback.format_exc(), 'red'))
        finally:
            try:
                clientsocket.close()
            except:
                pass

    def handle_exit_communication(self, prev_sock, dest_sock, aes_key, aes_nonce):
        """Handle exit node communication"""
        print(colored("[EXIT] Starting exit node communication", 'blue'))
        while True:
            try:
                print(colored("\n[EXIT] Waiting for message...", 'yellow'))
                message = recv_message_with_length_prefix(prev_sock)
                if not message:
                    print(colored("[EXIT] Empty message received", 'red'))
                    break

                print(colored(f"[EXIT] Received message length: {len(message)}", 'blue'))

                # Create AES cipher for decryption
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)

                # Split message into ciphertext and tag
                ciphertext = message[:-16]
                tag = message[-16:]

                print(colored("[EXIT] Attempting decryption...", 'yellow'))
                try:
                    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                    print(colored("[EXIT] Decryption successful", 'green'))

                    # Try to decode as UTF-8 for logging
                    try:
                        print(colored(f"[EXIT] Decrypted message: {decrypted.decode('utf-8')}", 'green'))
                    except:
                        print(colored("[EXIT] Binary data received", 'yellow'))
                except Exception as e:
                    print(colored(f"[EXIT] Decryption error: {e}", 'red'))
                    break

                # Forward to destination
                if not send_message_with_length_prefix(dest_sock, decrypted):
                    print(colored("[EXIT] Failed to forward message", 'red'))
                    break
                print(colored("[EXIT] Message forwarded successfully", 'green'))

                # Get response from destination
                response = recv_message_with_length_prefix(dest_sock)
                if not response:
                    print(colored("[EXIT] No response from destination", 'red'))
                    break

                # Create new AES cipher for response encryption
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
                encrypted_response, tag = cipher.encrypt_and_digest(response)

                # Combine encrypted response and tag
                final_response = encrypted_response + tag

                # Send encrypted response back
                if not send_message_with_length_prefix(prev_sock, final_response):
                    print(colored("[EXIT] Failed to send response", 'red'))
                    break
                print(colored("[EXIT] Response sent successfully", 'green'))

            except Exception as e:
                print(colored(f"[EXIT] Communication error: {e}", 'red'))
                break

    def run(self):
        """Run the node server"""
        try:
            # Generate keys
            self.generate_keys()
            
            # Register with Directory Authority
            self.register_with_da()
            
            # Create server socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.ip, self.port))
            server_socket.listen(5)
            
            node_type = "Exit" if self.is_exit else "Relay"
            print(colored(f"{node_type} Node listening on port {self.port}", 'green'))
            
            while True:
                clientsocket, address = server_socket.accept()
                thread = threading.Thread(
                    target=self.handle_connection,
                    args=(clientsocket,)
                )
                thread.daemon = True
                thread.start()
                
        except Exception as e:
            print(colored(f"Fatal error: {e}", 'red'))
            raise
        finally:
            try:
                server_socket.close()
            except:
                pass

def main(port=None, is_exit=False):
    try:
        node = TorNode(port=port, is_exit=is_exit)
        node.run()
    except KeyboardInterrupt:
        print(colored("\nShutting down node...", 'red'))
        sys.exit(0)
    except Exception as e:
        print(colored(f"Fatal error: {e}", 'red'))
        sys.exit(1)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    main()