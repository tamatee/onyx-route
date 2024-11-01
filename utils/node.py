from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto import Random
import socket
import threading
import hashlib
import time
import signal
from .socket_tool import *
from .packing_tool import *
from .padding_tool import *
from termcolor import colored


# node.py
def main(port=None, is_exit=False):
    # Configuration
    if port is None:
        port = 7000  # default port
    IP = "127.0.0.1"
    DA_IP = "127.0.0.1"
    DA_PORT = 12345
    
    try:
        # Generate ECC key pair
        key = ECC.generate(curve='P-384')
        public_key = key.public_key()
        
        # Export public key in correct format
        pub_key_bytes = public_key.export_key(format='PEM')
        if isinstance(pub_key_bytes, str):
            pub_key_bytes = pub_key_bytes.encode('utf-8')
        
        print(colored(f"Debug - Generated key for node {port}:", 'blue'))
        print(colored(f"Public key length: {len(pub_key_bytes)}", 'blue'))
        print(colored(f"Public key: {pub_key_bytes[:64]}...", 'blue'))
        
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((IP, port))
        s.listen(5)

        # Register with Directory Authority
        try:
            print(colored(f"Attempting to register with DA ({DA_IP}:{DA_PORT})", 'yellow'))
            da_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            da_sock.connect((DA_IP, DA_PORT))
            
            # Send node type
            node_type = b'e' if is_exit else b'n'
            da_sock.send(node_type)
            print(colored(f"Sent node type: {node_type}", 'blue'))
            
            # Send address
            addr = packHostPort(IP, port)
            if isinstance(addr, str):
                addr = addr.encode('utf-8')
            da_sock.send(addr)
            print(colored(f"Sent address (length: {len(addr)})", 'blue'))
            
            # Send public key with length prefix
            print(colored(f"Sending public key (length: {len(pub_key_bytes)})", 'blue'))
            if not send_message_with_length_prefix(da_sock, pub_key_bytes):
                raise Exception("Failed to send public key")
            
            # Wait briefly to ensure registration is complete
            time.sleep(0.1)
            da_sock.close()
            print(colored(f"Successfully registered with DA", 'green'))
            
        except Exception as e:
            print(colored(f"Node {port}: Failed to register with DA: {e}", 'red'))
            return

        node_type = "Exit" if is_exit else "Relay"
        print(colored(f"{node_type} Node listening on port {port}", 'green'))
        
        while True:
            try:
                (clientsocket, address) = s.accept()
                t = threading.Thread(target=handle_connection, 
                                  args=(clientsocket, key, is_exit))
                t.daemon = True
                t.start()
            except Exception as e:
                print(colored(f"Node {port}: Connection error: {e}", 'red'))

    except Exception as e:
        print(colored(f"Node {port}: Fatal error: {e}", 'red'))
        return

def handle_connection(clientsocket, private_key, is_exit):
    """
    Handle incoming connection and message routing using ECC
    """
    try:
        print(colored("\nReceiving initial setup message...", 'yellow'))
        # Receive initial setup message
        message = recv_message_with_length_prefix(clientsocket)
        if not message:
            print(colored("Empty message received", 'red'))
            return

        try:
            # Extract sender's public key and encrypted data
            pub_key_end = message.find(b'-----END PUBLIC KEY-----') + len(b'-----END PUBLIC KEY-----')
            if pub_key_end == -1:
                print(colored("Invalid message format: No public key found", 'red'))
                return
                
            sender_public_key = ECC.import_key(message[:pub_key_end])
            remaining_data = message[pub_key_end:]

            print(colored("\nPerforming ECDH key derivation...", 'blue'))
            # Perform ECDH to derive shared key
            shared_point = private_key.d * sender_public_key.pointQ
            shared_key = shared_point.x.to_bytes()[:32]  # Use first 32 bytes for AES key
            
            # Print key information for debugging
            key_hash = hashlib.sha256(shared_key).hexdigest()[:8]
            print(colored(f"Derived shared key hash: {key_hash}", 'blue'))

            # Extract components
            if len(remaining_data) < 32:  # Minimum length check
                print(colored("Invalid message: insufficient data length", 'red'))
                return

            nonce = remaining_data[:16]
            tag = remaining_data[-16:]
            ciphertext = remaining_data[16:-16]

            print(colored("\nDecrypting message...", 'blue'))
            print(colored(f"Nonce length: {len(nonce)}", 'blue'))
            print(colored(f"Ciphertext length: {len(ciphertext)}", 'blue'))
            print(colored(f"Tag length: {len(tag)}", 'blue'))

            try:
                # Create AES-GCM cipher
                aes = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
                
                # Decrypt and verify
                decrypted = aes.decrypt_and_verify(ciphertext, tag)
                print(colored("Successfully decrypted message", 'green'))

                # Extract next hop information
                next_addr = decrypted[:8]
                next_message = decrypted[8:]

                if not is_exit:
                    # Relay node
                    print(colored("\nOperating as relay node", 'blue'))
                    try:
                        next_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        next_ip, next_port = unpackHostPort(next_addr)
                        print(colored(f"Connecting to next hop: {next_ip}:{next_port}", 'blue'))
                        next_sock.connect((next_ip, next_port))
                        
                        # Forward the message
                        if not send_message_with_length_prefix(next_sock, next_message):
                            raise Exception("Failed to forward message to next hop")
                        print(colored("Successfully forwarded message", 'green'))

                        # Handle ongoing communication
                        handle_relay_communication(clientsocket, next_sock, shared_key)
                    except Exception as e:
                        print(colored(f"Relay error: {e}", 'red'))
                    finally:
                        next_sock.close()
                else:
                    # Exit node
                    print(colored("\nOperating as exit node", 'blue'))
                    try:
                        dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        dest_ip, dest_port = unpackHostPort(next_addr)
                        print(colored(f"Connecting to destination: {dest_ip}:{dest_port}", 'blue'))
                        dest_sock.connect((dest_ip, dest_port))

                        # Handle destination communication
                        handle_exit_communication(clientsocket, dest_sock, shared_key)
                    except Exception as e:
                        print(colored(f"Exit node error: {e}", 'red'))
                    finally:
                        dest_sock.close()

            except ValueError as e:
                print(colored(f"Decryption error: {e}", 'red'))
                print(colored(f"Ciphertext (hex): {ciphertext.hex()}", 'red'))
                print(colored(f"Tag (hex): {tag.hex()}", 'red'))
                return

        except Exception as e:
            print(colored(f"Message processing error: {e}", 'red'))
            return

    except Exception as e:
        print(colored(f"Connection handling error: {e}", 'red'))
    finally:
        clientsocket.close()

def handle_relay_communication(prev_sock, next_sock, shared_key, nonce):
    """Handle relay communication with encryption debugging"""
    # Print initial encryption parameters
    key_hash = hashlib.sha256(shared_key).hexdigest()[:8]
    nonce_hash = hashlib.sha256(nonce).hexdigest()[:8]
    print(colored(f"[RELAY] Using Key Hash: {key_hash}, Nonce Hash: {nonce_hash}", 'blue'))

    while True:
        try:
            print(colored("\n[RELAY] Waiting for message...", 'yellow'))
            message = recv_message_with_length_prefix(prev_sock)
            if not message:
                print(colored("[RELAY] Empty message received", 'red'))
                break

            print(colored(f"[RELAY] Received message length: {len(message)}", 'blue'))
            print(colored(f"[RELAY] First 16 bytes: {message[:16].hex()}", 'blue'))

            try:
                # Create AES object
                aes = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
                
                # Split message
                ciphertext = message[:-16]
                tag = message[-16:]
                
                print(colored(f"[RELAY] Attempting decryption...", 'yellow'))
                print(colored(f"[RELAY] Ciphertext length: {len(ciphertext)}", 'blue'))
                print(colored(f"[RELAY] Tag length: {len(tag)}", 'blue'))
                print(colored(f"[RELAY] Using Key Hash: {key_hash}, Nonce Hash: {nonce_hash}", 'blue'))
                
                decrypted = aes.decrypt_and_verify(ciphertext, tag)
                print(colored("[RELAY] Decryption successful", 'green'))
                print(colored(f"[RELAY] Decrypted length: {len(decrypted)}", 'blue'))
                
                if not send_message_with_length_prefix(next_sock, decrypted):
                    print(colored("[RELAY] Failed to forward message", 'red'))
                    break
                
                print(colored("[RELAY] Message forwarded", 'green'))

            except Exception as e:
                print(colored(f"[RELAY] Decryption error: {e}", 'red'))
                print(colored(f"[RELAY] Failed message: {message.hex()}", 'red'))
                break

            # Handle response
            response = recv_message_with_length_prefix(next_sock)
            if not response:
                print(colored("[RELAY] No response from next node", 'red'))
                break

            try:
                # Encrypt response
                aes = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
                encrypted_response, tag = aes.encrypt_and_digest(response)
                final_response = encrypted_response + tag
                
                if not send_message_with_length_prefix(prev_sock, final_response):
                    print(colored("[RELAY] Failed to send response", 'red'))
                    break
                print(colored("[RELAY] Sent response to previous node", 'green'))

            except Exception as e:
                print(colored(f"[RELAY] Encryption error: {e}", 'red'))
                break

        except Exception as e:
            print(colored(f"[RELAY] Communication error: {e}", 'red'))
            break

def handle_exit_communication(prev_sock, dest_sock, shared_key, nonce):
    """Handle exit node communication with detailed logging"""
    while True:
        try:
            print(colored("\n[EXIT] Waiting for message from previous node...", 'yellow'))
            encrypted_message = recv_message_with_length_prefix(prev_sock)
            if not encrypted_message:
                print(colored("[EXIT] Empty message received", 'red'))
                break

            print(colored(f"[EXIT] Received message length: {len(encrypted_message)}", 'blue'))
            print(colored(f"[EXIT] Message hex: {encrypted_message.hex()[:64]}...", 'blue'))

            try:
                aes = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
                ciphertext = encrypted_message[:-16]
                tag = encrypted_message[-16:]
                print(colored(f"[EXIT] Ciphertext length: {len(ciphertext)}", 'blue'))
                print(colored(f"[EXIT] Tag length: {len(tag)}", 'blue'))

                final_message = aes.decrypt_and_verify(ciphertext, tag)
                print(colored("[EXIT] Successfully decrypted message", 'green'))
                print(colored(f"[EXIT] Decrypted length: {len(final_message)}", 'blue'))

                try:
                    print(colored(f"[EXIT] Decrypted content: {final_message.decode('utf-8')}", 'green'))
                except:
                    print(colored("[EXIT] Message is binary data", 'yellow'))

                # Forward to destination
                print(colored("[EXIT] Forwarding to destination...", 'yellow'))
                if not send_message_with_length_prefix(dest_sock, final_message):
                    print(colored("[EXIT] Failed to forward to destination", 'red'))
                    break
                print(colored("[EXIT] Message forwarded to destination", 'green'))

                # Get response from destination
                print(colored("[EXIT] Waiting for destination response...", 'yellow'))
                response = recv_message_with_length_prefix(dest_sock)
                if not response:
                    print(colored("[EXIT] No response from destination", 'red'))
                    break
                print(colored("[EXIT] Received response from destination", 'green'))

                # Encrypt response
                aes = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
                encrypted_response, tag = aes.encrypt_and_digest(response)
                final_response = encrypted_response + tag
                print(colored("[EXIT] Successfully encrypted response", 'green'))

                # Send back through Tor network
                if not send_message_with_length_prefix(prev_sock, final_response):
                    print(colored("[EXIT] Failed to send response", 'red'))
                    break
                print(colored("[EXIT] Sent response to previous node", 'green'))

            except Exception as e:
                print(colored(f"[EXIT] Processing error: {e}", 'red'))
                continue

        except Exception as e:
            print(colored(f"[EXIT] Communication error: {e}", 'red'))
            break
        
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()