from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
import socket
import threading
import hashlib
import signal
from .socket_tool import *
from .packing_tool import *
from .padding_tool import *
from termcolor import colored

def main(port=None, is_exit=False):
    # Configuration
    if port is None:
        port = 7000  # default port
    IP = "127.0.0.1"
    DA_IP = "127.0.0.1"
    DA_PORT = 12345
    # Generate RSA key pair
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    public_key = key.publickey()
    # Create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, port))
    s.listen(5)

    # Register with Directory Authority
    # In node.py, modify the registration part
    try:
       da_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       da_sock.connect((DA_IP, DA_PORT))
       # Send node type
       if is_exit:
           da_sock.send(b'e')
       else:
           da_sock.send(b'n')
       # Send address
       addr = packHostPort(IP, port)
       da_sock.send(addr)
       #Send public key
       pub_key_bytes = public_key.export_key()
       send_message_with_length_prefix(da_sock, pub_key_bytes)
       da_sock.close()
    except Exception as e:
        print(colored(f"Node {port}: Failed to register with DA: {e}", 'red'))
        return

    node_type = "Exit" if is_exit else "Relay"
    print(colored(f"{node_type} Node listening on port {port}", 'green'))
    while True:
        try:
            (clientsocket, address) = s.accept()
            # Create new thread for each connection
            t = threading.Thread(target=handle_connection, 
                              args=(clientsocket, key, is_exit))
            t.daemon = True
            t.start()
        except Exception as e:
            print(colored(f"Node {port}: Connection error: {e}", 'red'))

def handle_connection(clientsocket, private_key, is_exit):
    """
    Handle incoming connection and message routing with proper padding
    """
    try:
        # Receive initial setup message
        message = recv_message_with_length_prefix(clientsocket)
        if not message:
            print(colored("Empty message received", 'red'))
            return

        # Split message into RSA-encrypted part and the rest
        rsa_length = private_key.size_in_bytes()
        if len(message) < rsa_length:
            print(colored("Message too short for RSA decryption", 'red'))
            return

        # Decrypt RSA portion to get AES key and nonce
        rsa_encrypted = message[:rsa_length]
        aes_encrypted = message[rsa_length:-16]  # Exclude the MAC tag
        tag = message[-16:]  # Get the MAC tag

        try:
            cipher = PKCS1_OAEP.new(private_key)
            aes_key_and_nonce = cipher.decrypt(rsa_encrypted)
            aes_key = aes_key_and_nonce[:32]  # AES key is 32 bytes
            nonce = aes_key_and_nonce[32:]  # Nonce is 16 bytes
        except Exception as e:
            print(colored(f"RSA decryption failed: {e}", 'red'))
            print(colored(f"RSA-encrypted data: {rsa_encrypted.hex()}", 'red'))
            return

        # Decrypt AES portion
        try:
            aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            decrypted = aes.decrypt_and_verify(aes_encrypted, tag)
        except Exception as e:
            print(colored(f"AES decryption failed: {e}", 'red'))
            print(colored(f"AES-encrypted data: {aes_encrypted.hex()}", 'red'))
            print(colored(f"MAC tag: {tag.hex()}", 'red'))
            return

        # Extract next hop information
        next_addr = decrypted[:8]
        next_message = decrypted[8:]

        if not is_exit:
            # Relay node
            try:
                next_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                next_ip, next_port = unpackHostPort(next_addr)
                print(f"Connecting to next hop: {next_ip}:{next_port}")
                next_sock.connect((next_ip, next_port))
                send_message_with_length_prefix(next_sock, next_message)

                handle_relay_communication(clientsocket, next_sock, aes_key, nonce)
            except Exception as e:
                print(colored(f"Relay error: {e}", 'red'))
            finally:
                next_sock.close()
        else:
            # Exit node
            try:
                dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dest_ip, dest_port = unpackHostPort(next_addr)
                print(f"Exit node connecting to destination: {dest_ip}:{dest_port}")
                dest_sock.connect((dest_ip, dest_port))

                handle_exit_communication(clientsocket, dest_sock, aes_key, nonce)
            except Exception as e:
                print(colored(f"Exit node error: {e}", 'red'))
            finally:
                dest_sock.close()

    except Exception as e:
        print(colored(f"Connection handling error: {e}", 'red'))
    finally:
        clientsocket.close()


def handle_relay_communication(prev_sock, next_sock, aes_key, nonce):
    """Handle relay communication with encryption debugging"""
    # Print initial encryption parameters
    key_hash = hashlib.sha256(aes_key).hexdigest()[:8]
    nonce_hash = hashlib.sha256(nonce).hexdigest()[:8]
    print(colored(f"[RELAY] Using Key: {key_hash}, Nonce: {nonce_hash}", 'blue'))

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
                aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                
                # Split message
                ciphertext = message[:-16]
                tag = message[-16:]
                
                print(colored(f"[RELAY] Attempting decryption...", 'yellow'))
                print(colored(f"[RELAY] Ciphertext length: {len(ciphertext)}", 'blue'))
                print(colored(f"[RELAY] Tag length: {len(tag)}", 'blue'))
                print(colored(f"[RELAY] Using Key: {key_hash}, Nonce: {nonce_hash}", 'blue'))
                
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

            # Receive response from next node
            response = recv_message_with_length_prefix(next_sock)
            if not response:
                print(colored("[RELAY] No response from next node", 'red'))
                break

            # Encrypt response
            try:
                # Create new AES object for response
                aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                
                # Encrypt and get tag
                encrypted_response, tag = aes.encrypt_and_digest(response)
                
                # Combine encrypted response and tag
                final_response = encrypted_response + tag
                
                # Send back to previous node
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

def handle_exit_communication(prev_sock, dest_sock, aes_key, nonce):
    """Handle exit node communication with detailed logging"""
    while True:
        try:
            # Receive encrypted message from previous node
            print(colored("\n[EXIT] Waiting for message from previous node...", 'yellow'))
            encrypted_message = recv_message_with_length_prefix(prev_sock)
            if not encrypted_message:
                print(colored("[EXIT] Empty message received", 'red'))
                break

            print(colored(f"[EXIT] Received message length: {len(encrypted_message)}", 'blue'))
            print(colored(f"[EXIT] Message hex: {encrypted_message.hex()[:64]}...", 'blue'))

            # Decrypt the final layer
            try:
                aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
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

            except Exception as e:
                print(colored(f"[EXIT] Decryption error: {e}", 'red'))
                print(colored(f"[EXIT] Key length: {len(aes_key)}", 'red'))
                print(colored(f"[EXIT] Nonce length: {len(nonce)}", 'red'))
                continue

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
            try:
                aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                encrypted_response, tag = aes.encrypt_and_digest(response)
                final_response = encrypted_response + tag
                print(colored("[EXIT] Successfully encrypted response", 'green'))

            except Exception as e:
                print(colored(f"[EXIT] Encryption error: {e}", 'red'))
                continue

            # Send back through Tor network
            if not send_message_with_length_prefix(prev_sock, final_response):
                print(colored("[EXIT] Failed to send response", 'red'))
                break
            print(colored("[EXIT] Sent response to previous node", 'green'))

        except Exception as e:
            print(colored(f"[EXIT] Communication error: {e}", 'red'))
            break
        
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()