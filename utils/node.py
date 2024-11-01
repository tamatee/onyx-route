from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
import socket
import threading
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

        # Decrypt RSA portion to get AES key
        rsa_encrypted = message[:rsa_length]
        aes_encrypted = message[rsa_length:]
        
        cipher = PKCS1_OAEP.new(private_key)
        try:
            aes_key = cipher.decrypt(rsa_encrypted)
        except Exception as e:
            print(colored(f"RSA decryption failed: {e}", 'red'))
            return

        # Ensure AES encrypted data is properly padded
        if len(aes_encrypted) % 16 != 0:
            print(colored("AES data not properly padded", 'red'))
            return

        # Decrypt AES portion
        try:
            aes = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
            decrypted = aes.decrypt(aes_encrypted)
            decrypted = unpad_message(decrypted)  # Remove padding after decryption
        except Exception as e:
            print(colored(f"AES decryption failed: {e}", 'red'))
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

                handle_relay_communication(clientsocket, next_sock, aes_key)
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

                handle_exit_communication(clientsocket, dest_sock, aes_key)
            except Exception as e:
                print(colored(f"Exit node error: {e}", 'red'))
            finally:
                dest_sock.close()

    except Exception as e:
        print(colored(f"Connection handling error: {e}", 'red'))
    finally:
        clientsocket.close()


def handle_relay_communication(prev_sock, next_sock, aes_key):
    """Handle ongoing communication for relay nodes with proper padding"""
    while True:
        try:
            # Receive from previous node
            message = recv_message_with_length_prefix(prev_sock)
            if not message:
                break

            # Decrypt one layer
            aes = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
            decrypted = aes.decrypt(message)
            decrypted = unpad_message(decrypted)  # Remove padding

            # Forward to next node
            send_message_with_length_prefix(next_sock, decrypted)

            # Receive response
            response = recv_message_with_length_prefix(next_sock)
            if not response:
                break

            # Encrypt and pad response
            padded_response = pad_message(response)
            aes = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
            encrypted = aes.encrypt(padded_response)

            send_message_with_length_prefix(prev_sock, encrypted)

        except Exception as e:
            print(colored(f"Relay communication error: {e}", 'red'))
            break

def handle_exit_communication(prev_sock, dest_sock, aes_key):
    """Handle ongoing communication for exit nodes with proper padding"""
    while True:
        try:
            # Receive from previous node
            message = recv_message_with_length_prefix(prev_sock)
            if not message:
                break

            # Decrypt final layer
            aes = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
            decrypted = aes.decrypt(message)
            decrypted = unpad_message(decrypted)  # Remove padding

            # Send to destination
            send_message_with_length_prefix(dest_sock, decrypted)

            # Receive response
            response = recv_message_with_length_prefix(dest_sock)
            if not response:
                break

            # Encrypt and pad response
            padded_response = pad_message(response)
            aes = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
            encrypted = aes.encrypt(padded_response)

            send_message_with_length_prefix(prev_sock, encrypted)

        except Exception as e:
            print(colored(f"Exit communication error: {e}", 'red'))
            break

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()