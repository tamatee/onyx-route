from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto import Random
import hashlib
from .socket_tool import *
from .padding_tool import *
from .packing_tool import *
from .ecc_encryption_tool import *
from .timing_tool import *
import socket
import sys
from termcolor import colored

def main():
    # Constants
    DA_IP = '127.0.0.1'
    DA_PORT = 12345
    DEST_HOST = '127.0.0.1'
    DEST_PORT = 54321

    try:
        # Read Directory Authority's ECC public key
        with open('keys/ecc_public.pem', 'rb') as da_file:  # Changed to 'rb' mode
            da_pub_key = ECC.import_key(da_file.read())

        # Connect to Directory Authority
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((DA_IP, DA_PORT))
        s.send(b'r')  # Request route

        # Create ephemeral ECC key pair for DA communication
        client_priv_key, client_pub_key = ECCTools.generate_keypair()

        # Generate AES key and nonce
        randfile = Random.new()
        aes_key = randfile.read(32)
        route_nonce = randfile.read(16)
        aes_key_and_nonce = aes_key + route_nonce

        # Get shared key using ECDH
        shared_point = client_priv_key.d * da_pub_key.pointQ
        shared_key = shared_point.x.to_bytes()[:32]

        # Create and send wrapped message
        client_pub_bytes = client_pub_key.export_key(format='PEM')
        if isinstance(client_pub_bytes, str):
            client_pub_bytes = client_pub_bytes.encode('utf-8')

        # Create AES-GCM cipher
        nonce = Random.get_random_bytes(16)
        aes = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)

        # Encrypt AES key and nonce
        ciphertext, tag = aes.encrypt_and_digest(aes_key_and_nonce)

        # Combine message components (all bytes)
        wrapped_message = client_pub_bytes + nonce + ciphertext + tag

        print("Debug info:")
        print(f"Public key length: {len(client_pub_bytes)}")
        print(f"Nonce length: {len(nonce)}")
        print(f"Ciphertext length: {len(ciphertext)}")
        print(f"Tag length: {len(tag)}")
        print(f"Total message length: {len(wrapped_message)}")

        if not send_message_with_length_prefix(s, wrapped_message):
            s.close()
            print(colored("Directory authority connection failed", 'red'))
            return

        # Receive and decrypt route data
        data = recv_message_with_length_prefix(s)
        if data == b"":
            s.close()
            print(colored("Directory authority connection failed", 'red'))
            return

        # Decrypt route data
        aes_obj = AES.new(aes_key, AES.MODE_GCM, nonce=route_nonce)
        try:
            hop_data = aes_obj.decrypt_and_verify(data[:-16], data[-16:])
            print("Successfully decrypted route data")
        except ValueError as e:
            print(colored(f"Route data decryption failed: {e}", 'red'))
            s.close()
            return

        hoplist = process_route(hop_data)
        hoplist = list(reversed(hoplist))
        s.close()

        # Start connection through the Tor network
        run_client_connection(hoplist, packHostPort(DEST_HOST, DEST_PORT))

    except FileNotFoundError:
        print(colored("Error: Directory authority public key file not found", 'red'))
    except Exception as e:
        print(colored(f"Error occurred: {str(e)}", 'red'))
        import traceback
        traceback.print_exc()

def wrap_all_messages(hoplist, destination):
    """Wrap message for all hops using ECC"""
    # Ensure destination is bytes
    if isinstance(destination, str):
        destination = destination.encode('utf-8')
    wrapped_message = destination
    
    shared_keys = []
    ephemeral_keys = []
    
    try:
        for i in range(len(hoplist)):
            # Generate ephemeral ECC keypair for this hop
            ephemeral_private = ECC.generate(curve='P-384')
            ephemeral_keys.append(ephemeral_private)
            
            # Generate shared key using ECDH
            shared_key = derive_shared_key(ephemeral_private, hoplist[i][2])
            shared_keys.append(shared_key)
            
            # Add previous hop address if not first hop
            if i != 0:
                prev_hop = hoplist[i - 1]
                packed_route = packHostPort(prev_hop[0], prev_hop[1])
                wrapped_message = packed_route + wrapped_message
            
            # Export public key as bytes
            pub_key_bytes = ephemeral_private.public_key().export_key(format='PEM')
            if isinstance(pub_key_bytes, str):
                pub_key_bytes = pub_key_bytes.encode('utf-8')
                
            # Generate nonce and encrypt
            nonce = Random.get_random_bytes(16)
            cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(wrapped_message)
            
            # Combine components
            wrapped_message = pub_key_bytes + nonce + ciphertext + tag
            
        return wrapped_message, shared_keys, ephemeral_keys
    except Exception as e:
        print(colored(f"Error in wrap_all_messages: {str(e)}", 'red'))
        raise

def run_client_connection(hoplist, destination):
    """
    Run client connection with ECC encryption
    """
    timer = ProcessTimer()
    try:
        # Start timer
        timer.start_process("Initial Connection")

        # Connect to first node
        next_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        next_host = (hoplist[len(hoplist) - 1][0], hoplist[len(hoplist) - 1][1])
        next_s.connect(next_host)

        # Create and send initial setup message using ECC
        timer.mark_timestamp("Creating initial setup message")
        wrapped_message, shared_keys, ephemeral_keys = wrap_all_messages(hoplist, destination)

        if not send_message_with_length_prefix(next_s, wrapped_message):
            print(colored("Failed to establish initial connection", 'red'))
            return

        timer.end_process("Initial Connection")
        print(colored("\nConnection established through Tor network!", 'green'))
        print(colored("Type 'QUIT' to exit", 'yellow'))

        while True:
            try:
                print(colored("\nCLIENT: Type message to send:", 'yellow'))
                message = input()

                if message.upper() == 'QUIT':
                    print(colored("Closing connection...", 'red'))
                    break

                # Time message processing
                timer.start_process("Message Processing")

                # Debug info - show encryption parameters
                print(colored("\nDEBUG: Encryption parameters (in network order):", 'blue'))
                for i in range(len(hoplist)):
                    key_hash = hashlib.sha256(shared_keys[i]).hexdigest()[:8]
                    print(colored(f"Hop {i}: Shared Key Hash: {key_hash}", 'blue'))

                # Encryption timing
                timer.start_process("Encryption")
                # Prepare message
                message_bytes = message.encode('utf-8')
                current_message = message_bytes

                # Add encryption layers in correct order
                for i in range(len(hoplist)):
                    shared_key = shared_keys[i]
                    nonce = Random.get_random_bytes(16)
                    aes = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
                    current_message, tag = aes.encrypt_and_digest(current_message)
                    current_message = nonce + current_message + tag

                    key_hash = hashlib.sha256(shared_key).hexdigest()[:8]
                    print(colored(f"Layer {i} encrypted with Key Hash: {key_hash}", 'blue'))
                    print(colored(f"Message length after layer {i}: {len(current_message)}", 'blue'))

                timer.end_process("Encryption")

                # Send timing
                timer.start_process("Message Transmission")
                if not send_message_with_length_prefix(next_s, current_message):
                    print(colored("Failed to send message", 'red'))
                    break
                print(colored("DEBUG: Message sent successfully", 'green'))
                timer.end_process("Message Transmission")

                # Receive and decrypt response
                timer.start_process("Decryption")
                response = recv_message_with_length_prefix(next_s)
                if not response:
                    print(colored("No response received", 'red'))
                    break

                # Decrypt response layers
                try:
                    current_response = response
                    for i in range(len(hoplist) - 1, -1, -1):
                        shared_key = shared_keys[i]
                        nonce = current_response[:16]
                        tag = current_response[-16:]
                        ciphertext = current_response[16:-16]

                        aes = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
                        current_response = aes.decrypt_and_verify(ciphertext, tag)

                        key_hash = hashlib.sha256(shared_key).hexdigest()[:8]
                        print(colored(f"Decrypted layer {i} with Key Hash: {key_hash}", 'blue'))

                    timer.end_process("Decryption")
                    timer.end_process("Message Processing")

                    # Print timing summary and response
                    print(timer.get_summary())
                    timer.reset()
                    print(colored("\nCLIENT: Response from server:", 'green'))
                    print(colored(current_response.decode('utf-8'), 'blue'))

                except Exception as e:
                    print(colored(f"\nDecryption error: {e}", 'red'))
                    timer.mark_timestamp(f"Decryption error: {e}")

            except socket.error as e:
                print(colored("\nConnection lost!", 'red'))
                timer.mark_timestamp(f"Error: {e}")
                break
            except Exception as e:
                print(colored(f"\nError: {e}", 'red'))
                timer.mark_timestamp(f"Error: {e}")
                break

    except socket.error as e:
        print(colored(f"Connection error: {e}", 'red'))
    except Exception as e:
        print(colored(f"Error: {e}", 'red'))
    finally:
        try:
            next_s.close()
        except:
            pass

def prepare_message(message, shared_keys):
    """Prepare message with proper encryption layers"""
    if isinstance(message, str):
        message_bytes = message.encode('utf-8')
    else:
        message_bytes = message

    current_message = message_bytes
    for i, key in enumerate(reversed(shared_keys)):
        # Generate fresh nonce for each layer
        nonce = Random.get_random_bytes(16)

        # Create AES-GCM cipher
        aes = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # Encrypt
        ciphertext, tag = aes.encrypt_and_digest(current_message)

        # Combine components
        current_message = nonce + ciphertext + tag

        # Debug info
        print(colored(f"Layer {i} encryption:", 'blue'))
        print(colored(f"Nonce: {nonce.hex()[:16]}", 'blue'))
        print(colored(f"Message length: {len(current_message)}", 'blue'))

    return current_message

# Update the client's message sending code to use this function
def send_message_through_circuit(message, next_s, shared_keys):
    """Send message through the circuit with proper encryption"""
    try:
        encrypted_message = prepare_message(message, shared_keys)
        if not send_message_with_length_prefix(next_s, encrypted_message):
            return False
        return True
    except Exception as e:
        print(colored(f"Error sending message: {e}", 'red'))
        return False

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\nClosing client...", 'red'))
        sys.exit(0)