from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
import hashlib
from .socket_tool import *
from .padding_tool import *
from .packing_tool import *
from .encryption_tool import *
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
        # Read Directory Authority's public key
        with open('keys/public.pem', 'r') as da_file:
            da_pub_key = RSA.import_key(da_file.read())  

        # Connect to Directory Authority
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((DA_IP, DA_PORT))
        s.send(b'r')  # Request route

        # Create and send AES key and nonce
        randfile = Random.new()
        aes_key = randfile.read(32)
        nonce = randfile.read(16)  # Generate a nonce
        aes_key_and_nonce = aes_key + nonce  # Concatenate AES key and nonce
        cipher = PKCS1_OAEP.new(da_pub_key)
        aes_msg = cipher.encrypt(aes_key_and_nonce)  # Encrypt the concatenated AES key and nonce

        if not send_message_with_length_prefix(s, aes_msg):
            s.close()
            print(colored("Directory authority connection failed", 'red'))
            return 

        # Receive route data
        data = recv_message_with_length_prefix(s)
        if data == b"":
            s.close()
            print(colored("Directory authority connection failed", 'red'))
            return

        # Decrypt route data
        aes_obj = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        hop_data = aes_obj.decrypt_and_verify(data[:-16], data[-16:])
        hoplist = process_route(hop_data)
        hoplist = list(reversed(hoplist))

        # Start connection through the Tor network
        run_client_connection(hoplist, packHostPort(DEST_HOST, DEST_PORT))

    except FileNotFoundError:
        print(colored("Error: Directory authority public key file not found", 'red'))
    except Exception as e:
        print(colored(f"Error occurred: {e}", 'red'))

def run_client_connection(hoplist, destination):
    """
    Run client connection with correct encryption order
    """
    try:
        # Connect to first node
        next_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        next_host = (hoplist[len(hoplist) - 1][0], hoplist[len(hoplist) - 1][1])
        next_s.connect(next_host)

        # Create and send initial setup message
        wrapped_message, aes_key_list, nonce_list = wrap_all_messages(hoplist, destination)
        if not send_message_with_length_prefix(next_s, wrapped_message):
            print(colored("Failed to establish initial connection", 'red'))
            return

        print(colored("\nConnection established through Tor network!", 'green'))
        print(colored("Type 'QUIT' to exit", 'yellow'))

        while True:
            try:
                print(colored("\nCLIENT: Type message to send:", 'yellow'))
                message = input()
                
                if message.upper() == 'QUIT':
                    print(colored("Closing connection...", 'red'))
                    break

                # Debug info - show encryption parameters in network order
                print(colored("\nDEBUG: Encryption parameters (in network order):", 'blue'))
                for i in range(len(hoplist)):
                    key_hash = hashlib.sha256(aes_key_list[i]).hexdigest()[:8]
                    nonce_hash = hashlib.sha256(nonce_list[i]).hexdigest()[:8]
                    print(colored(f"Hop {i}: Key: {key_hash}, Nonce: {nonce_hash}", 'blue'))

                # Prepare message
                message_bytes = message.encode('utf-8')
                current_message = message_bytes

                # Add encryption layers in correct order (first hop = outer layer)
                for i in range(len(hoplist)):
                    key = aes_key_list[i]
                    nonce = nonce_list[i]
                    aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    current_message, tag = aes.encrypt_and_digest(current_message)
                    current_message += tag
                    
                    key_hash = hashlib.sha256(key).hexdigest()[:8]
                    nonce_hash = hashlib.sha256(nonce).hexdigest()[:8]
                    print(colored(f"Layer {i} encrypted with Key: {key_hash}, Nonce: {nonce_hash}", 'blue'))
                    print(colored(f"Message length after layer {i}: {len(current_message)}", 'blue'))

                if not send_message_with_length_prefix(next_s, current_message):
                    print(colored("Failed to send message", 'red'))
                    break
                print(colored("DEBUG: Message sent successfully", 'green'))

                # Receive response
                response = recv_message_with_length_prefix(next_s)
                if not response:
                    print(colored("No response received", 'red'))
                    break

                # Decrypt response layers in reverse order
                try:
                    current_response = response
                    for i in range(len(hoplist) - 1, -1, -1):
                        key = aes_key_list[i]
                        nonce = nonce_list[i]
                        aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
                        
                        ciphertext = current_response[:-16]
                        tag = current_response[-16:]
                        
                        current_response = aes.decrypt_and_verify(ciphertext, tag)
                        
                        key_hash = hashlib.sha256(key).hexdigest()[:8]
                        print(colored(f"Decrypted layer {i} with Key: {key_hash}", 'blue'))

                    # Display the final decrypted response
                    print(colored("\nCLIENT: Response from server:", 'green'))
                    print(colored(current_response.decode('utf-8'), 'blue'))

                except Exception as e:
                    print(colored(f"\nDecryption error: {e}", 'red'))

            except socket.error as e:
                print(colored("\nConnection lost!", 'red'))
                break
            except Exception as e:
                print(colored(f"\nError: {e}", 'red'))
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

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\nClosing client...", 'red'))
        sys.exit(0)