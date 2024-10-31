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
   try:
       da_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       da_sock.connect((DA_IP, DA_PORT))

       # Send node type ('e' for exit node, 'n' for relay node)
       if is_exit:
           da_sock.send(b'e')
       else:
           da_sock.send(b'n')

       # Send address and public key
       addr = packHostPort(IP, port)
       pub_key_bytes = public_key.exportKey()
       da_sock.send(addr + pub_key_bytes)
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
   try:
       # Receive initial setup message
       message = recv_message_with_length_prefix(clientsocket)
       if not message:
           clientsocket.close()
           return

       # Decrypt the layer meant for this node
       cipher = PKCS1_OAEP.new(private_key)
       decrypted = cipher.decrypt(message)
       
       # Parse the decrypted message
       next_addr = decrypted[:8]
       aes_key = decrypted[8:40]
       next_message = decrypted[40:]
       
       if not is_exit:
           # Relay node: Forward to next node
           try:
               next_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
               next_ip, next_port = unpackHostPort(next_addr)
               next_sock.connect((next_ip, next_port))
               send_message_with_length_prefix(next_sock, next_message)
               
               # Handle ongoing communication
               handle_relay_communication(clientsocket, next_sock, aes_key)
           except Exception as e:
               print(colored(f"Relay error: {e}", 'red'))
           finally:
               next_sock.close()
       else:
           # Exit node: Connect to destination
           try:
               dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
               dest_ip, dest_port = unpackHostPort(next_addr)
               dest_sock.connect((dest_ip, dest_port))
               
               # Handle communication with destination
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
   while True:
       try:
           # Receive from previous node
           message = recv_message_with_length_prefix(prev_sock)
           if not message:
               break

           # Decrypt one layer
           aes = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
           decrypted = aes.decrypt(message)

           # Forward to next node
           send_message_with_length_prefix(next_sock, decrypted)

           # Receive response from next node
           response = recv_message_with_length_prefix(next_sock)
           if not response:
               break

           # Encrypt response
           aes = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
           encrypted = aes.encrypt(pad_message(response))

           # Send back to previous node
           send_message_with_length_prefix(prev_sock, encrypted)

       except Exception as e:
           print(colored(f"Relay communication error: {e}", 'red'))
           break

def handle_exit_communication(prev_sock, dest_sock, aes_key):
   while True:
       try:
           # Receive from previous node
           message = recv_message_with_length_prefix(prev_sock)
           if not message:
               break

           # Decrypt final layer
           aes = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
           decrypted = aes.decrypt(message)

           # Remove padding and send to destination
           send_message_with_length_prefix(dest_sock, decrypted.rstrip(b'\0'))

           # Receive response from destination
           response = recv_message_with_length_prefix(dest_sock)
           if not response:
               break

           # Encrypt response
           aes = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
           encrypted = aes.encrypt(pad_message(response))

           # Send back to previous node
           send_message_with_length_prefix(prev_sock, encrypted)

       except Exception as e:
           print(colored(f"Exit communication error: {e}", 'red'))
           break

if __name__ == "__main__":
   signal.signal(signal.SIGINT, signal_handler)
   main()