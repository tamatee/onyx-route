from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
import socket
import random
import sys
from termcolor import colored
from .socket_tool import *
from .padding_tool import *
from .packing_tool import *

def main():
   # กำหนดค่าคงที่
   RSA_KEY_SIZE = 212
   NUM_NODES = 3
   DA_IP = "127.0.0.1"
   DA_PORT = 12345

   relay_nodes = {}  # เก็บ relay nodes
   exit_nodes = {}   # เก็บ exit nodes

   randfile = Random.new()

   # อ่าน private key
   try:
       with open('C:\\Users\\FackG\\Desktop\\practical_source\\practical_project\\keys\\private.pem', 'r') as da_file:
           da_private = da_file.read()
       da_mykey = RSA.importKey(da_private)
   except FileNotFoundError:
       print(colored("Error: Private key file not found", 'red'))
       return
   except Exception as e:
       print(colored(f"Error loading private key: {e}", 'red'))
       return

   # สร้าง socket และ bind
   try:
       s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       s.bind((DA_IP, DA_PORT))
       s.listen(5)
       print(colored(f"Directory Authority listening on {DA_IP}:{DA_PORT}", 'green'))
   except Exception as e:
       print(colored(f"Socket error: {e}", 'red'))
       return

   while True:
       try:
           clientsocket, addr = s.accept()

           # รับประเภทคำขอ
           request_type = clientsocket.recv(1).decode('utf-8')
           if not request_type:
               clientsocket.close()
               continue

           if request_type == 'n':  # relay node
               msg = recvn(clientsocket, RSA_KEY_SIZE+8)
               if not msg:
                   clientsocket.close()
                   continue
               node_addr = msg[:8]
               key = msg[8:]
               relay_nodes[node_addr] = key
               port = unpackHostPort(node_addr)[1]
               print(colored(f"Registered relay node on port {port}", 'green'))

           elif request_type == 'e':  # exit node
               msg = recvn(clientsocket, RSA_KEY_SIZE+8)
               if not msg:
                   clientsocket.close()
                   continue
               node_addr = msg[:8]
               key = msg[8:]
               exit_nodes[node_addr] = key
               port = unpackHostPort(node_addr)[1]
               print(colored(f"Registered exit node on port {port}", 'green'))

           elif request_type == 'r':  # route request
               try:
                   # รับ encrypted aes key จาก client
                   aes_enc = recv_message_with_length_prefix(clientsocket)
                   if not aes_enc:
                       clientsocket.close()
                       continue

                   # ถอดรหัส AES key
                   cipher = PKCS1_OAEP.new(da_mykey)
                   aes_key = cipher.decrypt(aes_enc)

                   # ตรวจสอบว่ามี nodes เพียงพอ
                   if len(relay_nodes) < NUM_NODES-1 or len(exit_nodes) < 1:
                       print(colored("Error: Not enough nodes available", 'red'))
                       clientsocket.close()
                       continue

                   # สุ่มเลือก nodes
                   relay_list = random.sample(list(relay_nodes.items()), NUM_NODES-1)
                   exit = random.sample(list(exit_nodes.items()), 1)

                   # สร้างเส้นทาง
                   route_message = construct_route(relay_list, exit)

                   # เข้ารหัสและส่งเส้นทาง
                   aes_obj = AES.new(aes_key, AES.MODE_CBC, b"0"*16)
                   blob = aes_obj.encrypt(pad_message(route_message))
                   send_message_with_length_prefix(clientsocket, blob)

                   print(colored("Sent route to client", 'green'))

               except Exception as e:
                   print(colored(f"Error processing route request: {e}", 'red'))

           else:
               print(colored(f"Unknown request type: {request_type}", 'yellow'))

       except Exception as e:
           print(colored(f"Error handling client: {e}", 'red'))
       finally:
           try:
               clientsocket.close()
           except:
               pass

def construct_route(relays, exit):
   """สร้างข้อความเส้นทางจาก relay nodes และ exit node"""
   message = b""
   # เพิ่ม relay nodes
   for addr, key in relays:
       message += addr + key
   # เพิ่ม exit node
   message += exit[0][0] + exit[0][1]
   return message

if __name__ == "__main__":
   try:
       main()
   except KeyboardInterrupt:
       print(colored("\nShutting down Directory Authority...", 'red'))
       sys.exit(0)
   except Exception as e:
       print(colored(f"Fatal error: {e}", 'red'))
       sys.exit(1)