from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import socket
import utils
import sys
from termcolor import colored

def main():
   # กำหนดค่าคงที่
   DA_IP = '127.0.0.1'
   DA_PORT = 12345
   DEST_HOST = '127.0.0.1'
   DEST_PORT = 54321

   try:
       # อ่าน public key ของ directory authority
       with open('dir_auth_pub_key.pem', 'r') as da_file:
           da_pub_key = RSA.importKey(da_file.read())

       # เชื่อมต่อกับ directory authority
       s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       s.connect((DA_IP, DA_PORT))
       s.send(b'r')  # ระบุประเภทคำขอ (route)

       # สร้างและส่ง AES key
       randfile = Random.new()
       aes_key = randfile.read(32)
       aes_obj = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
       aes_msg = da_pub_key.encrypt(aes_key, 0)[0]
       
       if not utils.send_message_with_length_prefix(s, aes_msg):
           s.close()
           print(colored("Directory authority connection failed", 'red'))
           return

       # รับข้อมูลเส้นทาง
       data = utils.recv_message_with_length_prefix(s)
       if data == b"":
           s.close()
           print(colored("Directory authority connection failed", 'red'))
           return

       hop_data = aes_obj.decrypt(data)
       hoplist = utils.process_route(hop_data)
       hoplist = list(reversed(hoplist))

       # เริ่มการเชื่อมต่อผ่านเส้นทาง
       run_client_connection(hoplist, utils.packHostPort(DEST_HOST, DEST_PORT))

   except FileNotFoundError:
       print(colored("Error: Directory authority public key file not found", 'red'))
   except Exception as e:
       print(colored(f"Error occurred: {e}", 'red'))

def run_client_connection(hoplist, destination):
   try:
       # เชื่อมต่อกับ node แรก
       next_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       next_host = (hoplist[len(hoplist) - 1][0], hoplist[len(hoplist) - 1][1])
       next_s.connect(next_host)

       # สร้างและส่งข้อความเริ่มต้น
       wrapped_message, aes_key_list = utils.wrap_all_messages(hoplist, destination)
       utils.send_message_with_length_prefix(next_s, wrapped_message)

       print(colored("\nConnection established through Tor network!", 'green'))
       print(colored("Type 'QUIT' to exit", 'yellow'))

       while True:
           try:
               print(colored("\nCLIENT: Type message to send:", 'yellow'))
               message = input()
               
               if message.upper() == 'QUIT':
                   print(colored("Closing connection...", 'red'))
                   break

               # ส่งข้อความ
               message = message.encode('utf-8')
               message = utils.add_all_layers(aes_key_list, message)
               if not utils.send_message_with_length_prefix(next_s, message):
                   print(colored("Failed to send message", 'red'))
                   break
               
               # รับการตอบกลับ
               response = utils.recv_message_with_length_prefix(next_s)
               if not response:
                   print(colored("No response received", 'red'))
                   break
                   
               response = utils.peel_all_layers(aes_key_list, response)
               print(colored("\nCLIENT: Response from server:", 'red'))
               print(colored(response.decode('utf-8'), 'red'))

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