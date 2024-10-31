from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import struct
import socket
import signal
import os
import sys

# new code

# Receives a message from a socket of a specified length
def recvn(socket, length):
    recv_end_index = 0
    recv_buffer = b""  # เปลี่ยนเป็น bytes
    while length > recv_end_index:
        new_buffer = socket.recv(length - recv_end_index)  # ไม่ต้อง decode
        bytes_read = len(new_buffer)
        if bytes_read == 0:
            return b""
        recv_buffer += new_buffer  # รวม bytes
        recv_end_index += bytes_read
    return recv_buffer

# Receive a message from socket with a length prefix
def recv_message_with_length_prefix(socket):
    packet_len = recvn(socket, 4)
    if packet_len == b"":  # เปรียบเทียบกับ empty bytes
        return b""
    message_length = struct.unpack('!I', packet_len)[0]
    message = recvn(socket, message_length)
    return message

def sendn(socket, message):
    length = len(message)
    sent_end_index = 0
    while length > sent_end_index:
        bytes_sent = socket.send(message[sent_end_index:])
        if bytes_sent == 0:
            return 0
        sent_end_index += bytes_sent
    return length

def send_message_with_length_prefix(socket, message):
    prefix = struct.pack('!I', len(message))
    # 4 bytes, should send all of it
    #send prefix
    byte_sent = sendn(socket, prefix)
    if byte_sent == 0:
        return False
    #send message
    byte_sent = sendn(socket, message)
    if byte_sent == 0:
        return False

# old code
# def pad_message(message):
#     """
#     Pads a string for use with AES encryption
#     :param message: bytes to be padded
#     :return: padded message
#     """
#     if isinstance(message, str):
#         message = message.encode('utf-8')
#     pad_size = 16 - (len(message) % 16)
#     if pad_size == 0:
#         pad_size = 16
#     padding = bytes([pad_size] * pad_size)
#     return message + padding

# def unpad_message(message):
#     pad_size = message[-1]
#     return message[:-pad_size]

# def add_layer(message, aes_key):
#     aes_obj = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
#     if isinstance(message, str):
#         message = message.encode('utf-8')
#     ciphertext = aes_obj.encrypt(message)
#     return ciphertext

# def peel_layer(ciphertext, aes_key):
#     aes_obj = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
#     message = aes_obj.decrypt(ciphertext)
#     return message

# def wrap_message(message, rsa_key, aes_key):
#     aes_obj = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
#     if isinstance(message, str):
#         message = message.encode('utf-8')
#     ciphertext_aes = aes_obj.encrypt(message)
#     ciphertext_rsa = rsa_key.encrypt(aes_key, rsa_key.publickey())[0]
#     blob = ciphertext_rsa + ciphertext_aes
#     return blob

# def unwrap_message(blob, rsa_key):
#     ciphertext_rsa = blob[0:128]
#     ciphertext_aes = blob[128:len(blob)]
#     aes_key = rsa_key.decrypt(ciphertext_rsa)
#     aes_obj = AES.new(aes_key, AES.MODE_CBC, "0" * 16)
#     message = aes_obj.decrypt(ciphertext_aes)
#     print("length of aes key: " + str(len(aes_key)))
#     return message, aes_key

def signal_handler(received_signal, frame):
   os.killpg(os.getpgid(0), signal.SIGINT)
   sys.exit(0)