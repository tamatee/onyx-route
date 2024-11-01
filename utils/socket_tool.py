import struct
import signal
import os
import sys

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

def send_message_with_length_prefix(socket, message):
    try:
        prefix = struct.pack('!I', len(message))
        # Send prefix (4 bytes)
        if sendn(socket, prefix) == 0:
            return False
        # Send message
        if sendn(socket, message) == 0:
            return False
        return True
    except:
        return False

def sendn(socket, message):
    try:
        length = len(message)
        sent_end_index = 0
        while length > sent_end_index:
            bytes_sent = socket.send(message[sent_end_index:])
            if bytes_sent == 0:
                return 0
            sent_end_index += bytes_sent
        return length
    except:
        return 0

def signal_handler(received_signal, frame):
   os.kill(os.getpid(0), signal.SIGINT)
   sys.exit(0)