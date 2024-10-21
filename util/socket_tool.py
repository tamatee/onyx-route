import socket

def recv_message(src_socket):
    message = src_socket.recv(1024)
    return message.decode()