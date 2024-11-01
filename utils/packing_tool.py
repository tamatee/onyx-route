import struct
import socket
from Crypto.PublicKey import ECC

def packHostPort(ip, port):
    """Pack IP and port into bytes"""
    return socket.inet_aton(ip) + struct.pack("!i", port)

def unpackHostPort(packed):
    return (socket.inet_ntoa(packed[:4]), struct.unpack("!i", packed[4:])[0])

def process_route(data):
    """Process route data from Directory Authority and extract node information.
    
    Args:
        data: Decrypted route data from Directory Authority
        
    Returns:
        List of tuples containing (host, port, public_key) for each node
    """
    try:
        nodes = []
        current_pos = 0
        
        while current_pos < len(data):
            # Extract address (8 bytes)
            if current_pos + 8 > len(data):
                print(f"Insufficient data for address at position {current_pos}")
                break
                
            addr = data[current_pos:current_pos + 8]
            current_pos += 8
            
            # Find the PEM boundaries
            begin_key = b"-----BEGIN PUBLIC KEY-----\n"
            end_key = b"-----END PUBLIC KEY-----"
            
            key_start = data.find(begin_key, current_pos)
            if key_start == -1:
                print("Could not find start of public key")
                break
                
            key_end = data.find(end_key, key_start)
            if key_end == -1:
                print("Could not find end of public key")
                break
                
            # Extract the complete key including boundaries
            key_data = data[key_start:key_end + len(end_key)]
            
            # Import the key using ECC instead of RSA
            try:
                host, port = unpackHostPort(addr)
                public_key = ECC.import_key(key_data)
                nodes.append((host, port, public_key))
                print(f"Successfully processed node at {host}:{port}")
                current_pos = key_end + len(end_key)
            except Exception as e:
                print(f"Error importing key: {e}")
                print(f"Key data preview: {key_data[:50]}...")
                break
                
        return nodes
        
    except Exception as e:
        print(f"Error processing route: {e}")
        return []