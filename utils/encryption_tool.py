from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
from .padding_tool import *
from .packing_tool import *

def add_layer(message, aes_key):
    aes_obj = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
    if isinstance(message, str):
        message = message.encode('utf-8')
    # Make sure message length is multiple of 16 for AES
    padded_message = pad_message(message)
    ciphertext = aes_obj.encrypt(padded_message)
    return ciphertext

def add_all_layers(aes_key_list, message):
    """
    Add all encryption layers to a message
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Start with padded message
    current = pad(message, AES.block_size)
    
    # Apply each encryption layer in reverse order
    for key in reversed(aes_key_list):
        aes = AES.new(key, AES.MODE_CBC, b"0" * 16)
        current = aes.encrypt(pad(current, AES.block_size))
    
    return current

def peel_layer(ciphertext, aes_key):
    aes_obj = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
    message = aes_obj.decrypt(ciphertext)
    return message

def peel_all_layers(aes_key_list, message):
    """
    Remove all encryption layers from a message
    """
    current = message
    
    # Remove each encryption layer in order
    for key in aes_key_list:
        aes = AES.new(key, AES.MODE_CBC, b"0" * 16)
        try:
            current = unpad(aes.decrypt(current), AES.block_size)
        except ValueError:
            # If unpadding fails, just remove null bytes
            current = aes.decrypt(current).rstrip(b'\0')
    
    return current

def wrap_message(message, public_key, aes_key):
    """
    Wrap a message for a single hop
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Encrypt message with AES
    aes = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
    padded_message = pad(message, AES.block_size)
    encrypted_message = aes.encrypt(padded_message)
    
    # Encrypt AES key with RSA
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_key = rsa_cipher.encrypt(aes_key)
    
    return encrypted_key + encrypted_message

def wrap_all_messages(hoplist, destination):
    """
    Wrap message for all hops
    """
    randfile = Random.new()
    wrapped_message = destination
    aes_key_list = []
    
    for i in range(len(hoplist)):
        # Generate AES key
        elem_aes_key = randfile.read(32)
        aes_key_list.append(elem_aes_key)
        
        # Get previous hop address if not first hop
        if i != 0:
            packed_route = packHostPort(hoplist[i - 1][0], hoplist[i - 1][1])
            wrapped_message = packed_route + wrapped_message
        
        # Wrap the message
        wrapped_message = wrap_message(wrapped_message, hoplist[i][2], elem_aes_key)
    
    return wrapped_message, aes_key_list


def unwrap_message(blob, rsa_key):
    try:
        # Split the blob into RSA and AES parts
        # PKCS1_OAEP output size is the same as key size in bytes
        key_size = rsa_key.size_in_bytes()
        ciphertext_rsa = blob[:key_size]
        ciphertext_aes = blob[key_size:]
        
        # Decrypt the AES key using RSA-OAEP
        cipher = PKCS1_OAEP.new(rsa_key)
        aes_key = cipher.decrypt(ciphertext_rsa)
        
        # Use the decrypted AES key to decrypt the message
        aes_obj = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
        message = aes_obj.decrypt(ciphertext_aes)
        
        return message, aes_key
        
    except Exception as e:
        print(f"Error in unwrap_message: {e}")
        raise e

def process_layer(message, rsa_key):
    """Helper function to process a single layer of encryption"""
    try:
        # Split RSA and AES parts
        key_size = rsa_key.size_in_bytes()
        ciphertext_rsa = message[:key_size]
        ciphertext_aes = message[key_size:]
        
        # Decrypt AES key using RSA-OAEP
        cipher = PKCS1_OAEP.new(rsa_key)
        aes_key = cipher.decrypt(ciphertext_rsa)
        
        # Decrypt message using AES
        aes_obj = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
        decrypted_message = aes_obj.decrypt(ciphertext_aes)
        
        return decrypted_message, aes_key
        
    except Exception as e:
        print(f"Error in process_layer: {e}")
        raise e