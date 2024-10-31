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
    message = pad_message(message)
    for key in aes_key_list:
        message = add_layer(message, key)
    return message

def peel_layer(ciphertext, aes_key):
    aes_obj = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
    message = aes_obj.decrypt(ciphertext)
    return message

def peel_all_layers(aes_key_list, response):
    for i in reversed(range(0, len(aes_key_list))):
        response = peel_layer(response, aes_key_list[i])
    response = unpad_message(response)
    return response

def wrap_message(message, rsa_key, aes_key):
    aes_obj = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
    if isinstance(message, str):
        message = message.encode('utf-8')
    # Make sure message length is multiple of 16 for AES
    padded_message = pad_message(message)
    ciphertext_aes = aes_obj.encrypt(padded_message)
    
    # Use PKCS1_OAEP for RSA encryption
    cipher = PKCS1_OAEP.new(rsa_key)
    ciphertext_rsa = cipher.encrypt(aes_key)
    
    # Combine RSA-encrypted AES key with AES-encrypted message
    blob = ciphertext_rsa + ciphertext_aes
    return blob

def wrap_all_messages(hoplist, destination):
    randfile = Random.new()
    wrapped_message = destination
    aes_key_list = []
    packedroute = ""
    for i in range(0, len(hoplist)):
        # have some way of getting each, probably from directory authority
        elem_aes_key = randfile.read(32)
        aes_key_list.append(elem_aes_key)
        if i != 0:
            packedroute = packHostPort(hoplist[i - 1][0], hoplist[i - 1][1])
        wrapped_message = packedroute + wrapped_message
        wrapped_message = wrap_message(
            pad_message(wrapped_message), hoplist[i][2], elem_aes_key)
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