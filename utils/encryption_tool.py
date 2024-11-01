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
    Add all encryption layers to a message using the AES keys.
    
    Args:
        aes_key_list (list): List of AES keys
        message (bytes): Original message
        
    Returns:
        bytes: Encrypted message
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    result = pad_message(message)
    
    # Apply encryption layers in reverse order
    for key in reversed(aes_key_list):
        aes = AES.new(key, AES.MODE_CBC, b"0" * 16)
        result = aes.encrypt(pad_message(result))
    
    return result

def peel_layer(ciphertext, aes_key):
    aes_obj = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
    message = aes_obj.decrypt(ciphertext)
    return message

def peel_all_layers(aes_key_list, message):
    """
    Remove all encryption layers from a message using the AES keys.
    
    Args:
        aes_key_list (list): List of AES keys
        message (bytes): Encrypted message
        
    Returns:
        bytes: Decrypted message
    """
    result = message
    
    # Remove encryption layers in forward order
    for key in aes_key_list:
        aes = AES.new(key, AES.MODE_CBC, b"0" * 16)
        result = aes.decrypt(result)
    
    # Remove padding from final result
    return result.rstrip(b'\0')

def wrap_message(message, public_key, aes_key):
    """
    Wrap a message layer with encryption for a single hop.
    
    Args:
        message (bytes): The message to wrap
        public_key (RSA.RsaKey): Public key of the target node
        aes_key (bytes): AES key for symmetric encryption
        
    Returns:
        bytes: Wrapped message
    """
    # Ensure message is bytes
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Create AES cipher
    aes = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
    
    # Encrypt message with AES
    cipher_text = aes.encrypt(message)
    
    # Encrypt AES key with RSA
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    
    # Combine encrypted key and message
    return encrypted_aes_key + cipher_text

def wrap_all_messages(hoplist, destination):
    """
    Wrap message for all hops in the route.
    
    Args:
        hoplist (list): List of tuples containing (host, port, public_key) for each hop
        destination (bytes): Packed destination address
        
    Returns:
        tuple: (wrapped_message, aes_key_list)
    """
    randfile = Random.new()
    wrapped_message = destination  # Should already be bytes from packHostPort
    aes_key_list = []
    
    for i in range(len(hoplist)):
        # Generate AES key for this hop
        elem_aes_key = randfile.read(32)
        aes_key_list.append(elem_aes_key)
        
        # Get packed route for previous hop (if not first hop)
        if i != 0:
            packed_route = packHostPort(hoplist[i - 1][0], hoplist[i - 1][1])
            wrapped_message = packed_route + wrapped_message
        
        # Pad and wrap the message
        padded_message = pad_message(wrapped_message)
        wrapped_message = wrap_message(padded_message, hoplist[i][2], elem_aes_key)
    
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