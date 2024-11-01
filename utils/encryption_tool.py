from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
from .padding_tool import *
from .packing_tool import *

def add_layer(message, aes_key, nonce):
    """Add an encryption layer with consistent nonce handling"""
    aes_obj = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    if isinstance(message, str):
        message = message.encode('utf-8')
    ciphertext, tag = aes_obj.encrypt_and_digest(message)
    return ciphertext + tag  # Concatenate ciphertext and tag

def peel_layer(message, aes_key, nonce):
    """Remove an encryption layer with consistent nonce handling"""
    aes_obj = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext = message[:-16]  # Separate ciphertext from tag
    tag = message[-16:]  # Get the tag
    return aes_obj.decrypt_and_verify(ciphertext, tag)

def add_all_layers(aes_key_list, message, nonce_list):
    """
    Add all encryption layers with proper tag handling
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    current = message
    for key, nonce in zip(reversed(aes_key_list), reversed(nonce_list)):
        # Create new AES object for this layer
        aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
        # Encrypt the current message (which includes previous layer's tag)
        ciphertext, tag = aes.encrypt_and_digest(current)
        # Combine ciphertext and tag for this layer
        current = ciphertext + tag
    
    return current

def peel_all_layers(aes_key_list, message, nonce_list):
    """
    Remove all encryption layers with proper tag handling
    """
    current = message
    
    for i, (key, nonce) in enumerate(zip(aes_key_list, nonce_list)):
        try:
            # Create new AES object for this layer
            aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
            # Split the message into ciphertext and tag
            tag = current[-16:]
            ciphertext = current[:-16]
            # Decrypt and verify this layer
            current = aes.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            print(f"Error peeling layer {i+1}: {e}")
            raise
    
    return current

def wrap_message(message, public_key, aes_key, nonce):
    """
    Wrap a message for a single hop with proper tag handling
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Create AES cipher
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    
    # Encrypt message and get tag
    ciphertext, tag = aes.encrypt_and_digest(message)
    
    # Encrypt the key and nonce with RSA
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_key = rsa_cipher.encrypt(aes_key + nonce)
    
    # Return the combined message
    return encrypted_key + ciphertext + tag

def unwrap_message(blob, rsa_key):
    """
    Unwrap a message with proper tag handling
    """
    try:
        # Get sizes
        key_size = rsa_key.size_in_bytes()
        
        # Split the message
        encrypted_key = blob[:key_size]
        ciphertext = blob[key_size:-16]
        tag = blob[-16:]
        
        # Decrypt the key and nonce
        cipher = PKCS1_OAEP.new(rsa_key)
        key_and_nonce = cipher.decrypt(encrypted_key)
        aes_key = key_and_nonce[:32]
        nonce = key_and_nonce[32:]
        
        # Create AES cipher
        aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        
        # Decrypt and verify
        message = aes.decrypt_and_verify(ciphertext, tag)
        
        return message, aes_key, nonce
        
    except Exception as e:
        print(f"Error unwrapping message: {e}")
        raise

def wrap_all_messages(hoplist, destination):
    """Wrap message for all hops with consistent nonce handling"""
    randfile = Random.new()
    wrapped_message = destination
    aes_key_list = []
    nonce_list = []
    
    for i in range(len(hoplist)):
        # Generate new AES key and nonce for each hop
        elem_aes_key = randfile.read(32)
        aes_key_list.append(elem_aes_key)
        
        nonce = randfile.read(16)
        nonce_list.append(nonce)
        
        # Add previous hop address if not first hop
        if i != 0:
            packed_route = packHostPort(hoplist[i - 1][0], hoplist[i - 1][1])
            wrapped_message = packed_route + wrapped_message
        
        # Wrap the message for this hop
        wrapped_message = wrap_message(wrapped_message, hoplist[i][2], elem_aes_key, nonce)
    
    return wrapped_message, aes_key_list, nonce_list

def process_layer(message, rsa_key):
    """
    Process a single layer with proper tag handling
    """
    try:
        # Get RSA key size
        key_size = rsa_key.size_in_bytes()
        
        # Split message parts
        encrypted_key = message[:key_size]
        ciphertext = message[key_size:-16]
        tag = message[-16:]
        
        # Decrypt key and nonce
        cipher = PKCS1_OAEP.new(rsa_key)
        key_and_nonce = cipher.decrypt(encrypted_key)
        aes_key = key_and_nonce[:32]
        nonce = key_and_nonce[32:]
        
        # Create AES cipher
        aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        
        # Decrypt and verify
        decrypted = aes.decrypt_and_verify(ciphertext, tag)
        
        return decrypted, aes_key, nonce
        
    except Exception as e:
        print(f"Error processing layer: {e}")
        raise