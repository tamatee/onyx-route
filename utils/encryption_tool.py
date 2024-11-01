# encryption_tool.py
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto import Random
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from .padding_tool import *
from .packing_tool import *

def derive_shared_key(private_key, public_key):
    """Derive a shared key using ECDH and HKDF"""
    shared_point = private_key.d * public_key.pointQ
    shared_secret = shared_point.x.to_bytes()
    
    # Use HKDF to derive the final key
    shared_key = HKDF(
        master=shared_secret,
        key_len=32,
        salt=b'onion-routing',
        hashmod=SHA256,
        context=b'encryption'
    )
    return shared_key

def wrap_message(message, recipient_public_key, sender_private_key):
    """Wrap a message for a single hop using ECC and AES-GCM"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Generate shared key using ECDH
    shared_key = derive_shared_key(sender_private_key, recipient_public_key)
    
    # Generate nonce for AES-GCM
    nonce = Random.get_random_bytes(16)
    
    # Create AES cipher
    aes = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
    
    # Encrypt message and get tag
    ciphertext, tag = aes.encrypt_and_digest(message)
    
    # Include sender's public key for receiver to derive same shared key
    sender_public_bytes = sender_private_key.public_key().export_key(format='PEM').encode()

    # Return the combined message (all in bytes)
    return sender_public_bytes + nonce + ciphertext + tag

def unwrap_message(blob, recipient_private_key):
    """Unwrap a message using ECC and AES-GCM"""
    try:
        # Find the end of the public key
        pub_key_marker = b"-----END PUBLIC KEY-----\n"
        pub_key_end = blob.find(pub_key_marker) + len(pub_key_marker)
        
        # Extract components
        sender_public_bytes = blob[:pub_key_end]
        sender_public_key = ECC.import_key(sender_public_bytes)
        
        # Rest of the data
        remaining_data = blob[pub_key_end:]
        nonce = remaining_data[:16]
        tag = remaining_data[-16:]
        ciphertext = remaining_data[16:-16]
        
        # Derive shared key
        shared_key = derive_shared_key(recipient_private_key, sender_public_key)
        
        # Create AES cipher
        aes = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
        
        # Decrypt and verify
        message = aes.decrypt_and_verify(ciphertext, tag)
        
        return message, shared_key, nonce
        
    except Exception as e:
        print(f"Error unwrapping message: {e}")
        raise

def wrap_all_messages(hoplist, destination):
    """Wrap message for all hops using ECC"""
    wrapped_message = destination
    aes_key_list = []
    nonce_list = []
    
    for i in range(len(hoplist)):
        # Generate ephemeral ECC keypair for this hop
        ephemeral_private = ECC.generate(curve='P-384')
        
        # Generate shared key using ECDH
        shared_key = derive_shared_key(ephemeral_private, hoplist[i][2])
        aes_key_list.append(shared_key)
        
        # Generate nonce
        nonce = Random.get_random_bytes(16)
        nonce_list.append(nonce)
        
        # Add previous hop address if not first hop
        if i != 0:
            packed_route = packHostPort(hoplist[i - 1][0], hoplist[i - 1][1])
            wrapped_message = packed_route + wrapped_message
        
        # Wrap the message for this hop
        wrapped_message = wrap_message(wrapped_message, hoplist[i][2], ephemeral_private)
    
    return wrapped_message, aes_key_list, nonce_list

# Keep original add_layer and peel_layer functions as they are for AES operations

def add_layer(message, aes_key, nonce):
    """Add an encryption layer with consistent nonce handling"""
    aes_obj = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    if isinstance(message, str):
        message = message.encode('utf-8')
    ciphertext, tag = aes_obj.encrypt_and_digest(message)
    return ciphertext + tag

def peel_layer(message, aes_key, nonce):
    """Remove an encryption layer with consistent nonce handling"""
    aes_obj = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext = message[:-16]
    tag = message[-16:]
    return aes_obj.decrypt_and_verify(ciphertext, tag)

def add_all_layers(aes_key_list, message, nonce_list):
    """Add all encryption layers with proper tag handling"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    current = message
    for key, nonce in zip(reversed(aes_key_list), reversed(nonce_list)):
        aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = aes.encrypt_and_digest(current)
        current = ciphertext + tag
    
    return current

def peel_all_layers(aes_key_list, message, nonce_list):
    """Remove all encryption layers with proper tag handling"""
    current = message
    
    for i, (key, nonce) in enumerate(zip(aes_key_list, nonce_list)):
        try:
            aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
            tag = current[-16:]
            ciphertext = current[:-16]
            current = aes.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            print(f"Error peeling layer {i+1}: {e}")
            raise
    
    return current