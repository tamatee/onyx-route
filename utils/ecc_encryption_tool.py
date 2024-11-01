# ecc_encryption_tool.py
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
import hashlib

class ECCTools:
    @staticmethod
    def generate_keypair():
        """Generate an ECC key pair using curve P-384"""
        private_key = ECC.generate(curve='P-384')
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def serialize_public_key(public_key):
        """Serialize public key to PEM format"""
        return public_key.export_key(format='PEM')
    
    @staticmethod
    def serialize_private_key(private_key):
        """Serialize private key to PEM format"""
        return private_key.export_key(format='PEM')
    
    @staticmethod
    def deserialize_key(pem_data):
        """Deserialize key from PEM format"""
        return ECC.import_key(pem_data)
    
    @staticmethod
    def derive_shared_key(private_key, peer_public_key):
        """Derive a shared key using ECDH"""
        # Perform ECDH key agreement
        shared_point = private_key.d * peer_public_key.pointQ
        shared_secret = shared_point.x.to_bytes()
        
        # Use HKDF to derive AES key
        derived_key = HKDF(
            shared_secret,
            32,  # 32 bytes for AES-256
            salt=b'onion-routing',
            hashmod=SHA256,
            context=b'encryption'
        )
        return derived_key

def wrap_message(message, recipient_public_key, sender_private_key):
    """Wrap a message for a single hop using ECC and AES-GCM"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    elif not isinstance(message, bytes):
        raise TypeError("Message must be string or bytes")
    
    # Generate shared key using ECDH
    shared_key = derive_shared_key(sender_private_key, recipient_public_key)
    
    # Generate nonce for AES-GCM
    nonce = Random.get_random_bytes(16)
    
    # Create AES cipher
    aes = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
    
    # Encrypt message and get tag
    ciphertext, tag = aes.encrypt_and_digest(message)
    
    # Include sender's public key for receiver to derive same shared key
    # Make sure public key is in bytes
    sender_public_bytes = sender_private_key.public_key().export_key(format='PEM')
    if isinstance(sender_public_bytes, str):
        sender_public_bytes = sender_public_bytes.encode()

    # All components should now be bytes
    print("Debug - Types:")
    print("sender_public_bytes:", type(sender_public_bytes))
    print("nonce:", type(nonce))
    print("ciphertext:", type(ciphertext))
    print("tag:", type(tag))
    
    # Return the combined message (all in bytes)
    return sender_public_bytes + nonce + ciphertext + tag

def unwrap_message(blob, recipient_private_key):
    """
    Unwrap a message using ECC and AES-GCM
    """
    try:
        # Extract components
        # Parse sender's public key
        pub_key_end = blob.find(b'-----END PUBLIC KEY-----') + len(b'-----END PUBLIC KEY-----')
        sender_public_bytes = blob[:pub_key_end]
        remaining_data = blob[pub_key_end:]

        # Rest of the data
        nonce = remaining_data[:16]
        tag = remaining_data[-16:]
        ciphertext = remaining_data[16:-16]

        # Import sender's public key
        sender_public_key = ECCTools.deserialize_key(sender_public_bytes)

        # Derive shared key
        shared_key = ECCTools.derive_shared_key(recipient_private_key, sender_public_key)

        # Decrypt message
        cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
        try:
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted, shared_key
        except ValueError as e:
            print(f"Decryption error: {e}")
            print(f"Ciphertext hex: {ciphertext.hex()[:32]}...")
            print(f"Tag hex: {tag.hex()}")
            raise

    except Exception as e:
        print(f"Error unwrapping message: {e}")
        raise

def wrap_all_messages(hoplist, destination):
    """Wrap message for all hops using ECC"""
    # Ensure destination is bytes
    if isinstance(destination, str):
        wrapped_message = destination.encode('utf-8')
    else:
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
            if isinstance(packed_route, str):
                packed_route = packed_route.encode('utf-8')
            wrapped_message = packed_route + wrapped_message
        
        # Wrap the message for this hop
        wrapped_message = wrap_message(wrapped_message, hoplist[i][2], ephemeral_private)
    
    return wrapped_message, aes_key_list, nonce_list

def derive_shared_key(private_key, public_key):
    """Derive a shared key using ECDH and HKDF"""
    # Perform ECDH
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