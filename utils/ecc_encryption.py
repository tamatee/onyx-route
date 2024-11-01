from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto import Random
import os

class ECCTools:
    @staticmethod
    def generate_keypair():
        """Generate an ECC key pair using curve P-384"""
        private_key = ECC.generate(curve='P-384')
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def key_to_bytes(key):
        """Convert an ECC key to bytes in PEM format"""
        if isinstance(key, ECC.EccKey):
            if key.has_private():
                return key.export_key(format='PEM', use_pkcs8=True)
            else:
                return key.export_key(format='PEM')
        raise ValueError("Invalid key type")
    
    @staticmethod
    def public_key_from_bytes(key_bytes):
        """Load public key from PEM bytes"""
        if isinstance(key_bytes, str):
            key_bytes = key_bytes.encode('utf-8')
        return ECC.import_key(key_bytes)
    
    @staticmethod
    def private_key_from_bytes(key_bytes):
        """Load private key from PEM bytes"""
        if isinstance(key_bytes, str):
            key_bytes = key_bytes.encode('utf-8')
        return ECC.import_key(key_bytes)

    @staticmethod
    def derive_shared_key(private_key, peer_public_key, context=None):
        """Derive a shared key using ECDH"""
        if not isinstance(private_key, ECC.EccKey) or not private_key.has_private():
            raise ValueError("Invalid private key")
        if not isinstance(peer_public_key, ECC.EccKey) or peer_public_key.has_private():
            raise ValueError("Invalid public key")
            
        # Compute the shared point
        shared_point = private_key.d * peer_public_key.pointQ
        shared_secret = shared_point.x.to_bytes()
        
        # Use HKDF to derive the final key
        context_bytes = context.encode('utf-8') if isinstance(context, str) else (context or b'')
        return HKDF(
            master=shared_secret,
            key_len=32,
            salt=b'ECC-Encryption-Salt',
            hashmod=SHA256,
            context=context_bytes
        )

    @staticmethod
    def encrypt_message(recipient_public_key, message, context=None):
        """
        Encrypt a message using ECC-based hybrid encryption
        Returns: (ephemeral_public_key_bytes, encrypted_data, tag, nonce)
        """
        try:
            # Input validation
            if not isinstance(message, bytes):
                if isinstance(message, str):
                    message = message.encode('utf-8')
                else:
                    raise ValueError("Message must be bytes or string")
                    
            # Generate ephemeral key pair
            ephemeral_private_key = ECC.generate(curve='P-384')
            ephemeral_public_key = ephemeral_private_key.public_key()
            
            # Derive shared key
            shared_key = ECCTools.derive_shared_key(
                ephemeral_private_key,
                recipient_public_key,
                context=context
            )
            
            # Generate nonce
            nonce = Random.get_random_bytes(12)
            
            # Create cipher and encrypt
            cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
            if context:
                cipher.update(context.encode('utf-8') if isinstance(context, str) else context)
                
            ciphertext, tag = cipher.encrypt_and_digest(message)
            
            # Export the ephemeral public key
            ephem_pub_bytes = ECCTools.key_to_bytes(ephemeral_public_key).encode('utf-8')
            
            return (ephem_pub_bytes, ciphertext, tag, nonce)
            
        except Exception as e:
            raise Exception(f"Encryption error: {str(e)}")

    @staticmethod
    def decrypt_message(private_key, ephemeral_public_bytes, ciphertext, tag, nonce, context=None):
        """Decrypt a message using ECC-based hybrid encryption"""
        try:
            # Import ephemeral public key
            if isinstance(ephemeral_public_bytes, str):
                ephemeral_public_bytes = ephemeral_public_bytes.encode('utf-8')
                
            ephemeral_public_key = ECCTools.public_key_from_bytes(ephemeral_public_bytes)
            
            # Derive shared key
            shared_key = ECCTools.derive_shared_key(
                private_key,
                ephemeral_public_key,
                context=context
            )
            
            # Create cipher for decryption
            cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
            if context:
                cipher.update(context.encode('utf-8') if isinstance(context, str) else context)
                
            # Decrypt and verify
            return cipher.decrypt_and_verify(ciphertext, tag)
            
        except Exception as e:
            raise Exception(f"Decryption error: {str(e)}")

    @staticmethod
    def wrap_message(message, recipient_public_key, aes_key=None, nonce=None):
        """Wrap a message with optional existing AES key and nonce"""
        if aes_key is None:
            aes_key = Random.get_random_bytes(32)
        if nonce is None:
            nonce = Random.get_random_bytes(12)
            
        if isinstance(message, str):
            message = message.encode('utf-8')
            
        # Encrypt message with AES-GCM
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        
        # Encrypt the AES key and nonce using ECC
        ephem_pub_key, enc_key_data, key_tag, key_nonce = ECCTools.encrypt_message(
            recipient_public_key,
            aes_key + nonce
        )
        
        return {
            'ephemeral_public_key': ephem_pub_key,
            'encrypted_key_data': enc_key_data,
            'key_tag': key_tag,
            'key_nonce': key_nonce,
            'ciphertext': ciphertext,
            'tag': tag
        }

    @staticmethod
    def unwrap_message(wrapped_data, private_key):
        """Unwrap a message encrypted with wrap_message"""
        try:
            # Extract components
            ephem_pub_key = wrapped_data['ephemeral_public_key']
            enc_key_data = wrapped_data['encrypted_key_data']
            key_tag = wrapped_data['key_tag']
            key_nonce = wrapped_data['key_nonce']
            ciphertext = wrapped_data['ciphertext']
            tag = wrapped_data['tag']
            
            # Decrypt the AES key and nonce
            key_data = ECCTools.decrypt_message(
                private_key,
                ephem_pub_key,
                enc_key_data,
                key_tag,
                key_nonce
            )
            
            aes_key = key_data[:32]
            nonce = key_data[32:]
            
            # Decrypt the message
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            return plaintext, aes_key, nonce
            
        except Exception as e:
            raise Exception(f"Unwrap error: {str(e)}")