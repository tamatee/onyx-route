# keygen.py

import os
from utils.ecc_encryption import ECCTools
from termcolor import colored

def generate_keys():
    try:
        # Create keys directory if it doesn't exist
        os.makedirs('keys', exist_ok=True)
        
        # Generate new key pair
        print(colored("Generating new ECC key pair...", 'yellow'))
        private_key, public_key = ECCTools.generate_keypair()
        
        # Get key bytes
        private_bytes = ECCTools.key_to_bytes(private_key).encode('utf-8')
        public_bytes = ECCTools.key_to_bytes(public_key).encode('utf-8')
        
        # Save private key
        with open('keys/ecc_private.pem', 'wb') as f:
            f.write(private_bytes)
            
        # Save public key
        with open('keys/ecc_public.pem', 'wb') as f:
            f.write(public_bytes)
            
        print(colored("Keys generated successfully!", 'green'))
        print(colored("Private key saved to: keys/private.pem", 'green'))
        print(colored("Public key saved to: keys/public.pem", 'green'))
        
        # Verify keys can be loaded back
        try:
            loaded_private = ECCTools.private_key_from_bytes(private_bytes)
            loaded_public = ECCTools.public_key_from_bytes(public_bytes)
            print(colored("Key verification successful!", 'green'))
        except Exception as e:
            print(colored(f"Warning: Key verification failed: {e}", 'yellow'))
        
    except Exception as e:
        print(colored(f"Error generating keys: {e}", 'red'))
        raise

if __name__ == "__main__":
    try:
        generate_keys()
    except KeyboardInterrupt:
        print(colored("\nKey generation cancelled.", 'red'))
    except Exception as e:
        print(colored(f"Fatal error: {e}", 'red'))