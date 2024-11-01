from Crypto.PublicKey import RSA
from Crypto import Random
import os

def generate_keys():
    # Create directory if it doesn't exist
    if not os.path.exists('keys'):
        os.makedirs('keys')
    
    # Generate key pair
    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator)
    
    # Export private key
    private_key = key.export_key()
    with open('keys/private.pem', 'wb') as f:
        f.write(private_key)
    
    # Export public key
    public_key = key.publickey().export_key()
    with open('keys/public.pem', 'wb') as f:
        f.write(public_key)

    print("Keys generated successfully!")

if __name__ == "__main__":
    generate_keys()