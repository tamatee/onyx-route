# generate_ecc_keys.py
from Crypto.PublicKey import ECC

def generate_ecc_keypair():
    # Generate key pair with specific curve
    private_key = ECC.generate(curve='P-384')
    
    # Save private key
    with open('keys/ecc_private.pem', 'wt') as f:
        f.write(private_key.export_key(format='PEM'))
    
    # Save public key
    with open('keys/ecc_public.pem', 'wt') as f:
        public_key = private_key.public_key()
        f.write(public_key.export_key(format='PEM'))

    print("ECC keys generated successfully:")
    print(f" - Private key saved to: keys/ecc_private.pem")
    print(f" - Public key saved to: keys/ecc_public.pem")

if __name__ == "__main__":
    generate_ecc_keypair()