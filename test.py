from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Load RSA private key from a PEM file
def load_private_key(filename):
    with open(filename, 'rb') as file:
        private_key = RSA.import_key(file.read())
    return private_key

# Load RSA public key from a PEM file
def load_public_key(filename):
    with open(filename, 'rb') as file:
        public_key = RSA.import_key(file.read())
    return public_key

# Encrypt a message using the public key
def encrypt_message(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message)
    return ciphertext

# Decrypt a message using the private key
def decrypt_message(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message

# Main program
if __name__ == "__main__":
    # Load your existing keys
    private_key = load_private_key("keys/private.pem")  # Replace with your private key file path
    public_key = load_public_key("keys/public.pem")      # Replace with your public key file path

    # Message to encrypt
    message = b"Hi, I'm a dog :)"
    print(f"Original Message: {message.decode('utf-8')}")

    # Encrypt the message
    ciphertext = encrypt_message(public_key, message)
    print(f"Encrypted Message: {ciphertext.hex()}")

    # Decrypt the message
    decrypted_message = decrypt_message(private_key, ciphertext)
    print(f"Decrypted Message: {decrypted_message.decode('utf-8')}")
