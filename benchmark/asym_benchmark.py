import time
import os
import matplotlib.pyplot as plt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Define the number of iterations for benchmarking
iterations = 100
plaintext = b'This is a test message.'

# Function to encrypt with AES
def aes_encrypt(key, data):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()  # Prepend IV for decryption

# Function to decrypt with AES
def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]  # Extract the IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext[16:]) + decryptor.finalize()

# ECC Benchmarking (excluding key generation)
ecc_encryption_time = []
ecc_decryption_time = []

for _ in range(iterations):
    # ECDH Key Exchange
    ecc_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    peer_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    peer_public_key = peer_private_key.public_key()  # Get the public key
    shared_key = ecc_private_key.exchange(ec.ECDH(), peer_public_key)  # Use the public key

    # Derive a key for AES encryption from the shared key
    kdf = Scrypt(salt=os.urandom(16), length=32, n=2**14, r=8, p=1)
    aes_key = kdf.derive(shared_key)

    # Encrypt
    start = time.time()
    ciphertext = aes_encrypt(aes_key, plaintext)
    ecc_encryption_time.append((time.time() - start) * 1000)  # Convert to milliseconds

    # Decrypt
    start = time.time()
    decrypted_plaintext = aes_decrypt(aes_key, ciphertext)
    ecc_decryption_time.append((time.time() - start) * 1000)  # Convert to milliseconds

# RSA Benchmarking (excluding key generation)
rsa_encryption_time = []
rsa_decryption_time = []

for _ in range(iterations):
    rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    
    # Encrypt
    public_key = rsa_private_key.public_key()
    start = time.time()
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    rsa_encryption_time.append((time.time() - start) * 1000)  # Convert to milliseconds

    # Decrypt
    start = time.time()
    decrypted_plaintext = rsa_private_key.decrypt(
        ciphertext,
        padding.OAEP(  # Add the same padding for decryption
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    rsa_decryption_time.append((time.time() - start) * 1000)  # Convert to milliseconds

# Calculate average times
ecc_avg_times = [
    sum(ecc_encryption_time) / iterations,
    sum(ecc_decryption_time) / iterations,
]

rsa_avg_times = [
    sum(rsa_encryption_time) / iterations,
    sum(rsa_decryption_time) / iterations,
]

# Plotting the results
labels = ['Encryption', 'Decryption']
x = range(len(labels))

plt.figure(figsize=(10, 5))
plt.bar(x, ecc_avg_times, width=0.4, label='ECC', align='center')
plt.bar([p + 0.4 for p in x], rsa_avg_times, width=0.4, label='RSA', align='center')

plt.xlabel('Operation')
plt.ylabel('Time (milliseconds)')
plt.title('Benchmarking ECC vs RSA')
plt.xticks([p + 0.2 for p in x], labels)
plt.legend()
plt.grid()
plt.show()