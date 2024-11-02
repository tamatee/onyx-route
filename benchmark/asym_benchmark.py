import time
import os
import matplotlib.pyplot as plt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Define the range of packet sizes to benchmark (1 to 64 bytes)
packet_sizes = range(1, 65)

# Define the number of iterations for benchmarking
iterations = 100

# Initialize lists to hold average times for each packet size
ecc_encryption_times = []
ecc_decryption_times = []
rsa_encryption_times = []
rsa_decryption_times = []

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

# Benchmark ECC and RSA for each packet size
for size in packet_sizes:
    plaintext = os.urandom(size)  # Create a packet of `size` bytes

    # ECC Benchmarking
    ecc_enc_times = []
    ecc_dec_times = []
    for _ in range(iterations):
        ecc_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        peer_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        peer_public_key = peer_private_key.public_key()
        shared_key = ecc_private_key.exchange(ec.ECDH(), peer_public_key)

        # Derive AES key from shared key
        kdf = Scrypt(salt=os.urandom(16), length=32, n=2**14, r=8, p=1)
        aes_key = kdf.derive(shared_key)

        # Encrypt
        start = time.time()
        ciphertext = aes_encrypt(aes_key, plaintext)
        ecc_enc_times.append((time.time() - start) * 1000)

        # Decrypt
        start = time.time()
        decrypted_plaintext = aes_decrypt(aes_key, ciphertext)
        ecc_dec_times.append((time.time() - start) * 1000)

    ecc_encryption_times.append(sum(ecc_enc_times) / iterations)
    ecc_decryption_times.append(sum(ecc_dec_times) / iterations)

    # RSA Benchmarking
    rsa_enc_times = []
    rsa_dec_times = []
    for _ in range(iterations):
        rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = rsa_private_key.public_key()

        # Encrypt
        start = time.time()
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        rsa_enc_times.append((time.time() - start) * 1000)

        # Decrypt
        start = time.time()
        decrypted_plaintext = rsa_private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        rsa_dec_times.append((time.time() - start) * 1000)

    rsa_encryption_times.append(sum(rsa_enc_times) / iterations)
    rsa_decryption_times.append(sum(rsa_dec_times) / iterations)

# Plotting the results
plt.figure(figsize=(12, 6))
plt.plot(packet_sizes, ecc_encryption_times, label='ECC Encryption', color='blue')
plt.plot(packet_sizes, ecc_decryption_times, label='ECC Decryption', color='cyan')
plt.plot(packet_sizes, rsa_encryption_times, label='RSA Encryption', color='red')
plt.plot(packet_sizes, rsa_decryption_times, label='RSA Decryption', color='orange')

plt.xlabel('Packet Size (bytes)')
plt.ylabel('Time (milliseconds)')
plt.title('Benchmarking ECC vs RSA by Packet Size')
plt.legend()
plt.grid()
plt.show()