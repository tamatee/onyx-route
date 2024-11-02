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
iterations = 100  # Define the number of iterations for benchmarking

# Initialize dictionaries to hold average times for each packet size for each algorithm
encryption_times = {'ECC': [], 'RSA': []}
decryption_times = {'ECC': [], 'RSA': []}

# Function to encrypt with AES (for ECC and hybrid encryption)
def aes_encrypt(key, data):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()  # Prepend IV for decryption

# Function to decrypt with AES (for ECC and hybrid encryption)
def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]  # Extract the IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext[16:]) + decryptor.finalize()

# Benchmarking ECC with AES encryption (hybrid approach)
def benchmark_ecc(plaintext, iterations):
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
        
        # Verify decryption
        assert decrypted_plaintext == plaintext, "Decryption failed"

    return sum(ecc_enc_times) / iterations, sum(ecc_dec_times) / iterations

# Benchmarking RSA encryption and decryption
def benchmark_rsa(plaintext, iterations):
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
        
        # Verify decryption
        assert decrypted_plaintext == plaintext, "Decryption failed"

    return sum(rsa_enc_times) / iterations, sum(rsa_dec_times) / iterations

# Run benchmarks for each packet size
for size in packet_sizes:
    plaintext = os.urandom(size)  # Create a packet of `size` bytes
    
    # ECC Benchmarking
    ecc_enc_time, ecc_dec_time = benchmark_ecc(plaintext, iterations)
    encryption_times['ECC'].append(ecc_enc_time)
    decryption_times['ECC'].append(ecc_dec_time)

    # RSA Benchmarking
    rsa_enc_time, rsa_dec_time = benchmark_rsa(plaintext, iterations)
    encryption_times['RSA'].append(rsa_enc_time)
    decryption_times['RSA'].append(rsa_dec_time)

# Plotting the results
plt.figure(figsize=(12, 6))

# Plot ECC and RSA encryption and decryption times
plt.plot(packet_sizes, encryption_times['ECC'], label='ECC Encryption', color='blue')
plt.plot(packet_sizes, decryption_times['ECC'], label='ECC Decryption', color='cyan')
plt.plot(packet_sizes, encryption_times['RSA'], label='RSA Encryption', color='red')
plt.plot(packet_sizes, decryption_times['RSA'], label='RSA Decryption', color='orange')

plt.xlabel('Packet Size (bytes)')
plt.ylabel('Time (milliseconds)')
plt.title('Benchmarking ECC vs RSA by Packet Size')
plt.legend()
plt.grid()
plt.show()
