import time
import os
import math
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import numpy as np
import matplotlib.pyplot as plt

class EncryptionBenchmark:
    def __init__(self):
        # Generate keys for different algorithms
        self.aes_key = AESGCM.generate_key(bit_length=256)
        self.chacha_key = ChaCha20Poly1305.generate_key()
        
        # RSA key generation with configurable size
        self.rsa_key_size = 2048
        print(f"Generating {self.rsa_key_size}-bit RSA key...")
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.rsa_key_size
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        
        # Calculate maximum RSA message length for the given key size
        # Formula: (key_size_bits / 8) - 2 * (hash_size_bits / 8) - 2
        self.max_rsa_chunk_size = (self.rsa_key_size // 8) - 2 * (256 // 8) - 2
        print(f"Maximum RSA chunk size: {self.max_rsa_chunk_size} bytes")

    def _split_data_for_rsa(self, data):
        """Split data into chunks suitable for RSA encryption"""
        return [data[i:i + self.max_rsa_chunk_size] 
                for i in range(0, len(data), self.max_rsa_chunk_size)]

    def benchmark_aes(self, data, iterations=100):

        times = []
        iv_size = 16  # CBC mode requires a 16-byte IV

        for _ in range(iterations):
            iv = os.urandom(iv_size)
            aes_cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
            encryptor = aes_cipher.encryptor()
            decryptor = aes_cipher.decryptor()

            # Start encryption and decryption benchmark
            start_time = time.perf_counter()

            # Pad data to AES block size (16 bytes)
            padded_data = data + b"\0" * (16 - len(data) % 16)

            # Encrypt
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # Decrypt
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            end_time = time.perf_counter()
            times.append(end_time - start_time)

            # Verify
            assert plaintext.rstrip(b"\0") == data  # Remove padding for comparison

        return np.mean(times), np.std(times)

    def benchmark_chacha20(self, data, iterations=100):
        """Benchmark ChaCha20-Poly1305 encryption"""
        times = []
        chacha = ChaCha20Poly1305(self.chacha_key)
        
        for _ in range(iterations):
            nonce = os.urandom(12)
            start_time = time.perf_counter()
            
            # Encrypt
            ciphertext = chacha.encrypt(nonce, data, None)
            
            # Decrypt
            plaintext = chacha.decrypt(nonce, ciphertext, None)
            
            end_time = time.perf_counter()
            times.append(end_time - start_time)
            
            # Verify
            assert plaintext == data
            
        return np.mean(times), np.std(times)

    def benchmark_rsa_batch(self, data, iterations=100):
        """Benchmark RSA encryption with batch processing for larger messages"""
        times = []
        
        for _ in range(iterations):
            start_time = time.perf_counter()
            
            # Split data into chunks
            chunks = self._split_data_for_rsa(data)
            
            # Encrypt all chunks
            ciphertexts = []
            for chunk in chunks:
                ciphertext = self.rsa_public_key.encrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                ciphertexts.append(ciphertext)
            
            # Decrypt all chunks
            plaintexts = []
            for ciphertext in ciphertexts:
                plaintext = self.rsa_private_key.decrypt(
                    ciphertext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                plaintexts.append(plaintext)
            
            # Combine decrypted chunks
            final_plaintext = b''.join(plaintexts)
            
            end_time = time.perf_counter()
            times.append(end_time - start_time)
            
            # Verify
            assert final_plaintext == data
            
        return np.mean(times), np.std(times)
    
    def benchmark_aes_ctr(self, data, iterations=100):
        """Benchmark AES-CTR encryption"""
        times = []
        iv_size = 16  # AES-CTR mode typically uses a 16-byte nonce

        for _ in range(iterations):
            nonce = os.urandom(iv_size)
            aes_cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(nonce))
            encryptor = aes_cipher.encryptor()
            decryptor = aes_cipher.decryptor()

            start_time = time.perf_counter()

            # Encrypt
            ciphertext = encryptor.update(data) + encryptor.finalize()

            # Decrypt
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            end_time = time.perf_counter()
            times.append(end_time - start_time)

            # Verify
            assert plaintext == data

        return np.mean(times), np.std(times)

    def benchmark_3des(self, data, iterations=100):
        """Benchmark 3DES encryption"""
        times = []
        des3_key = os.urandom(24)  # 3DES requires a 24-byte key
        iv = os.urandom(8)  # 3DES uses an 8-byte IV

        for _ in range(iterations):
            des3_cipher = Cipher(algorithms.TripleDES(des3_key), modes.CBC(iv))
            encryptor = des3_cipher.encryptor()
            decryptor = des3_cipher.decryptor()

            start_time = time.perf_counter()

            # Pad data to 3DES block size (8 bytes)
            padded_data = data + b"\0" * (8 - len(data) % 8)

            # Encrypt
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # Decrypt
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            end_time = time.perf_counter()
            times.append(end_time - start_time)

            # Verify
            assert plaintext.rstrip(b"\0") == data

        return np.mean(times), np.std(times)

    def run_comparison(self, data_sizes=None):
        if data_sizes is None:
            data_sizes = [64, 256, 1024, 4096, 16384, 65536, 262144, 1048576]
        
        results = {
            'AES-CBC': [],
            'ChaCha20-Poly1305': [],
            'AES-CTR': [],
            '3DES': []
        }
        
        for size in data_sizes:
            data = os.urandom(size)
            print(f"\nTesting with {size} bytes:")
            
            # AES-CBC
            mean_time, std_time = self.benchmark_aes(data)
            results['AES-CBC'].append(mean_time * 1000)
            print(f"AES-CBC: {mean_time*1000:.10f} ms (±{std_time*1000:.10f})")
            
            # ChaCha20-Poly1305
            mean_time, std_time = self.benchmark_chacha20(data)
            results['ChaCha20-Poly1305'].append(mean_time * 1000)
            print(f"ChaCha20: {mean_time*1000:.10f} ms (±{std_time*1000:.10f})")
    
            # AES-CTR
            mean_time, std_time = self.benchmark_aes_ctr(data)
            results['AES-CTR'].append(mean_time * 1000)
            print(f"AES-CTR: {mean_time*1000:.10f} ms (±{std_time*1000:.10f})")
            
            # 3DES
            mean_time, std_time = self.benchmark_3des(data)
            results['3DES'].append(mean_time * 1000)
            print(f"3DES: {mean_time*1000:.10f} ms (±{std_time*1000:.10f})")
        
        return results, data_sizes

    def plot_results(self, results, data_sizes):
        """Plot comparison results"""
        plt.figure(figsize=(12, 8))
        
        for algorithm, times in results.items():
            valid_points = [(size, time) for size, time in zip(data_sizes, times) if time is not None]
            if valid_points:
                sizes, times = zip(*valid_points)
                plt.plot(sizes, times, marker='o', label=algorithm)
        
        plt.xlabel('Data Size (bytes)')
        plt.ylabel('Time (ms)')
        plt.title('Encryption Algorithm Performance Comparison')
        plt.legend()
        plt.grid(True)
        plt.xscale('log')
        plt.yscale('log')
        plt.show()

def main():
    benchmark = EncryptionBenchmark()
    results, data_sizes = benchmark.run_comparison()
    benchmark.plot_results(results, data_sizes)

if __name__ == "__main__":
    main()