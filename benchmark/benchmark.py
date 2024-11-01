import os
import time
import numpy as np
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes

class EncryptionBenchmark:
    def __init__(self):
        # Generate keys for different algorithms
        self.aes_key = os.urandom(32)  # AES-256
        self.aes_gcm_key = os.urandom(32)  # AES-GCM
        self.chacha_key = ChaCha20Poly1305.generate_key()  # ChaCha20 key

    def benchmark_aes_cbc(self, data, iterations=100):
        """Benchmark AES encryption in CBC mode."""
        times = []
        iv_size = 16  # AES block size in bytes

        for _ in range(iterations):
            iv = os.urandom(iv_size)  # Generate random IV
            aes_cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
            encryptor = aes_cipher.encryptor()
            decryptor = aes_cipher.decryptor()

            # Start timing the encryption and decryption
            start_time = time.perf_counter()

            # Pad data to AES block size (16 bytes)
            padded_data = data + b"\0" * (16 - len(data) % 16)

            # Encrypt
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # Decrypt
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            end_time = time.perf_counter()
            times.append(end_time - start_time)

            # Verify that the decrypted plaintext matches the original data
            assert plaintext.rstrip(b"\0") == data  # Remove padding for comparison

        return np.mean(times), np.std(times)

    def benchmark_aes_ctr(self, data, iterations=100):
        """Benchmark AES encryption in CTR mode."""
        times = []
        nonce_size = 16  # AES-CTR typically uses a 16-byte nonce

        for _ in range(iterations):
            nonce = os.urandom(nonce_size)  # Generate random nonce
            aes_cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(nonce))
            encryptor = aes_cipher.encryptor()
            decryptor = aes_cipher.decryptor()

            # Start timing the encryption and decryption
            start_time = time.perf_counter()

            # Encrypt
            ciphertext = encryptor.update(data) + encryptor.finalize()

            # Decrypt
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            end_time = time.perf_counter()
            times.append(end_time - start_time)

            # Verify that the decrypted plaintext matches the original data
            assert plaintext == data

        return np.mean(times), np.std(times)

    def benchmark_aes_gcm(self, data, iterations=100):
        """Benchmark AES-GCM encryption."""
        times = []
        aes_gcm = AESGCM(self.aes_gcm_key)

        for _ in range(iterations):
            nonce = os.urandom(12)  # GCM nonce should be 12 bytes
            start_time = time.perf_counter()

            # Encrypt
            ciphertext = aes_gcm.encrypt(nonce, data, None)

            # Decrypt
            plaintext = aes_gcm.decrypt(nonce, ciphertext, None)

            end_time = time.perf_counter()
            times.append(end_time - start_time)

            # Verify that the decrypted plaintext matches the original data
            assert plaintext == data

        return np.mean(times), np.std(times)

    def benchmark_chacha20(self, data, iterations=100):
        """Benchmark ChaCha20-Poly1305 encryption."""
        times = []
        chacha = ChaCha20Poly1305(self.chacha_key)
        
        for _ in range(iterations):
            nonce = os.urandom(12)  # ChaCha20 nonce size
            start_time = time.perf_counter()
            
            # Encrypt
            ciphertext = chacha.encrypt(nonce, data, None)
            
            # Decrypt
            plaintext = chacha.decrypt(nonce, ciphertext, None)
            
            end_time = time.perf_counter()
            times.append(end_time - start_time)
            
            # Verify that the decrypted plaintext matches the original data
            assert plaintext == data
            
        return np.mean(times), np.std(times)

    def run_comparison(self, data_sizes=None):
        if data_sizes is None:
            # Data sizes up to 64 MB
            data_sizes = [
                64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 
                2097152, 4194304, 8388608, 16777216, 33554432, 67108864
            ]  # Data sizes in bytes
    
        results = {
            'AES-CBC': [],
            'AES-CTR': [],
            'AES-GCM': [],
            'ChaCha20-Poly1305': []
        }
    
        for size in data_sizes:
            data = os.urandom(size)  # Generate random data of the specified size
            print(f"\nTesting with {size} bytes of data:")
    
            # Benchmark AES-CBC
            mean_time, std_time = self.benchmark_aes_cbc(data)
            results['AES-CBC'].append(mean_time * 1000)  # Convert to milliseconds
            print(f"AES-CBC: {mean_time * 1000:.10f} ms (± {std_time * 1000:.10f})")
    
            # Benchmark AES-CTR
            mean_time, std_time = self.benchmark_aes_ctr(data)
            results['AES-CTR'].append(mean_time * 1000)  # Convert to milliseconds
            print(f"AES-CTR: {mean_time * 1000:.10f} ms (± {std_time * 1000:.10f})")
    
            # Benchmark AES-GCM
            mean_time, std_time = self.benchmark_aes_gcm(data)
            results['AES-GCM'].append(mean_time * 1000)  # Convert to milliseconds
            print(f"AES-GCM: {mean_time * 1000:.10f} ms (± {std_time * 1000:.10f})")
    
            # Benchmark ChaCha20-Poly1305
            mean_time, std_time = self.benchmark_chacha20(data)
            results['ChaCha20-Poly1305'].append(mean_time * 1000)  # Convert to milliseconds
            print(f"ChaCha20-Poly1305: {mean_time * 1000:.10f} ms (± {std_time * 1000:.10f})")
    
        return results, data_sizes

    def plot_results(self, results, data_sizes):
        """Plot the comparison results for all algorithms."""
        plt.figure(figsize=(12, 8))

        for algorithm, times in results.items():
            plt.plot(data_sizes, times, marker='o', label=algorithm)

        plt.xlabel('Data Size (bytes)')
        plt.ylabel('Time (ms)')
        plt.title('Encryption Performance Comparison')
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
