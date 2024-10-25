import time
import os
import math
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import numpy as np
import matplotlib.pyplot as plt

class EncryptionBenchmark:
    def __init__(self, rsa_key_size=2048):
        # Generate keys for different algorithms
        self.aes_key = AESGCM.generate_key(bit_length=256)
        self.chacha_key = ChaCha20Poly1305.generate_key()
        
        # RSA key generation with configurable size
        self.rsa_key_size = rsa_key_size
        print(f"Generating {rsa_key_size}-bit RSA key...")
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=rsa_key_size
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        
        # Calculate maximum RSA message length for the given key size
        # Formula: (key_size_bits / 8) - 2 * (hash_size_bits / 8) - 2
        self.max_rsa_chunk_size = (rsa_key_size // 8) - 2 * (256 // 8) - 2
        print(f"Maximum RSA chunk size: {self.max_rsa_chunk_size} bytes")

    def _split_data_for_rsa(self, data):
        """Split data into chunks suitable for RSA encryption"""
        return [data[i:i + self.max_rsa_chunk_size] 
                for i in range(0, len(data), self.max_rsa_chunk_size)]

    def benchmark_aes(self, data, iterations=100):
        """Benchmark AES-GCM encryption"""
        times = []
        aesgcm = AESGCM(self.aes_key)
        
        for _ in range(iterations):
            nonce = os.urandom(12)
            start_time = time.perf_counter()
            
            # Encrypt
            ciphertext = aesgcm.encrypt(nonce, data, None)
            
            # Decrypt
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            end_time = time.perf_counter()
            times.append(end_time - start_time)
            
            # Verify
            assert plaintext == data
            
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

    def run_comparison(self, data_sizes=None):
        """Run comparison tests for different data sizes"""
        if data_sizes is None:
            # Default sizes from 64 bytes to 1MB
            data_sizes = [64, 256, 1024, 4096, 16384, 65536, 262144, 1048576]
        
        results = {
            'AES-GCM': [],
            'ChaCha20-Poly1305': [],
            f'RSA-{self.rsa_key_size}': []
        }
        
        for size in data_sizes:
            data = os.urandom(size)
            print(f"\nTesting with {size} bytes:")
            
            # Test AES-GCM
            mean_time, std_time = self.benchmark_aes(data)
            results['AES-GCM'].append(mean_time * 1000)  # Convert to ms
            print(f"AES-GCM: {mean_time*1000:.10f} ms (±{std_time*1000:.10f})")
            
            # Test ChaCha20-Poly1305
            mean_time, std_time = self.benchmark_chacha20(data)
            results['ChaCha20-Poly1305'].append(mean_time * 1000)
            print(f"ChaCha20: {mean_time*1000:.10f} ms (±{std_time*1000:.10f})")
            
            # Test RSA with batching
            try:
                mean_time, std_time = self.benchmark_rsa_batch(data)
                results[f'RSA-{self.rsa_key_size}'].append(mean_time * 1000)
                num_chunks = math.ceil(size / self.max_rsa_chunk_size)
                print(f"RSA-{self.rsa_key_size} ({num_chunks} chunks): {mean_time*1000:.10f} ms (±{std_time*1000:.10f})")
            except Exception as e:
                print(f"RSA-{self.rsa_key_size}: Error - {str(e)}")
                results[f'RSA-{self.rsa_key_size}'].append(None)
        
        return results, data_sizes

    def plot_results(self, results, data_sizes):
        """Plot comparison results"""
        plt.figure(figsize=(12, 8))
        
        for algorithm, times in results.items():
            # Filter out None values
            valid_points = [(size, time) for size, time in zip(data_sizes, times) if time is not None]
            if valid_points:
                sizes, times = zip(*valid_points)
                plt.plot(sizes, times, marker='o', label=algorithm)
        
        plt.xlabel('Data Size (bytes)')
        plt.ylabel('Time (ms)')
        plt.title(f'Encryption Algorithm Performance Comparison\n(RSA-{self.rsa_key_size} with batching)')
        plt.legend()
        plt.grid(True)
        plt.xscale('log')
        plt.yscale('log')
        plt.show()

def main():
    # Test with different RSA key sizes
    rsa_key_sizes = [2048, 3072, 4096]
    
    for key_size in rsa_key_sizes:
        print(f"\nRunning benchmark with {key_size}-bit RSA key")
        benchmark = EncryptionBenchmark(rsa_key_size=key_size)
        results, data_sizes = benchmark.run_comparison()
        benchmark.plot_results(results, data_sizes)

if __name__ == "__main__":
    main()