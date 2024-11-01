import time
import os
import math
import numpy as np
import matplotlib.pyplot as plt
from termcolor import colored
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20, Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from utils.encryption_tool import TorCrypto, EncryptionMethod, EncryptionConfig
from utils.crypto_config import DEFAULT_CONFIG

class TorEncryptionBenchmark:
    def __init__(self, rsa_key_size=2048):
        print(colored(f"Initializing benchmark with {rsa_key_size}-bit RSA key...", 'yellow'))
        
        # Generate RSA keys
        self.rsa_key_size = rsa_key_size
        self.private_key = RSA.generate(rsa_key_size)
        self.public_key = self.private_key.publickey()
        
        # Initialize different crypto configurations
        self.crypto_configs = {
            'AES': EncryptionConfig(symmetric_method=EncryptionMethod.AES),
            'ChaCha20': EncryptionConfig(symmetric_method=EncryptionMethod.CHACHA20),
            'Blowfish': EncryptionConfig(symmetric_method=EncryptionMethod.BLOWFISH)
        }
        
        # Create TorCrypto instances for each method
        self.crypto_instances = {
            name: TorCrypto(config) 
            for name, config in self.crypto_configs.items()
        }
        
        print(colored("Initialization complete", 'green'))

    def benchmark_encryption(self, method_name, data, iterations=100):
        """Benchmark a specific encryption method"""
        crypto = self.crypto_instances[method_name]
        times = []
        
        for _ in range(iterations):
            # Generate new key for each iteration
            sym_key = crypto.symmetric.generate_key()
            
            start_time = time.perf_counter()
            
            # Encrypt
            if isinstance(data, str):
                data = data.encode('utf-8')
            padded_data = pad(data, 16)  # Use AES block size
            encrypted = crypto.encrypt_layer(padded_data, sym_key)
            
            # Decrypt
            decrypted = crypto.decrypt_layer(encrypted, sym_key)
            final_data = unpad(decrypted, 16)
            
            end_time = time.perf_counter()
            times.append(end_time - start_time)
            
            # Verify
            assert final_data == data, f"Decryption failed for {method_name}"
            
        return np.mean(times), np.std(times)

    def simulate_circuit_encryption(self, data, keys, public_keys):
        """Simulate encryption through a Tor circuit"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Add padding to the original message
        message = pad(data, 16)
        
        # Apply encryption layers (like onion layers)
        for i in range(len(keys)):
            # First, encrypt with symmetric key
            aes = AES.new(keys[i], AES.MODE_CBC, b"0" * 16)
            message = aes.encrypt(pad(message, 16))
            
            # Then encrypt the symmetric key with RSA
            cipher = PKCS1_OAEP.new(public_keys[i])
            encrypted_key = cipher.encrypt(keys[i])
            
            # Combine them
            message = encrypted_key + message
            
        return message

    def simulate_circuit_decryption(self, data, keys, private_keys):
        """Simulate decryption through a Tor circuit"""
        message = data
        
        # Remove layers in reverse order
        for i in range(len(keys)-1, -1, -1):
            # Split RSA and AES parts
            rsa_size = private_keys[i].size_in_bytes()
            encrypted_key = message[:rsa_size]
            encrypted_data = message[rsa_size:]
            
            # Decrypt symmetric key
            cipher = PKCS1_OAEP.new(private_keys[i])
            sym_key = cipher.decrypt(encrypted_key)
            assert sym_key == keys[i], "Key mismatch in circuit"
            
            # Decrypt data
            aes = AES.new(sym_key, AES.MODE_CBC, b"0" * 16)
            message = aes.decrypt(encrypted_data)
            try:
                message = unpad(message, 16)
            except ValueError:
                pass
            
        return message

    def benchmark_full_circuit(self, data, num_hops=3, iterations=100):
        """Benchmark complete Tor circuit encryption"""
        times = []
        
        for _ in range(iterations):
            # Generate keys for the circuit
            sym_keys = [get_random_bytes(32) for _ in range(num_hops)]
            node_private_keys = [RSA.generate(self.rsa_key_size) for _ in range(num_hops)]
            node_public_keys = [key.publickey() for key in node_private_keys]
            
            start_time = time.perf_counter()
            
            # Simulate circuit encryption
            encrypted = self.simulate_circuit_encryption(data, sym_keys, node_public_keys)
            
            # Simulate circuit decryption
            decrypted = self.simulate_circuit_decryption(encrypted, sym_keys, node_private_keys)
            
            end_time = time.perf_counter()
            times.append(end_time - start_time)
            
            # Verify
            if isinstance(data, str):
                data = data.encode('utf-8')
            assert decrypted == data, "Circuit encryption/decryption failed"
            
        return np.mean(times), np.std(times)

    def run_comparison(self, data_sizes=None):
        """Run comparison tests for different data sizes"""
        if data_sizes is None:
            data_sizes = [64, 256, 1024, 4096, 16384, 65536]
        
        results = {
            'AES': [],
            'ChaCha20': [],
            'Blowfish': [],
            'Full Circuit (3 hops)': []
        }
        
        for size in data_sizes:
            data = os.urandom(size)
            print(colored(f"\nTesting with {size} bytes:", 'yellow'))
            
            # Test each encryption method
            for method in ['AES', 'ChaCha20', 'Blowfish']:
                try:
                    mean_time, std_time = self.benchmark_encryption(method, data)
                    results[method].append(mean_time * 1000)  # Convert to ms
                    print(colored(
                        f"{method}: {mean_time*1000:.3f} ms (±{std_time*1000:.3f})",
                        'cyan'
                    ))
                except Exception as e:
                    print(colored(f"Error testing {method}: {e}", 'red'))
                    results[method].append(None)
            
            # Test full circuit
            try:
                mean_time, std_time = self.benchmark_full_circuit(data)
                results['Full Circuit (3 hops)'].append(mean_time * 1000)
                print(colored(
                    f"Full Circuit: {mean_time*1000:.3f} ms (±{std_time*1000:.3f})",
                    'green'
                ))
            except Exception as e:
                print(colored(f"Error testing full circuit: {e}", 'red'))
                results['Full Circuit (3 hops)'].append(None)
        
        return results, data_sizes

    def plot_results(self, results, data_sizes):
        """Plot comparison results"""
        plt.figure(figsize=(12, 8))
        
        colors = {
            'AES': 'blue',
            'ChaCha20': 'green',
            'Blowfish': 'red',
            'Full Circuit (3 hops)': 'purple'
        }
        
        for algorithm, times in results.items():
            # Filter out None values
            valid_points = [(size, time) for size, time in zip(data_sizes, times) if time is not None]
            if valid_points:
                sizes, times = zip(*valid_points)
                plt.plot(sizes, times, marker='o', 
                        label=algorithm, color=colors[algorithm])
        
        plt.xlabel('Data Size (bytes)')
        plt.ylabel('Time (ms)')
        plt.title(f'Tor Network Encryption Performance\n(RSA-{self.rsa_key_size})')
        plt.legend()
        plt.grid(True)
        plt.xscale('log')
        plt.yscale('log')
        
        # Add performance zones
        plt.axhspan(0, 1, color='green', alpha=0.1, label='Excellent')
        plt.axhspan(1, 10, color='yellow', alpha=0.1, label='Good')
        plt.axhspan(10, 100, color='orange', alpha=0.1, label='Fair')
        plt.axhspan(100, 1000, color='red', alpha=0.1, label='Poor')
        
        plt.show()

    def save_results_to_file(self, results, data_sizes, filename='benchmark_results.txt'):
        """Save benchmark results to a file"""
        with open(filename, 'w') as f:
            f.write(f"Tor Network Encryption Benchmark Results\n")
            f.write(f"RSA Key Size: {self.rsa_key_size} bits\n")
            f.write("=" * 50 + "\n\n")
            
            for size, *times in zip(data_sizes, *[results[algo] for algo in results]):
                f.write(f"\nData Size: {size} bytes\n")
                f.write("-" * 30 + "\n")
                for algo, time in zip(results.keys(), times):
                    if time is not None:
                        f.write(f"{algo}: {time:.3f} ms\n")
                    else:
                        f.write(f"{algo}: Failed\n")

def main():
    # Test with different RSA key sizes
    rsa_key_sizes = [2048, 3072, 4096]
    
    for key_size in rsa_key_sizes:
        print(colored(f"\nRunning benchmark with {key_size}-bit RSA key", 'yellow'))
        benchmark = TorEncryptionBenchmark(rsa_key_size=key_size)
        
        # Run benchmarks
        results, data_sizes = benchmark.run_comparison()
        
        # Save results
        benchmark.save_results_to_file(results, data_sizes, 
                                     f'benchmark_results_{key_size}.txt')
        
        # Plot results
        benchmark.plot_results(results, data_sizes)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\nBenchmark interrupted", 'red'))
    except Exception as e:
        print(colored(f"\nError: {e}", 'red'))