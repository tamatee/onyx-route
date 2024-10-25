import math
import random
from typing import Tuple, NamedTuple

class PaillierPublicKey(NamedTuple):
    n: int
    g: int

class PaillierPrivateKey(NamedTuple):
    lambda_: int
    mu: int
    public_key: PaillierPublicKey

def generate_paillier_keypair(bits: int = 1024) -> Tuple[PaillierPublicKey, PaillierPrivateKey]:
    """Generate a new Paillier keypair."""
    # Generate two large prime numbers
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    
    n = p * q
    g = n + 1  # This is a simple valid choice for g
    
    # Calculate lambda (lcm of p-1 and q-1)
    lambda_ = math.lcm(p - 1, q - 1)
    
    # Calculate mu
    # mu = (L(g^lambda mod n^2))^(-1) mod n, where L(x) = (x-1)/n
    # For g = n + 1, this simplifies to lambda^(-1) mod n
    mu = pow(lambda_, -1, n)
    
    public_key = PaillierPublicKey(n, g)
    private_key = PaillierPrivateKey(lambda_, mu, public_key)
    
    return public_key, private_key

def generate_prime(bits: int) -> int:
    """Generate a prime number of specified bits."""
    while True:
        # Generate random number of specified bits
        num = random.getrandbits(bits)
        # Ensure it's odd
        num |= 1
        # Ensure it's of correct bit length
        num |= (1 << bits - 1)
        # Check if prime
        if is_probable_prime(num):
            return num

def is_probable_prime(n: int, k: int = 5) -> bool:
    """Miller-Rabin primality test."""
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def encrypt(public_key: PaillierPublicKey, plaintext: int) -> int:
    """Encrypt a message using the public key."""
    n = public_key.n
    n_sq = n * n
    
    # Generate random r
    r = random.randrange(1, n)
    
    # c = g^m * r^n mod n^2
    c = (pow(public_key.g, plaintext, n_sq) * pow(r, n, n_sq)) % n_sq
    return c

def decrypt(private_key: PaillierPrivateKey, ciphertext: int) -> int:
    """Decrypt a message using the private key."""
    n = private_key.public_key.n
    n_sq = n * n
    
    # Calculate L(c^lambda mod n^2) * mu mod n
    x = pow(ciphertext, private_key.lambda_, n_sq)
    L = (x - 1) // n
    plaintext = (L * private_key.mu) % n
    return plaintext

def homomorphic_add(public_key: PaillierPublicKey, c1: int, c2: int) -> int:
    """Add two encrypted values homomorphically."""
    n_sq = public_key.n * public_key.n
    return (c1 * c2) % n_sq

# Test the implementation
if __name__ == "__main__":
    # Generate keys
    print("Generating keypair...")
    public_key, private_key = generate_paillier_keypair(bits=512)  # Using smaller key for demo
    print("Keys generated!")
    
    # Test regular encryption/decryption
    message1 = 42
    message2 = 73
    print(f"\nOriginal messages: {message1} and {message2}")
    
    # Encrypt messages
    cipher1 = encrypt(public_key, message1)
    cipher2 = encrypt(public_key, message2)
    print(f"Encrypted message 1: {cipher1}")
    print(f"Encrypted message 2: {cipher2}")
    
    # Test homomorphic addition
    cipher_sum = homomorphic_add(public_key, cipher1, cipher2)
    
    # Decrypt results
    decrypted1 = decrypt(private_key, cipher1)
    decrypted2 = decrypt(private_key, cipher2)
    decrypted_sum = decrypt(private_key, cipher_sum)
    
    print("\nDecryption results:")
    print(f"Decrypted message 1: {decrypted1}")
    print(f"Decrypted message 2: {decrypted2}")
    print(f"Decrypted sum: {decrypted_sum}")
    print(f"Actual sum: {message1 + message2}")
    print(f"Homomorphic property verified: {decrypted_sum == message1 + message2}")