from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(2048)
cipher = PKCS1_OAEP.new(key)


plaintext = "hi, i'm a dog :)"

public_key = key.exportKey(format = "OpenSSH", passphrase=None, pkcs = 1)
cipher_text = cipher.encrypt(plaintext.encode())
print (cipher_text)
print (PKCS1_OAEP.new(key).decrypt(cipher_text).decode())
print (len(public_key))