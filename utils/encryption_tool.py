from Crypto.Cipher import AES

def add_layer(message, aes_key):
    aes_obj = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
    if isinstance(message, str):
        message = message.encode('utf-8')
    ciphertext = aes_obj.encrypt(message)
    return ciphertext

def peel_layer(ciphertext, aes_key):
    aes_obj = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
    message = aes_obj.decrypt(ciphertext)
    return message

def wrap_message(message, rsa_key, aes_key):
    aes_obj = AES.new(aes_key, AES.MODE_CBC, b"0" * 16)
    if isinstance(message, str):
        message = message.encode('utf-8')
    ciphertext_aes = aes_obj.encrypt(message)
    ciphertext_rsa = rsa_key.encrypt(aes_key, rsa_key.publickey())[0]
    blob = ciphertext_rsa + ciphertext_aes
    return blob

def unwrap_message(blob, rsa_key):
    ciphertext_rsa = blob[0:128]
    ciphertext_aes = blob[128:len(blob)]
    aes_key = rsa_key.decrypt(ciphertext_rsa)
    aes_obj = AES.new(aes_key, AES.MODE_CBC, "0" * 16)
    message = aes_obj.decrypt(ciphertext_aes)
    print("length of aes key: " + str(len(aes_key)))
    return message, aes_key