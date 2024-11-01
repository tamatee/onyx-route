from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

def pad_message(message):
    """
    Pad message to multiple of 16 bytes for AES CBC mode.
    
    Args:
        message (bytes): Message to pad
        
    Returns:
        bytes: Padded message
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    return pad(message, AES.block_size)

def unpad_message(padded_message):
    """
    Remove PKCS7 padding from message.
    
    Args:
        padded_message (bytes): Padded message
        
    Returns:
        bytes: Original message
    """
    try:
        return unpad(padded_message, AES.block_size)
    except ValueError:
        # If unpadding fails, return the original message
        return padded_message