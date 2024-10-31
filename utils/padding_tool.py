def pad_message(message):
    if isinstance(message, str):
        message = message.encode('utf-8')
    pad_size = 16 - (len(message) % 16)
    if pad_size == 0:
        pad_size = 16
    padding = bytes([pad_size] * pad_size)
    return message + padding

def unpad_message(message):
    pad_size = message[-1]
    return message[:-pad_size]