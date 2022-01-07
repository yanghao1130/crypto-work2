from Crypto import Random
from Crypto.Cipher import AES

key=Random.new().read(AES.key_size[0])
iv=Random.new().read(AES.block_size)

def pkcs7_pad(message, block_size):
    # If the length of the given message is already equal to the block size, there is no need to pad
    if len(message) % block_size==0:
        return message

    # Otherwise compute the padding byte and return the padded message
    ch = block_size - len(message) % block_size
    return message + bytes([ch] * ch)

def is_pkcs7_padded(binary_data):
    """Returns whether the data is PKCS 7 padded."""

    # Take what we expect to be the padding
    padding = binary_data[-binary_data[-1]:]

    # Check that all the bytes in the range indicated by the padding are equal to the padding value itself
    return all(padding[b] == len(padding) for b in range(0, len(padding)))


def pkcs7_unpad(data):
    """Unpads the given data from its PKCS 7 padding and returns it."""
    if len(data) == 0:
        raise Exception("The input data must contain at least one byte")

    if not is_pkcs7_padded(data):
        return data

    padding_len = data[len(data) - 1]
    return data[:-padding_len]


def encrypt(data):
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    data = data.replace(';', '').replace('=', '')
    plaintext = (prefix + data + suffix).encode()
    cipher = AES.new(key, AES.MODE_CBC,iv)
    ciphertext=cipher.encrypt(pkcs7_pad(plaintext, AES.block_size))
    return ciphertext

def decrypt(data):
    cryptos = AES.new(key, AES.MODE_CBC, iv)
    plaintext=pkcs7_unpad(cryptos.decrypt(data))
    
    return plaintext,b';admin=true;' in plaintext

def find_prefix_length(block_length):
    ciphertexta=encrypt('A')
    ciphertextb=encrypt('B')
    common_len = 0
    while ciphertexta[common_len] == ciphertextb[common_len]:
        common_len += 1

    common_len = int(common_len / block_length) * block_length
    for i in range(1, block_length + 1):
        ciphertexta = encrypt('A' * i + 'X')
        ciphertextb = encrypt('A' * i + 'Y')
        
        if ciphertexta[common_len:common_len + block_length] == ciphertextb[common_len:common_len + block_length]:
                return common_len + (block_length - i)
    
        
def cbc_bit_flip():
    block_length=16
    prefix_length=find_prefix_length(block_length)
    additional_prefix_bytes = (block_length - (prefix_length % block_length)) % block_length
    total_prefix_length = prefix_length + additional_prefix_bytes

    plaintext = "?admin?true"
    additional_plaintext_bytes = (block_length - (len(plaintext) % block_length)) % block_length
    final_plaintext = additional_plaintext_bytes * '?' + plaintext
    ciphertext = encrypt(additional_prefix_bytes * '?' + final_plaintext) 
    
    semicolon = ciphertext[total_prefix_length - 11] ^ ord('?') ^ ord(';')
    equals = ciphertext[total_prefix_length - 5] ^ ord('?') ^ ord('=')
    forced_ciphertext = ciphertext[:total_prefix_length - 11] + bytes([semicolon]) + \
                        ciphertext[total_prefix_length - 10: total_prefix_length - 5] + \
                        bytes([equals]) + ciphertext[total_prefix_length - 4:]

    return forced_ciphertext

ciphertext=cbc_bit_flip()
print(decrypt(ciphertext))

