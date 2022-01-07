from random import randint
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64decode


key = Random.new().read(AES.key_size[0])
random_prefix = Random.new().read(randint(0, 255))

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

def aes_ecb_encrypt(data,padding):
    '''生成随机密钥进行加密'''
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(random_prefix+padding+data, AES.block_size))

def count_aes_ecb_repetitions(ciphertext,block_size):
    """Counts the number of repeated chunks of the ciphertext and returns it."""
    chunks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    number_of_duplicates = len(chunks) - len(set(chunks))
    return number_of_duplicates

'''寻找随机前缀prefix的长度'''
def find_prefix_length(data,block_length):
    ciphertext1 = aes_ecb_encrypt(data,b'')
    ciphertext2 = aes_ecb_encrypt(data,b'a')
    for i in range(0, len(ciphertext2), block_length):
        if ciphertext1[i:i+block_length] != ciphertext2[i:i+block_length]:
            prefix_length = i
            break
    a=i
    prefix_length=0
    use_length=3*block_length-1
    for i in range(100):
        padding=b'A' * use_length
        ciphertext=aes_ecb_encrypt(data,padding)
        if count_aes_ecb_repetitions(ciphertext,16)>0:
            use_length-=1
        else:
            return a+16-(use_length-16-15)

        
def byte_at_a_time_ecb_decrypt(data,prefix_length,block_length):
    key = Random.new().read(AES.key_size[0])
    maxlen=len(aes_ecb_encrypt(data,b''))
    dispadding=b''
    for i in range(maxlen):

        key = Random.new().read(AES.key_size[0])
        length_to_use=(block_length-prefix_length-(1+len(dispadding)))%block_length
        propadding=b'A'*length_to_use
        real_padding=aes_ecb_encrypt(data,propadding)
        determine_length = prefix_length+length_to_use + len(dispadding) + 1
        
        for j in range(256):
            fake_padding=aes_ecb_encrypt(propadding+dispadding+bytes([j]),b'')
            if fake_padding==real_padding[:determine_length]:
                dispadding+=bytes([j])
                break
        
    return dispadding

    


secret_padding = b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGF"
                            "pciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IH"
                            "RvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

prefix_length=find_prefix_length(secret_padding,16)
print(prefix_length)
discovered_secret_padding=byte_at_a_time_ecb_decrypt(secret_padding,prefix_length,16)
#print(discovered_secret_padding)
discovered_secret_padding=pkcs7_unpad(discovered_secret_padding)
print(discovered_secret_padding)
print(discovered_secret_padding==secret_padding)

