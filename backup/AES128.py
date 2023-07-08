import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# A constant key size of 128 bits for AES-128
KeySize = 128

# A constant block size of 128 bits for AES
BlockSize = 128

# A constant initialization vector size of 16 bytes for AES
IVSize = 16

def Encrypt(data: bytes, key: bytes) -> bytes:
    # Check the input parameters for null values
    if data is None or len(data) == 0:
        raise ValueError("data cannot be null or empty")
    if key is None or len(key) == 0:
        raise ValueError("key cannot be null or empty")

    # Check the key size for AES-128
    if len(key) * 8 != KeySize:
        raise ValueError(f"Invalid key size. Expected {KeySize} bits, got {len(key) * 8} bits.")

    # Create a new instance of the Cipher class with the specified key and algorithm (AES in CBC mode)
    cipher = Cipher(algorithms.AES(key), modes.CBC(os.urandom(IVSize)))

    # Generate a new encryptor from the cipher
    encryptor = cipher.encryptor()

    # Pad the data to match the block size using PKCS#7 padding scheme
    padder = padding.PKCS7(BlockSize).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the data using the encryptor
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return the encrypted data with the initialization vector as a byte array
    return cipher.algorithm.mode.nonce + ciphertext

def Decrypt(data: bytes, key: bytes) -> bytes:
    # Check the input parameters for null values
    if data is None or len(data) == 0:
        raise ValueError("data cannot be null or empty")
    if key is None or len(key) == 0:
        raise ValueError("key cannot be null or empty")

    # Check the key size for AES-128
    if len(key) * 8 != KeySize:
        raise ValueError(f"Invalid key size. Expected {KeySize} bits, got {len(key) * 8} bits.")

    # Read the initialization vector from the data
    iv = data[:IVSize]

    # Create a new instance of the Cipher class with the specified key and algorithm (AES in CBC mode)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    # Generate a new decryptor from the cipher
    decryptor = cipher.decryptor()

    # Decrypt the data using the decryptor
    plaintext = decryptor.update(data[IVSize:]) + decryptor.finalize()

    # Unpad the data using PKCS#7 padding scheme
    unpadder = padding.PKCS7(BlockSize).unpadder()
    unpadded_data = unpadder.update(plaintext) + unpadder.finalize()

    # Return the decrypted data as a byte array
    return unpadded_data
