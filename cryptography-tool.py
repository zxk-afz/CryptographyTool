from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.fernet import Fernet
import os

# Generate AES key (32 bytes - AES-256)
def generate_AES_key():
    return os.urandom(32)

# AES encryption
def encrypt_AES(input_file, output_file, key):
    with open(input_file, 'rb') as file:
        data = file.read()

    # generate random iv
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.cbc(iv), backend=default_backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, 'wb') as file:
        file.write(iv + encrypted_data)