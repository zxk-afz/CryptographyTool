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

    # Generate random iv
    iv = os.urandom(16)

    # Padder ensure that data is encrypted in blocks (e.g., 13 bytes string replaced with a 16 bytes string) 
    # (REMOVED WHEN DECRYPTED)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.cbc(iv), backend=default_backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, 'wb') as file:
        file.write(iv + encrypted_data)

# AES decryption
def decrypt_AES(input_file, output_file, key):
    with open(input_file, 'rb') as file:
        iv = file.read(16)
        encrypted_data = file.read()
    
    cipher = Cipher(algorithms.AES(key), modes.cbc(iv), backend=default_backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) = decryptor.finalize() 

    # REMOVE THE PADDING
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(decrypted_data) + unpadder.finalize()

    with open(output_file, 'wb') as file:
        file.write(data)