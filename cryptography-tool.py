from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.fernet import Fernet
import os

# Generate AES key (32 bytes - AES-256 | 16 bytes - AES-128)
def generate_AES_key():
    return os.urandom(32)

# Generate Frenet key
def generate_Fernet_key():
    return Fernet.generate_key()

# AES encryption
def encrypt_AES(input_file, output_file, key):
    # "rb" = read binary (just for your knowledge)
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

    # "wb" = write binary
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

# Frenet encryption (way easier than AES encryption)
def encrypt_Frenet(input_file, output_file, key):
    with open(input_file, 'rb') as file:
        data = file.read()
    
    # Padder included in Frenet ;) (Je pense)
    frenet = Fernet(key)
    encrypted_data = frenet.encrypt(data)

    with open(output_file, 'wb') as file:
        file.write(encrypted_data)

# Frenet decryption
def decrypt_Frenet(input_file, output_file, key):
    with open(input_file, "rb") as file:
        encrypted_data = file.read()
    
    frenet = Fernet(key)
    decrypted_data = frenet.decrypt(encrypted_data)

    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

# main function
def main():
    # Select encryption type
    type = input("Choose encryption type (1 for AES, 2 for Frenet): ")

    # type
    if type == "1":
        key = generate_AES_key()
        print("Selected AES encryption method")

        input_filename = input("Enter the full path of the file to encrypt (e.g., 'file.txt'): ")
        encrypted_filename = input("Enter the name of the file to save the encrypted data (e.g., 'file_encrypted.bin'): ")
        decrypted_filename = input("Enter the name of the file to save the decrypted data (e.g., 'file_decrypted.txt'): ")

        # Encrypt AES
        encrypt_AES(input_filename, encrypted_filename, key)
        print("Encryption complete.")
        
        # Decrypt Frenet
        decrypt_AES(encrypted_filename, decrypted_filename, key)
        print("Decryption complete.")
    
    elif type == "2":
        key = generate_Fernet_key()
        print("Selected Frenet encryption method")

        input_filename = input("Enter the full path of the file to encrypt (e.g., 'file.txt'): ")
        encrypted_filename = input("Enter the name of the file to save the encrypted data (e.g., 'file_encrypted.bin'): ")
        decrypted_filename = input("Enter the name of the file to save the decrypted data (e.g., 'file_decrypted.txt'): ")

        # Encrypt Frenet
        encrypt_Frenet(input_filename, encrypted_filename, key)
        print("Encryption complete.")

        # Decrypt Frenet
        decrypt_AES(encrypted_filename, decrypted_filename, key)
        print("Decryption complete.")
    
    else:       
        print("Invalid! Please write 1 for AES or 2 for Fernet.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram was cancelled :(")
