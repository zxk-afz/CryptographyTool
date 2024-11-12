from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.fernet import Fernet
import os

def is_encrypted(file_path):
    try:
        with open(file_path, 'rb') as file:
            first_bytes = file.read(4)  # Read the first bytes
            # Check if the first few bytes indicate encryption
            return first_bytes != b'PKCS'  # Check headers
    except Exception as e:
        print(f"Error checking file: {e}")
        return False

# AES encryption
def encrypt_AES(file_path, key):
    iv = os.urandom(16)  # Size (128 bits)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    # "rb" = read binary (just for your knowledge)
    with open(file_path, 'rb') as file:
        data = file.read()

    # Padder ensure that data is encrypted in blocks (e.g., 13 bytes string replaced with a 16 bytes string) 
    # (REMOVED WHEN DECRYPTED)
    pad_length = 16 - len(file_data) % 16
    file_data += bytes([pad_length]) * pad_length
    
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    with open(file_path + '.encrypted', 'wb') as file:
        file.write(iv + encrypted_data) 
    print(f"File encrypted as {file_path}.encrypted")

# AES decryption
def decrypt_AES(file_path, key):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    iv = file_data[:16] # IV
    encrypted_data = file_data[16:] # Encrypted data

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # REMOVE PADDING
    pad_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-pad_length]

    with open(file_path + '.decrypted', 'wb') as file:
        file.write(decrypted_data)
    print(f"File decrypted as {file_path}.decrypted")

# Fernet encryption (way easier than AES encryption)
def encrypt_Fernet(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        data = file.read()

    # Padder included in Fernet ;)
    encrypted_data = fernet.encrypt(data)

    with open(file_path + '.encrypted', 'wb') as file:
        file.write(encrypted_data)
    print(f"File encrypted as {file_path}.encrypted")

# Fernet decryption
def decrypt_Fernet(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(file_path + '.decrypted', 'wb') as file:
            file.write(decrypted_data)
        print(f"File decrypted as {file_path}.decrypted")
    except Exception as e:
        print(f"Decryption failed: {e}")

# Main logic
def main():
    file_path = input("Enter the full path of the file: ")

    if not os.path.exists(file_path):
        print("File does not exist :(")
        return

    if is_encrypted(file_path):
        print("This file appears to be encrypted.")
        method = input("Choose decryption method (Fernet or AES): ").lower()

        if method == "fernet":
            key = input("Enter the Fernet key for decryption: ")
            try:
                decrypt_Fernet(file_path, key.encode())
            except Exception as e:
                print(f"Error during decryption: {e}")
        elif method == "aes":
            key = input("Enter the AES key for decryption (16, 24, or 32 bytes): ").encode()
            try:
                decrypt_AES(file_path, key)
            except Exception as e:
                print(f"Error during decryption: {e}")
        else:
            print("Invalid method selected.")
    else:
        print("This file is not encrypted.")
        action = input("Do you want to encrypt the file? (y/n): ").lower()

        if action == "y" | "yes":
            method = input("Choose encryption method (Fernet or AES): ").lower()

            if method == "fernet":
                key = input("Enter a Fernet key for encryption (or generate one using Fernet.generate_key()): ").encode()
                try:
                    encrypt_Fernet(file_path, key)
                except Exception as e:
                    print(f"Error during encryption: {e}")
            elif method == "aes":
                key = input("Enter the AES key for encryption (16, 24, or 32 bytes): ").encode()
                try:
                    encrypt_AES(file_path, key)
                except Exception as e:
                    print(f"Error during encryption: {e}")
            else:
                print("Invalid method selected.")
        elif action == "no" | 'n':
            print("File was not encrypted.")
        else:
            print("Invalid input.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram was cancelled")
