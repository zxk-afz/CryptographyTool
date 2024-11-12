from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import math
# Function to calculate entropy
def calculate_entropy(data):
    byte_freq = [0] * 256
    for byte in data:
        byte_freq[byte] += 1
    
    entropy = 0.0
    for freq in byte_freq:
        if freq > 0:
            prob = freq / len(data)
            entropy -= prob * math.log2(prob)
    
    return entropy

# Function to check if the file is likely encrypted
def is_encrypted(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read(64)  # Read the first 64 bytes
            
            # Calculate entropy
            entropy = calculate_entropy(file_data)
            
            # If the entropy is above threshold , it's likely encrypted
            if entropy > 4.0:
                return True
            else:
                return False
    except Exception as e:
        print(f"Error checking file: {e}")
        return False

# Fernet encryption
def encrypt_fernet(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(file_path + '.encrypted', 'wb') as file:
        file.write(encrypted_data)
    print(f"File encrypted as {file_path}.encrypted")

# Fernet decryption
def decrypt_fernet(file_path, key):
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

# AES encryption
def encrypt_aes(file_path, key):
    iv = os.urandom(16)  # AES block size (128 bits)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Padder ensure that data is encrypted in blocks (e.g., 13 bytes string replaced with a 16 bytes string) 
    # (REMOVED WHEN DECRYPTED)
    pad_length = 16 - len(file_data) % 16
    file_data += bytes([pad_length]) * pad_length
    
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    with open(file_path + '.encrypted', 'wb') as file:
        file.write(iv + encrypted_data)
    print(f"File encrypted as {file_path}.encrypted")

# Function for AES decryption
def decrypt_aes(file_path, key):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    iv = file_data[:16]
    encrypted_data = file_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # REMOVE PADDING
    pad_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-pad_length]

    with open(file_path + '.decrypted', 'wb') as file:
        file.write(decrypted_data)
    print(f"File decrypted as {file_path}.decrypted")

# Prompt for input with retries
def prompt_input(prompt, required=True):
    while True:
        user_input = input(prompt)
        if user_input or not required:
            return user_input
        else:
            print("Input is required. Please try again.")

# Main 
def main():
    file_path = prompt_input("Enter the full path of the file: ")

    if not os.path.exists(file_path):
        print("File does not exist.")
        return

    if is_encrypted(file_path):
        print("This file appears to be encrypted.")
        method = prompt_input("Choose decryption method (Fernet or AES): ").lower()

        if method == "fernet":
            key_input = prompt_input("Enter the Fernet key for decryption: ")
            try:
                decrypt_fernet(file_path, key_input.encode())
            except Exception as e:
                print(f"Error during decryption: {e}")
        elif method == "aes":
            key_input = prompt_input("Enter the AES key for decryption (16, 24, or 32 bytes): ").encode()
            try:
                decrypt_aes(file_path, key_input)
            except Exception as e:
                print(f"Error during decryption: {e}")
        else:
            print("Invalid method selected.")
    else:
        print("This file is not encrypted.")
        action = prompt_input("Do you want to encrypt the file? (yes/no): ").lower()

        if action == "yes":
            method = prompt_input("Choose encryption method (Fernet or AES): ").lower()

            if method == "fernet":
                key_input = prompt_input("Enter a Fernet key for encryption (or generate one using Fernet.generate_key()): ").encode()
                try:
                    encrypt_fernet(file_path, key_input)
                except Exception as e:
                    print(f"Error during encryption: {e}")
            elif method == "aes":
                key_input = prompt_input("Enter the AES key for encryption (16, 24, or 32 bytes): ").encode()
                try:
                    encrypt_aes(file_path, key_input)
                except Exception as e:
                    print(f"Error during encryption: {e}")
            else:
                print("Invalid method selected.")
        elif action == "no":
            print("File was not encrypted and will not be processed.")
        else:
            print("Invalid input.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram was cancelled")
