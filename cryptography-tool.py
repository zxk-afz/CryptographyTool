import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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

# Function to check if the file is encrypted
def is_encrypted(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read(64)  # Read the first 64 bytes
            
            # Calculate entropy
            entropy = calculate_entropy(file_data)
            
            # If the entropy = above threshold, it's encrypted
            if entropy > 4.0:
                return True
            else:
                return False
    except Exception as e:
        print(f"Error checking file: {e}")
        return False

# Function to generate a Fernet key
def generate_fernet_key():
    return Fernet.generate_key()

# Fernet encryption
def encrypt_fernet(file_path):
    key = generate_fernet_key()
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        file_data = file.read()

    encrypted_data = fernet.encrypt(file_data)

    # Create the encrypted filename
    encrypted_filename = "encrypted-" + os.path.basename(file_path)
    with open(encrypted_filename, 'wb') as file:
        file.write(encrypted_data)

    # Save the key for later decryption
    key_filename = "key-" + os.path.basename(file_path)
    with open(key_filename, 'wb') as key_file:
        key_file.write(key)

    print(f"File encrypted as {encrypted_filename}")
    print(f"Key saved as {key_filename}")

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

# Function to generate a random AES key (supports 16, 24, or 32 bytes)
def generate_aes_key(key_size=32):
    return os.urandom(key_size)

# AES encryption
def encrypt_aes(file_path, key_size=32):
    key = generate_aes_key(key_size)
    iv = os.urandom(16) 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as file:
        file_data = file.read()

    # Padder ensure that data is encrypted in blocks (e.g., 13 bytes string replaced with a 16 bytes string) 
    # (REMOVED WHEN DECRYPTED)
    pad_length = 16 - len(file_data) % 16
    padded_data = file_data + bytes([pad_length]) * pad_length

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Create the encrypted filename
    encrypted_filename = "encrypted-" + os.path.basename(file_path)
    with open(encrypted_filename, 'wb') as file:
        file.write(iv + encrypted_data)

    # Save the key for later decryption
    key_filename = "key-" + os.path.basename(file_path)
    with open(key_filename, 'wb') as key_file:
        key_file.write(key)

    print(f"File encrypted as {encrypted_filename}")
    print(f"Key saved as {key_filename}")

# Function for AES decryption
def decrypt_aes(file_path, key):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    iv = file_data[:16]
    encrypted_data = file_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
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
                # Automatically generate a key if not provided
                encrypt_fernet(file_path)
            elif method == "aes":
                # Prompt for AES key size, default to 32 bytes if not provided
                key_size = int(prompt_input("Enter AES key size (16, 24, or 32 bytes): "))
                encrypt_aes(file_path, key_size=key_size)
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
