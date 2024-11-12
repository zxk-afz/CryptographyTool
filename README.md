# File Encryption and Decryption Tool (cryptography)

This Python script allows you to encrypt and decrypt files using your preferred encryption methods.

## Encryption Types/Methods
- **Fernet**: Symmetric encryption for secure file storage.
- **AES**: Advanced Encryption Standard, a widely-used symmetric encryption algorithm.


## Features

- **Entropy Calculation**: Determines if a file is likely encrypted based on its entropy value (Shannon entropy).
- **Fernet Encryption**: Encrypt files with Fernet symmetric encryption.
- **AES Encryption**: Encrypt files using AES with CBC mode (supporting key sizes of 16, 24, or 32 bytes).
- **Encryption Key Management**: Saves the generated encryption keys for later decryption.
- **Decryption**: Decrypt files using the saved keys (for both Fernet and AES encryption).

## Requirements
- Python 3.x
- `cryptography` library (for encryption)

## Installation
1. **Clone** or download the repository.
2. **Install** the Python dependencie:
```bash
pip install cryptography
```

## Usage

### Encrypt a File
1. Run the script.
2. Enter the full path of the file you want to encrypt.
3. Choose whether to encrypt using **Fernet** or **AES**.
4. If using **AES**, select the key size (16, 24, or 32 bytes).

The tool will create a new file prefixed with `encrypted-` and save the encryption key in a separate file with the prefix `key-`.

### Decrypt a File
1. Run the script.
2. Enter the full path of the encrypted file.
3. Choose whether to decrypt using **Fernet** or **AES**.
4. Enter the encryption key when prompted.

The tool will create a new file with the `.decrypted` suffix.

## Example

```bash
Enter the full path of the file: /home/user/file.txt
This file is not encrypted.
Do you want to encrypt the file? (yes/no): yes
Choose encryption method (Fernet or AES): Fernet
File encrypted as encrypted-file.txt
Key saved as key-file.txt
```