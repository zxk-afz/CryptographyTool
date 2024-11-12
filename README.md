# File Encryption and Decryption Tool (cryptography)

This Python script allows you to encrypt and decrypt files using your preferred encryption methods.

## Encryption Types/Methods
- **Fernet**: Symmetric encryption for secure file storage.
- **AES**: Advanced Encryption Standard, a widely-used symmetric encryption algorithm.

## Features
- Supports file encryption and decryption.
- User can select between different encryption methods (Fernet or AES).
- Handling of encryption and decryption processes.

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
1. **Run script**:
```bash
python file_encryptor.py
```
2. When **prompted**, enter:
- The full path of the file you want to encrypt or decrypt.
- The name of the file where the encrypted data will be saved (for encryption).
- The name of the file where the decrypted data will be saved (for decryption).
```bash
Enter the full path of the file to encrypt (e.g., 'file.txt'): file.txt
Enter the name of the file to save the encrypted data (e.g., 'file_encrypted.bin'): file_encrypted.bin
Enter the name of the file to save the decrypted data (e.g., 'file_decrypted.txt'): file_decrypted.txt
```
3. The script will automatically detect if the file is already encrypted. If it is encrypted, it will prompt the user to choose a decryption method (Fernet or AES).