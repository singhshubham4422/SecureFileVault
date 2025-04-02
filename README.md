# Secure File Encryption Application

A comprehensive web application for secure file encryption and decryption, offering multiple cryptographic algorithms with enhanced security features.

![screenshot](static/img/screenshot.png)

## Features

- **Multiple Encryption Algorithms**: AES-256, 3DES, RSA, and ECC
- **Symmetric Key Management**: Securely store and manage encryption keys
- **File Integrity Verification**: Checksums to verify file integrity
- **User Authentication**: Secure login with password hashing
- **Encryption History**: Track all encryption and decryption operations
- **Responsive UI**: Drag-and-drop interface with progress indicators
- **File Format Support**: Handles various file types including documents, images, and PDFs
- **Command-line Interface**: Additional CLI tool for automated operations

## Technologies Used

- **Backend**: Python 3 with Flask framework
- **Database**: SQLAlchemy with PostgreSQL
- **Encryption**: Cryptography and PyNaCl libraries
- **Frontend**: HTML5, CSS3, JavaScript with Bootstrap
- **Authentication**: Flask-Login and Werkzeug security
- **Form Validation**: Flask-WTF with CSRF protection

## Installation

### Prerequisites

- Python 3.8 or higher
- PostgreSQL database

### Setup

1. Clone the repository
```bash
git clone https://github.com/yourusername/secure-file-encryption-app.git
cd secure-file-encryption-app
```

2. Set up a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Configure environment variables
```bash
# Create a .env file with the following variables
FLASK_SECRET_KEY=your_secret_key
DATABASE_URL=postgresql://username:password@localhost/dbname
```

5. Initialize the database
```bash
flask db upgrade
```

6. Run the application
```bash
python main.py
```

The application will be available at `http://localhost:5000`

## Usage

### Web Interface

1. **Register/Login**: Create an account or log in to access the encryption features
2. **Upload File**: Drag and drop or select a file to encrypt
3. **Choose Algorithm**: Select your preferred encryption method
4. **Set Password/Key**: Enter a strong password or use asymmetric keys
5. **Download**: Securely download the encrypted file

### Command Line Interface

The application includes a command-line tool for encryption/decryption operations:

```bash
# Encrypt a file with AES-256
python cli_encrypt.py encrypt document.pdf document.pdf.enc --method aes

# Decrypt a file
python cli_encrypt.py decrypt document.pdf.enc document_decrypted.pdf --method aes

# Generate and use RSA keys
python cli_encrypt.py encrypt document.pdf document.pdf.enc --method rsa

# Decrypt with RSA private key
python cli_encrypt.py decrypt document.pdf.enc document_decrypted.pdf --method rsa --private-key rsa_private_key.pem
```

## Security Considerations

- All passwords are hashed using secure algorithms
- Files are processed in secure temporary locations
- Session data is encrypted and secure
- CSRF protection for all forms
- Encryption uses industry-standard algorithms and implementations
- Key derivation uses PBKDF2 with sufficient iterations

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## Examples

The `examples` directory contains sample scripts demonstrating how to use the encryption libraries programmatically:

```python
from crypto_utils import generate_salt, encrypt_file_aes, decrypt_file_aes

# Generate a random salt
salt = generate_salt()

# Encrypt a file
encrypt_file_aes("document.pdf", "document.pdf.enc", key, salt)

# Decrypt a file
decrypt_file_aes("document.pdf.enc", "document_decrypted.pdf", password)
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Cryptography](https://cryptography.io/) - Python library that provides cryptographic recipes
- [PyNaCl](https://pynacl.readthedocs.io/) - Python binding to the Networking and Cryptography library
- [Flask](https://flask.palletsprojects.com/) - Python web framework