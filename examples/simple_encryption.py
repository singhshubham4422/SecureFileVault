#!/usr/bin/env python3
"""
Simple Example: How to encrypt and decrypt a file using the crypto_utils module
This standalone script demonstrates basic usage of the encryption utilities.
"""

import os
import sys
import getpass

# Add the parent directory to path so we can import our modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_utils import (
    generate_salt,
    derive_key_from_password,
    encrypt_file_aes,
    decrypt_file_aes,
    generate_rsa_keypair,
    encrypt_file_rsa,
    decrypt_file_rsa
)

def encrypt_file_with_password(input_file, output_file):
    """Encrypt a file using AES-256 with a password."""
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        return
    
    # Get password from user
    password = getpass.getpass("Enter encryption password: ")
    confirm_password = getpass.getpass("Confirm encryption password: ")
    
    if password != confirm_password:
        print("Error: Passwords do not match.")
        return
    
    try:
        # Generate a random salt
        salt = generate_salt()
        
        # Derive encryption key from password
        key = derive_key_from_password(password, salt)
        
        # Encrypt the file
        encrypt_file_aes(input_file, output_file, key, salt)
        
        print(f"File successfully encrypted and saved to {output_file}")
        print("Keep your password safe! You will need it to decrypt the file.")
    except Exception as e:
        print(f"Error during encryption: {str(e)}")

def decrypt_file_with_password(input_file, output_file):
    """Decrypt a file that was encrypted with AES-256 and a password."""
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        return
    
    # Get password from user
    password = getpass.getpass("Enter decryption password: ")
    
    try:
        # Decrypt the file (salt is stored in the encrypted file)
        decrypt_file_aes(input_file, output_file, password)
        
        print(f"File successfully decrypted and saved to {output_file}")
    except Exception as e:
        print(f"Error during decryption: {str(e)}")
        print("This could be due to an incorrect password or a corrupted file.")

def encrypt_file_with_rsa(input_file, output_file):
    """Encrypt a file using RSA asymmetric encryption."""
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        return
    
    try:
        # Generate RSA key pair
        public_key, private_key = generate_rsa_keypair()
        
        # Encrypt the file with the public key
        encrypt_file_rsa(input_file, output_file, public_key)
        
        # Save the private key to a file
        private_key_file = f"{output_file}.key"
        with open(private_key_file, 'wb') as f:
            f.write(private_key)
        
        print(f"File successfully encrypted and saved to {output_file}")
        print(f"Private key saved to {private_key_file}")
        print("IMPORTANT: Keep this private key secure! You will need it to decrypt the file.")
    except Exception as e:
        print(f"Error during encryption: {str(e)}")

def decrypt_file_with_rsa(input_file, output_file, private_key_file):
    """Decrypt a file that was encrypted with RSA."""
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        return
    
    if not os.path.exists(private_key_file):
        print(f"Error: Private key file '{private_key_file}' not found.")
        return
    
    try:
        # Read the private key from file
        with open(private_key_file, 'rb') as f:
            private_key = f.read()
        
        # Decrypt the file
        decrypt_file_rsa(input_file, output_file, private_key)
        
        print(f"File successfully decrypted and saved to {output_file}")
    except Exception as e:
        print(f"Error during decryption: {str(e)}")

def print_menu():
    """Print the menu options."""
    print("\n===== File Encryption Example =====")
    print("1. Encrypt file with password (AES-256)")
    print("2. Decrypt file with password (AES-256)")
    print("3. Encrypt file with RSA")
    print("4. Decrypt file with RSA")
    print("5. Exit")
    return input("Enter your choice (1-5): ")

def main():
    """Main function to run the example."""
    print("Welcome to the File Encryption Example!")
    print("This script demonstrates how to use the crypto_utils module to encrypt and decrypt files.")
    
    while True:
        choice = print_menu()
        
        if choice == '1':
            input_file = input("Enter the path to the file to encrypt: ")
            output_file = input("Enter the path for the encrypted file: ")
            encrypt_file_with_password(input_file, output_file)
        
        elif choice == '2':
            input_file = input("Enter the path to the encrypted file: ")
            output_file = input("Enter the path for the decrypted file: ")
            decrypt_file_with_password(input_file, output_file)
        
        elif choice == '3':
            input_file = input("Enter the path to the file to encrypt: ")
            output_file = input("Enter the path for the encrypted file: ")
            encrypt_file_with_rsa(input_file, output_file)
        
        elif choice == '4':
            input_file = input("Enter the path to the encrypted file: ")
            output_file = input("Enter the path for the decrypted file: ")
            private_key_file = input("Enter the path to the private key file: ")
            decrypt_file_with_rsa(input_file, output_file, private_key_file)
        
        elif choice == '5':
            print("Thank you for using the File Encryption Example. Goodbye!")
            break
        
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")

if __name__ == "__main__":
    main()