#!/usr/bin/env python3
"""
Command-line interface for file encryption and decryption.
This tool provides a simple command-line interface for the file encryption functionality.
"""

import os
import sys
import argparse
import getpass
from datetime import datetime

from crypto_utils import (
    generate_salt,
    derive_key_from_password,
    encrypt_file_aes,
    decrypt_file_aes,
    encrypt_file_3des,
    decrypt_file_3des,
    generate_rsa_keypair,
    encrypt_file_rsa,
    decrypt_file_rsa,
    generate_ecc_keypair,
    encrypt_file_ecc,
    decrypt_file_ecc
)

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file for integrity verification."""
    import hashlib
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read the file in chunks to handle large files efficiently
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def encrypt_file(args):
    """Encrypt a file using the specified method."""
    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found.")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(args.output)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Calculate file hash for integrity verification
    file_hash = calculate_file_hash(args.input)
    print(f"File hash (SHA-256): {file_hash}")
    
    # Handle different encryption methods
    try:
        if args.method in ['aes', '3des']:
            # Symmetric encryption - need password
            if args.password:
                password = args.password
            else:
                password = getpass.getpass("Enter encryption password: ")
                confirm_password = getpass.getpass("Confirm encryption password: ")
                if password != confirm_password:
                    print("Error: Passwords do not match.")
                    sys.exit(1)
            
            # Generate salt and derive key
            salt = generate_salt()
            
            if args.method == 'aes':
                key = derive_key_from_password(password, salt)
                encrypt_file_aes(args.input, args.output, key, salt)
                print(f"File encrypted with AES-256 and saved to {args.output}")
            else:  # 3DES
                key = derive_key_from_password(password, salt, key_length=24)
                encrypt_file_3des(args.input, args.output, key, salt)
                print(f"File encrypted with 3DES and saved to {args.output}")
            
            print("Keep your password safe! You will need it to decrypt the file.")
        
        elif args.method == 'rsa':
            # RSA asymmetric encryption
            if args.public_key:
                # Use provided public key
                with open(args.public_key, 'rb') as f:
                    public_key = f.read()
                encrypt_file_rsa(args.input, args.output, public_key)
                print(f"File encrypted with RSA using provided public key and saved to {args.output}")
            else:
                # Generate a new key pair
                public_key, private_key = generate_rsa_keypair()
                encrypt_file_rsa(args.input, args.output, public_key)
                
                # Save the keys to files
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                private_key_file = f"rsa_private_key_{timestamp}.pem"
                public_key_file = f"rsa_public_key_{timestamp}.pem"
                
                with open(private_key_file, 'wb') as f:
                    f.write(private_key)
                with open(public_key_file, 'wb') as f:
                    f.write(public_key)
                
                print(f"File encrypted with RSA and saved to {args.output}")
                print(f"New RSA key pair generated:")
                print(f" - Private key saved to {private_key_file}")
                print(f" - Public key saved to {public_key_file}")
                print("IMPORTANT: Keep the private key secure! You will need it to decrypt the file.")
        
        elif args.method == 'ecc':
            # ECC asymmetric encryption
            if args.public_key:
                # Use provided public key
                with open(args.public_key, 'rb') as f:
                    public_key = f.read()
                    # Convert hex string to bytes if necessary
                    if isinstance(public_key, bytes) and public_key.startswith(b'-----'):
                        public_key = bytes.fromhex(public_key.decode().strip())
                encrypt_file_ecc(args.input, args.output, public_key)
                print(f"File encrypted with ECC using provided public key and saved to {args.output}")
            else:
                # Generate a new key pair
                public_key, private_key = generate_ecc_keypair()
                encrypt_file_ecc(args.input, args.output, public_key)
                
                # Save the keys to files
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                private_key_file = f"ecc_private_key_{timestamp}.hex"
                public_key_file = f"ecc_public_key_{timestamp}.hex"
                
                with open(private_key_file, 'w') as f:
                    f.write(private_key.hex())
                with open(public_key_file, 'w') as f:
                    f.write(public_key.hex())
                
                print(f"File encrypted with ECC and saved to {args.output}")
                print(f"New ECC key pair generated:")
                print(f" - Private key saved to {private_key_file}")
                print(f" - Public key saved to {public_key_file}")
                print("IMPORTANT: Keep the private key secure! You will need it to decrypt the file.")
        
        else:
            print(f"Error: Unknown encryption method '{args.method}'")
            sys.exit(1)
        
        # Print file size
        encrypted_size = os.path.getsize(args.output)
        original_size = os.path.getsize(args.input)
        print(f"Original file size: {original_size} bytes")
        print(f"Encrypted file size: {encrypted_size} bytes")
        
    except Exception as e:
        print(f"Error during encryption: {str(e)}")
        sys.exit(1)

def decrypt_file(args):
    """Decrypt a file using the specified method."""
    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found.")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(args.output)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Handle different decryption methods
    try:
        if args.method in ['aes', '3des']:
            # Symmetric decryption - need password
            if args.password:
                password = args.password
            else:
                password = getpass.getpass("Enter decryption password: ")
            
            if args.method == 'aes':
                decrypt_file_aes(args.input, args.output, password)
                print(f"File decrypted with AES-256 and saved to {args.output}")
            else:  # 3DES
                decrypt_file_3des(args.input, args.output, password)
                print(f"File decrypted with 3DES and saved to {args.output}")
        
        elif args.method == 'rsa':
            # RSA asymmetric decryption - need private key
            if not args.private_key:
                print("Error: RSA decryption requires a private key file.")
                sys.exit(1)
            
            with open(args.private_key, 'rb') as f:
                private_key = f.read()
            
            decrypt_file_rsa(args.input, args.output, private_key)
            print(f"File decrypted with RSA and saved to {args.output}")
        
        elif args.method == 'ecc':
            # ECC asymmetric decryption - need private key
            if not args.private_key:
                print("Error: ECC decryption requires a private key file.")
                sys.exit(1)
            
            with open(args.private_key, 'r') as f:
                private_key_hex = f.read().strip()
            
            decrypt_file_ecc(args.input, args.output, private_key_hex)
            print(f"File decrypted with ECC and saved to {args.output}")
        
        else:
            print(f"Error: Unknown decryption method '{args.method}'")
            sys.exit(1)
        
        # Calculate file hash for integrity verification
        file_hash = calculate_file_hash(args.output)
        print(f"Decrypted file hash (SHA-256): {file_hash}")
        
        # Print file size
        decrypted_size = os.path.getsize(args.output)
        encrypted_size = os.path.getsize(args.input)
        print(f"Encrypted file size: {encrypted_size} bytes")
        print(f"Decrypted file size: {decrypted_size} bytes")
        
    except Exception as e:
        print(f"Error during decryption: {str(e)}")
        sys.exit(1)

def main():
    """Main function to parse command-line arguments and call the appropriate functions."""
    parser = argparse.ArgumentParser(
        description="Command-line tool for file encryption and decryption"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Parser for the 'encrypt' command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("input", help="Path to the file to encrypt")
    encrypt_parser.add_argument("output", help="Path where to save the encrypted file")
    encrypt_parser.add_argument(
        "--method", "-m",
        choices=["aes", "3des", "rsa", "ecc"],
        default="aes",
        help="Encryption method to use (default: aes)"
    )
    encrypt_parser.add_argument(
        "--password", "-p",
        help="Password for symmetric encryption (if not provided, will be prompted)"
    )
    encrypt_parser.add_argument(
        "--public-key",
        help="Path to public key file for asymmetric encryption"
    )
    
    # Parser for the 'decrypt' command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("input", help="Path to the encrypted file")
    decrypt_parser.add_argument("output", help="Path where to save the decrypted file")
    decrypt_parser.add_argument(
        "--method", "-m",
        choices=["aes", "3des", "rsa", "ecc"],
        default="aes",
        help="Decryption method to use (default: aes)"
    )
    decrypt_parser.add_argument(
        "--password", "-p",
        help="Password for symmetric decryption (if not provided, will be prompted)"
    )
    decrypt_parser.add_argument(
        "--private-key",
        help="Path to private key file for asymmetric decryption"
    )
    
    args = parser.parse_args()
    
    if args.command == "encrypt":
        encrypt_file(args)
    elif args.command == "decrypt":
        decrypt_file(args)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()