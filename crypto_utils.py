import os
import hmac
import hashlib
import base64
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box

# Constants
SALT_SIZE = 16  # 128 bits
IV_SIZE = 16    # 128 bits
TAG_SIZE = 16   # 128 bits
KEY_ITERATIONS = 100000  # High number of iterations for key derivation
CHUNK_SIZE = 64 * 1024  # 64KB chunks for file processing

def generate_salt():
    """Generate a random salt for key derivation."""
    return os.urandom(SALT_SIZE)

def derive_key_from_password(password, salt, key_length=32):
    """
    Derive a key from a password and salt using PBKDF2.
    Default key_length is 32 bytes (256 bits) for AES-256.
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=KEY_ITERATIONS
    )
    key = kdf.derive(password)
    return key

# AES Encryption and Decryption
def encrypt_file_aes(input_path, output_path, key, salt):
    """
    Encrypt a file using AES-256-GCM.
    Stores salt, IV, and authentication tag with the ciphertext.
    """
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(IV_SIZE)
    
    # Initialize the cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    
    # Prepare the output file format:
    # [salt (16 bytes)][iv (16 bytes)][ciphertext][tag (16 bytes)]
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        # Write the salt and IV at the beginning of the file
        f_out.write(salt)
        f_out.write(iv)
        
        # Encrypt file in chunks
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break
            encrypted_chunk = encryptor.update(chunk)
            f_out.write(encrypted_chunk)
        
        # Finalize encryption and write the authentication tag
        encrypted_final = encryptor.finalize()
        f_out.write(encrypted_final)
        f_out.write(encryptor.tag)

def decrypt_file_aes(input_path, output_path, password):
    """
    Decrypt a file that was encrypted with AES-256-GCM.
    Reads salt, IV, and authentication tag from the file.
    """
    with open(input_path, 'rb') as f_in:
        # Read the salt and IV from the beginning of the file
        salt = f_in.read(SALT_SIZE)
        iv = f_in.read(IV_SIZE)
        
        # Derive the key from the password and salt
        key = derive_key_from_password(password, salt)
        
        # Read the ciphertext (excluding the tag)
        ciphertext = f_in.read()
        
        # The last 16 bytes are the tag
        tag = ciphertext[-TAG_SIZE:]
        ciphertext = ciphertext[:-TAG_SIZE]
        
        # Initialize the cipher for decryption
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        
        # Decrypt to the output file
        with open(output_path, 'wb') as f_out:
            # Process the ciphertext in chunks
            chunk_size = CHUNK_SIZE + 16  # Ciphertext will be slightly larger due to padding
            offset = 0
            
            while offset < len(ciphertext):
                chunk = ciphertext[offset:offset + chunk_size]
                offset += chunk_size
                
                decrypted_chunk = decryptor.update(chunk)
                f_out.write(decrypted_chunk)
            
            # Finalize decryption
            decrypted_final = decryptor.finalize()
            f_out.write(decrypted_final)

# 3DES Encryption and Decryption
def encrypt_file_3des(input_path, output_path, key, salt):
    """
    Encrypt a file using 3DES (Triple DES) in CBC mode.
    Stores salt and IV with the ciphertext.
    """
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(8)  # 3DES uses 8-byte IV
    
    # Initialize the cipher
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Prepare the padder
    padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
    
    # Prepare the output file format:
    # [salt (16 bytes)][iv (8 bytes)][ciphertext]
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        # Write the salt and IV at the beginning of the file
        f_out.write(salt)
        f_out.write(iv)
        
        # Encrypt file in chunks
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break
            
            # Pad only the last chunk
            if len(chunk) < CHUNK_SIZE:
                padded_chunk = padder.update(chunk) + padder.finalize()
                encrypted_chunk = encryptor.update(padded_chunk)
            else:
                encrypted_chunk = encryptor.update(chunk)
            
            f_out.write(encrypted_chunk)
        
        # Finalize encryption if there's any remaining data
        if len(chunk) == CHUNK_SIZE:
            # If the last chunk was full-sized, we need to add a padding block
            padded_chunk = padder.update(b'') + padder.finalize()
            encrypted_final = encryptor.update(padded_chunk) + encryptor.finalize()
            f_out.write(encrypted_final)
        else:
            # The last chunk was already padded
            encrypted_final = encryptor.finalize()
            f_out.write(encrypted_final)

def decrypt_file_3des(input_path, output_path, password):
    """
    Decrypt a file that was encrypted with 3DES in CBC mode.
    Reads salt and IV from the file.
    """
    with open(input_path, 'rb') as f_in:
        # Read the salt and IV from the beginning of the file
        salt = f_in.read(SALT_SIZE)
        iv = f_in.read(8)  # 3DES uses 8-byte IV
        
        # Derive the key from the password and salt
        key = derive_key_from_password(password, salt, key_length=24)  # 3DES uses 24-byte key
        
        # Read the ciphertext
        ciphertext = f_in.read()
        
        # Initialize the cipher for decryption
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        # Prepare the unpadder
        unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
        
        # Decrypt to the output file
        with open(output_path, 'wb') as f_out:
            # Process the ciphertext in chunks
            chunk_size = CHUNK_SIZE + 8  # Ciphertext may be slightly larger due to padding
            offset = 0
            chunks = []
            
            while offset < len(ciphertext):
                chunk = ciphertext[offset:offset + chunk_size]
                offset += chunk_size
                
                decrypted_chunk = decryptor.update(chunk)
                chunks.append(decrypted_chunk)
            
            # Finalize decryption
            decrypted_final = decryptor.finalize()
            if decrypted_final:
                chunks.append(decrypted_final)
            
            # Handle unpadding (only for the last chunk)
            if chunks:
                # Unpad the last chunk
                chunks[-1] = unpadder.update(chunks[-1])
                try:
                    chunks.append(unpadder.finalize())
                except ValueError:
                    # This might happen if padding is corrupted
                    pass
            
            # Write all chunks to the output file
            for chunk in chunks:
                f_out.write(chunk)

# RSA Encryption and Decryption
def generate_rsa_keypair():
    """Generate an RSA key pair and return public and private keys in PEM format."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Serialize the keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    return public_pem, private_pem

def encrypt_file_rsa(input_path, output_path, public_key_pem):
    """
    Encrypt a file using RSA with a hybrid approach (AES for data, RSA for the AES key).
    Only small files can be encrypted directly with RSA due to size limitations.
    """
    # Load the public key
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode('utf-8')
    public_key = load_pem_public_key(public_key_pem)
    
    # Generate a random AES key for the actual file encryption
    aes_key = os.urandom(32)  # 256-bit AES key
    iv = os.urandom(16)
    
    # Encrypt the AES key with RSA
    encrypted_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Prepare the output file format:
    # [encrypted_key_length (4 bytes)][encrypted_key][iv (16 bytes)][aes_encrypted_data]
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        # Write the encrypted key length and the encrypted key
        key_length = len(encrypted_key)
        f_out.write(struct.pack('<I', key_length))
        f_out.write(encrypted_key)
        
        # Write the IV
        f_out.write(iv)
        
        # Initialize AES cipher
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Prepare the padder
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        
        # Encrypt file in chunks
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break
            
            # Pad only the last chunk
            if len(chunk) < CHUNK_SIZE:
                padded_chunk = padder.update(chunk) + padder.finalize()
                encrypted_chunk = encryptor.update(padded_chunk)
            else:
                encrypted_chunk = encryptor.update(chunk)
            
            f_out.write(encrypted_chunk)
        
        # Finalize encryption if there's any remaining data
        if len(chunk) == CHUNK_SIZE:
            # If the last chunk was full-sized, we need to add a padding block
            padded_chunk = padder.update(b'') + padder.finalize()
            encrypted_final = encryptor.update(padded_chunk) + encryptor.finalize()
            f_out.write(encrypted_final)
        else:
            # The last chunk was already padded
            encrypted_final = encryptor.finalize()
            f_out.write(encrypted_final)

def decrypt_file_rsa(input_path, output_path, private_key_pem):
    """
    Decrypt a file that was encrypted using the RSA hybrid approach.
    """
    # Load the private key
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode('utf-8')
    
    try:
        private_key = load_pem_private_key(private_key_pem, password=None)
    except Exception as e:
        raise ValueError(f"Invalid private key: {str(e)}")
    
    with open(input_path, 'rb') as f_in:
        # Read the encrypted key length
        key_length_bytes = f_in.read(4)
        key_length = struct.unpack('<I', key_length_bytes)[0]
        
        # Read the encrypted AES key
        encrypted_key = f_in.read(key_length)
        
        # Read the IV
        iv = f_in.read(16)
        
        # Read the encrypted data
        ciphertext = f_in.read()
        
        # Decrypt the AES key with RSA
        try:
            aes_key = private_key.decrypt(
                encrypted_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            raise ValueError(f"Failed to decrypt the file key: {str(e)}")
        
        # Initialize AES cipher for decryption
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        # Prepare the unpadder
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        
        # Decrypt to the output file
        with open(output_path, 'wb') as f_out:
            # Process the ciphertext in chunks
            chunk_size = CHUNK_SIZE + 16  # Ciphertext may be slightly larger due to padding
            offset = 0
            chunks = []
            
            while offset < len(ciphertext):
                chunk = ciphertext[offset:offset + chunk_size]
                offset += chunk_size
                
                decrypted_chunk = decryptor.update(chunk)
                chunks.append(decrypted_chunk)
            
            # Finalize decryption
            decrypted_final = decryptor.finalize()
            if decrypted_final:
                chunks.append(decrypted_final)
            
            # Handle unpadding (only for the last chunk)
            if chunks:
                # Combine all chunks except the last one
                for chunk in chunks[:-1]:
                    f_out.write(chunk)
                
                # Unpad the last chunk
                last_chunk = chunks[-1]
                try:
                    unpadded = unpadder.update(last_chunk) + unpadder.finalize()
                    f_out.write(unpadded)
                except ValueError:
                    # If unpadding fails, write the raw chunk
                    f_out.write(last_chunk)

# ECC Encryption and Decryption
def generate_ecc_keypair():
    """Generate an ECC key pair using NaCl/libsodium's Curve25519."""
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    
    # Return the keys in bytes form
    return bytes(public_key), bytes(private_key)

def encrypt_file_ecc(input_path, output_path, public_key_bytes):
    """
    Encrypt a file using ECC with a hybrid approach (XSalsa20-Poly1305 for data, Curve25519 for key exchange).
    """
    # Convert public key bytes to nacl PublicKey
    if isinstance(public_key_bytes, str):
        # Assume it's a hex string
        public_key_bytes = bytes.fromhex(public_key_bytes)
    elif not isinstance(public_key_bytes, bytes):
        public_key_bytes = bytes(public_key_bytes)
    
    receiver_public_key = PublicKey(public_key_bytes)
    
    # Generate a sender keypair
    sender_private_key = PrivateKey.generate()
    sender_public_key = sender_private_key.public_key
    
    # Create an encrypted box
    box = Box(sender_private_key, receiver_public_key)
    
    # Generate a random nonce
    nonce = nacl.utils.random(Box.NONCE_SIZE)
    
    # Prepare the output file format:
    # [sender_public_key (32 bytes)][nonce (24 bytes)][encrypted_data]
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        # Write the sender's public key
        f_out.write(bytes(sender_public_key))
        
        # Write the nonce
        f_out.write(nonce)
        
        # Read and encrypt the file in chunks
        # Since Box.encrypt adds authentication data, we'll read the whole file
        # For larger files, we'd need to implement chunked encryption with our own authentication
        plaintext = f_in.read()
        encrypted = box.encrypt(plaintext, nonce)[Box.NONCE_SIZE:]  # Remove nonce from output
        
        # Write the encrypted data
        f_out.write(encrypted)

def decrypt_file_ecc(input_path, output_path, private_key_str):
    """
    Decrypt a file that was encrypted using the ECC hybrid approach.
    """
    # Convert private key string to bytes
    if isinstance(private_key_str, str):
        # Assume it's a hex string
        private_key_bytes = bytes.fromhex(private_key_str)
    else:
        private_key_bytes = bytes(private_key_str)
    
    try:
        receiver_private_key = PrivateKey(private_key_bytes)
    except Exception as e:
        raise ValueError(f"Invalid private key: {str(e)}")
    
    with open(input_path, 'rb') as f_in:
        # Read the sender's public key
        sender_public_key_bytes = f_in.read(32)
        sender_public_key = PublicKey(sender_public_key_bytes)
        
        # Read the nonce
        nonce = f_in.read(Box.NONCE_SIZE)
        
        # Read the encrypted data
        ciphertext = f_in.read()
        
        # Create a decryption box
        box = Box(receiver_private_key, sender_public_key)
        
        # Decrypt the data
        try:
            plaintext = box.decrypt(ciphertext, nonce)
        except Exception as e:
            raise ValueError(f"Failed to decrypt the file: {str(e)}")
        
        # Write the decrypted data to the output file
        with open(output_path, 'wb') as f_out:
            f_out.write(plaintext)
