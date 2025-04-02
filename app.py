import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, has_request_context
from werkzeug.utils import secure_filename
import tempfile
import uuid
from crypto_utils import (
    generate_salt, 
    derive_key_from_password, 
    encrypt_file_aes, 
    decrypt_file_aes,
    encrypt_file_3des,
    decrypt_file_3des,
    encrypt_file_rsa,
    decrypt_file_rsa,
    encrypt_file_ecc,
    decrypt_file_ecc,
    generate_rsa_keypair,
    generate_ecc_keypair
)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "secure-file-encryption-app")

# Configure upload settings
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar', 'py', 'js', 'html', 'css', 'csv'}
MAX_CONTENT_LENGTH = 20 * 1024 * 1024  # 20 MB max file size

# Temporary directory for file operations
TEMP_DIR = tempfile.gettempdir()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    # Clear any stored file paths when landing on the homepage
    if 'temp_file_path' in session:
        try:
            os.remove(session['temp_file_path'])
        except (OSError, FileNotFoundError):
            pass
        session.pop('temp_file_path', None)
        
    if 'output_file_path' in session:
        try:
            os.remove(session['output_file_path'])
        except (OSError, FileNotFoundError):
            pass
        session.pop('output_file_path', None)

    if 'encrypted_file_path' in session:
        try:
            os.remove(session['encrypted_file_path'])
        except (OSError, FileNotFoundError):
            pass
        session.pop('encrypted_file_path', None)
        
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    # Check if a file was uploaded
    if 'file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('index'))
    
    if not allowed_file(file.filename):
        flash(f'File type not allowed. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}', 'danger')
        return redirect(url_for('index'))
    
    # Get encryption parameters
    encryption_method = request.form.get('encryption_method')
    password = request.form.get('password')
    
    if not password and encryption_method in ['aes', '3des']:
        flash('Password is required for symmetric encryption', 'danger')
        return redirect(url_for('index'))
    
    try:
        # Save the uploaded file temporarily
        filename = secure_filename(file.filename)
        temp_file_path = os.path.join(TEMP_DIR, f"upload_{uuid.uuid4().hex}_{filename}")
        file.save(temp_file_path)
        
        # Store the path in the session for cleanup later
        session['temp_file_path'] = temp_file_path
        
        # Generate a unique output filename
        output_filename = f"encrypted_{uuid.uuid4().hex}_{filename}"
        output_file_path = os.path.join(TEMP_DIR, output_filename)
        
        # Perform encryption based on selected method
        if encryption_method == 'aes':
            salt = generate_salt()
            key = derive_key_from_password(password, salt)
            encrypt_file_aes(temp_file_path, output_file_path, key, salt)
            encryption_details = "AES-256 encryption"
            
        elif encryption_method == '3des':
            salt = generate_salt()
            key = derive_key_from_password(password, salt, key_length=24)  # 3DES uses a 24-byte key
            encrypt_file_3des(temp_file_path, output_file_path, key, salt)
            encryption_details = "3DES encryption"
            
        elif encryption_method == 'rsa':
            # For RSA, we'll generate a temporary keypair or use one uploaded by the user
            public_key, private_key = generate_rsa_keypair()
            encrypt_file_rsa(temp_file_path, output_file_path, public_key)
            
            # For RSA, we need to provide the private key to the user for decryption
            encryption_details = f"RSA encryption (Save this private key for decryption): {private_key.decode()}"
            
        elif encryption_method == 'ecc':
            # For ECC, also generate a temporary keypair
            public_key, private_key = generate_ecc_keypair()
            encrypt_file_ecc(temp_file_path, output_file_path, public_key)
            
            # For ECC, we need to provide the private key to the user for decryption
            encryption_details = f"ECC encryption (Save this private key for decryption): {private_key.hex()}"
        else:
            flash('Invalid encryption method selected', 'danger')
            return redirect(url_for('index'))
        
        # Store the output path in the session
        session['output_file_path'] = output_file_path
        session['encrypted_file_path'] = output_file_path
        session['encrypted_filename'] = output_filename
        session['encryption_details'] = encryption_details
        
        flash('File encrypted successfully!', 'success')
        return redirect(url_for('download_encrypted'))
        
    except Exception as e:
        logging.error(f"Encryption error: {str(e)}")
        flash(f'Error during encryption: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/download_encrypted')
def download_encrypted():
    if 'encrypted_file_path' not in session or 'encrypted_filename' not in session:
        flash('No encrypted file available for download', 'danger')
        return redirect(url_for('index'))
    
    file_path = session['encrypted_file_path']
    filename = session['encrypted_filename']
    encryption_details = session.get('encryption_details', 'File encrypted successfully')
    
    return render_template('index.html', encrypted_file=filename, encryption_details=encryption_details)

@app.route('/get_encrypted_file')
def get_encrypted_file():
    if 'encrypted_file_path' not in session or 'encrypted_filename' not in session:
        flash('No encrypted file available for download', 'danger')
        return redirect(url_for('index'))
    
    file_path = session['encrypted_file_path']
    filename = session['encrypted_filename']
    
    return send_file(file_path, as_attachment=True, download_name=filename)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    # Check if a file was uploaded
    if 'file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('index'))
    
    # Get decryption parameters
    decryption_method = request.form.get('decryption_method')
    password = request.form.get('password')
    private_key = request.form.get('private_key')
    
    if not password and decryption_method in ['aes', '3des']:
        flash('Password is required for symmetric decryption', 'danger')
        return redirect(url_for('index'))
    
    if not private_key and decryption_method in ['rsa', 'ecc']:
        flash('Private key is required for asymmetric decryption', 'danger')
        return redirect(url_for('index'))
    
    try:
        # Save the uploaded file temporarily
        filename = secure_filename(file.filename)
        temp_file_path = os.path.join(TEMP_DIR, f"upload_{uuid.uuid4().hex}_{filename}")
        file.save(temp_file_path)
        
        # Store the path in the session for cleanup later
        session['temp_file_path'] = temp_file_path
        
        # Generate a unique output filename
        # Remove 'encrypted_' prefix if present
        if filename.startswith('encrypted_'):
            output_filename = filename[len('encrypted_'):]
            # Remove the UUID portion (assuming UUID is 32 chars after encrypted_)
            if len(output_filename) > 33 and output_filename[32] == '_':
                output_filename = output_filename[33:]
        else:
            output_filename = f"decrypted_{filename}"
            
        output_file_path = os.path.join(TEMP_DIR, output_filename)
        
        # Perform decryption based on selected method
        if decryption_method == 'aes':
            decrypt_file_aes(temp_file_path, output_file_path, password)
            
        elif decryption_method == '3des':
            decrypt_file_3des(temp_file_path, output_file_path, password)
            
        elif decryption_method == 'rsa':
            decrypt_file_rsa(temp_file_path, output_file_path, private_key)
            
        elif decryption_method == 'ecc':
            decrypt_file_ecc(temp_file_path, output_file_path, private_key)
            
        else:
            flash('Invalid decryption method selected', 'danger')
            return redirect(url_for('index'))
        
        # Store the output path in the session
        session['output_file_path'] = output_file_path
        session['decrypted_file_path'] = output_file_path
        session['decrypted_filename'] = output_filename
        
        flash('File decrypted successfully!', 'success')
        return redirect(url_for('download_decrypted'))
        
    except Exception as e:
        logging.error(f"Decryption error: {str(e)}")
        flash(f'Error during decryption: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/download_decrypted')
def download_decrypted():
    if 'decrypted_file_path' not in session or 'decrypted_filename' not in session:
        flash('No decrypted file available for download', 'danger')
        return redirect(url_for('index'))
    
    file_path = session['decrypted_file_path']
    filename = session['decrypted_filename']
    
    return render_template('index.html', decrypted_file=filename)

@app.route('/get_decrypted_file')
def get_decrypted_file():
    if 'decrypted_file_path' not in session or 'decrypted_filename' not in session:
        flash('No decrypted file available for download', 'danger')
        return redirect(url_for('index'))
    
    file_path = session['decrypted_file_path']
    filename = session['decrypted_filename']
    
    return send_file(file_path, as_attachment=True, download_name=filename)

@app.errorhandler(413)
def request_entity_too_large(error):
    flash(f'File too large. Maximum size is {MAX_CONTENT_LENGTH/(1024*1024)} MB', 'danger')
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(error):
    flash('Page not found', 'danger')
    return redirect(url_for('index'))

@app.errorhandler(500)
def server_error(error):
    flash('Server error occurred', 'danger')
    return redirect(url_for('index'))

# Clean up temporary files when the application shuts down
@app.teardown_request
def cleanup_temp_files(exception):
    # Only attempt to clean up files if we're in a request context
    if has_request_context():
        for key in ['temp_file_path', 'output_file_path', 'encrypted_file_path', 'decrypted_file_path']:
            if key in session:
                try:
                    os.remove(session[key])
                except (OSError, FileNotFoundError):
                    pass
