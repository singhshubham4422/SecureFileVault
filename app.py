import os
import logging
import hashlib
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, has_request_context
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
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
from models import db, User, EncryptionHistory, EncryptionKey

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "secure-file-encryption-app")

# Configure session to be more secure and persistent
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_USE_SIGNER'] = True

# Configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Configure upload settings
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}
MAX_CONTENT_LENGTH = 20 * 1024 * 1024  # 20 MB max file size

# Create a secure temporary directory for file uploads
TEMP_DIR = os.path.join(tempfile.gettempdir(), 'secure_file_encryption')
os.makedirs(TEMP_DIR, exist_ok=True)

# Create database tables
with app.app_context():
    db.create_all()
    
def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file for integrity verification."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read the file in chunks to handle large files efficiently
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    # Redirect to login page if user is not authenticated
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # Only clean up files if we're not in the middle of a file download or on a download page
    if not session.get('downloading') and not session.get('on_download_page'):
        logging.debug("Index route - cleaning up old files")
        # Clear any stored file paths when landing on the homepage
        for key in ['temp_file_path', 'output_file_path', 'encrypted_file_path', 'decrypted_file_path']:
            if key in session:
                try:
                    path = session[key]
                    if os.path.exists(path):
                        logging.info(f"Cleaning up file from index route: {path}")
                        os.remove(path)
                    session.pop(key, None)
                except (OSError, FileNotFoundError) as e:
                    logging.error(f"Error clearing file {key} from index: {str(e)}")
                    
        # Also clear any stale flags
        session.pop('on_download_page', None)
    else:
        logging.debug("Index route - skipping cleanup due to active download or download page")
        
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
@login_required
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
        
        # Calculate file size and hash for integrity verification
        file_size = os.path.getsize(temp_file_path)
        file_hash = calculate_file_hash(temp_file_path)
        
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
            
            # If user is logged in, store the key in the database
            if current_user.is_authenticated:
                key_entry = EncryptionKey(
                    user_id=current_user.id,
                    key_name=f"RSA-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    key_type='rsa',
                    public_key=public_key.decode(),
                    private_key=private_key.decode(),
                )
                db.session.add(key_entry)
                db.session.commit()
            
        elif encryption_method == 'ecc':
            # For ECC, also generate a temporary keypair
            public_key, private_key = generate_ecc_keypair()
            encrypt_file_ecc(temp_file_path, output_file_path, public_key)
            
            # For ECC, we need to provide the private key to the user for decryption
            encryption_details = f"ECC encryption (Save this private key for decryption): {private_key.hex()}"
            
            # If user is logged in, store the key in the database
            if current_user.is_authenticated:
                key_entry = EncryptionKey(
                    user_id=current_user.id,
                    key_name=f"ECC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    key_type='ecc',
                    public_key=public_key.hex(),
                    private_key=private_key.hex(),
                )
                db.session.add(key_entry)
                db.session.commit()
                
        else:
            flash('Invalid encryption method selected', 'danger')
            return redirect(url_for('index'))
        
        # Store the output path in the session
        session['output_file_path'] = output_file_path
        session['encrypted_file_path'] = output_file_path
        session['encrypted_filename'] = output_filename
        session['encryption_details'] = encryption_details
        
        # Log what we're storing in the session
        logging.info(f"Stored in session - path: {output_file_path}, filename: {output_filename}")
        logging.info(f"Session now contains keys: {list(session.keys())}")
        
        # Save encryption history to database
        encrypted_file_size = os.path.getsize(output_file_path)
        
        # Create a new encryption history record
        history_entry = EncryptionHistory(
            user_id=current_user.id if current_user.is_authenticated else None,
            original_filename=filename,
            encrypted_filename=output_filename,
            encryption_method=encryption_method,
            operation_type='encrypt',
            file_size=file_size,
            file_hash=file_hash
        )
        db.session.add(history_entry)
        db.session.commit()
        
        flash('File encrypted successfully!', 'success')
        return redirect(url_for('download_encrypted'))
        
    except Exception as e:
        logging.error(f"Encryption error: {str(e)}")
        flash(f'Error during encryption: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/download_encrypted')
def download_encrypted():
    logging.debug("Session keys: %s", list(session.keys()))
    
    if 'encrypted_file_path' not in session or 'encrypted_filename' not in session:
        logging.error("Missing encrypted file information in session")
        flash('No encrypted file available for download', 'danger')
        return redirect(url_for('index'))
    
    file_path = session['encrypted_file_path']
    filename = session['encrypted_filename']
    encryption_details = session.get('encryption_details', 'File encrypted successfully')
    
    logging.info(f"Showing download page for: {file_path} as {filename}")
    
    # Mark that we're on the download page to prevent cleanup
    session['on_download_page'] = True
    
    # Verify the file exists
    if not os.path.exists(file_path):
        logging.error(f"File does not exist at path: {file_path}")
        session.pop('on_download_page', None)
        flash('Encrypted file not found on server', 'danger')
        return redirect(url_for('index'))
        
    # Return the download page with the file information
    return render_template('index.html', encrypted_file=filename, encryption_details=encryption_details)

@app.route('/get_encrypted_file')
def get_encrypted_file():
    logging.debug(f"Download encrypted file - Session keys: {list(session.keys())}")
    
    if 'encrypted_file_path' not in session or 'encrypted_filename' not in session:
        logging.error("Missing encrypted file path or filename in session during download")
        flash('No encrypted file available for download', 'danger')
        return redirect(url_for('index'))
    
    file_path = session['encrypted_file_path']
    filename = session['encrypted_filename']
    
    # Flag that we're in the process of downloading - don't delete the file
    session['downloading'] = True
    
    # Check if file exists before sending
    if not os.path.exists(file_path):
        logging.error(f"Encrypted file not found at path: {file_path}")
        session.pop('downloading', None)
        flash('Encrypted file not found on server', 'danger')
        return redirect(url_for('index'))
        
    try:
        logging.info(f"Attempting to send file: {file_path} as {filename}")
        response = send_file(file_path, as_attachment=True, download_name=filename)
        
        # Add a callback to clear the downloading flag when the response is closed
        @response.call_on_close
        def on_close():
            logging.info("Download encrypted file response closed, removing download flag")
            session.pop('downloading', None)
            
        return response
    except Exception as e:
        logging.error(f"Error sending file: {str(e)}")
        session.pop('downloading', None)
        flash(f'Error downloading file: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/decrypt', methods=['POST'])
@login_required
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
        
        # Calculate file size and hash for integrity verification
        file_size = os.path.getsize(temp_file_path)
        file_hash = calculate_file_hash(temp_file_path)
        
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
        
        # Log what we're storing in the session
        logging.info(f"Stored in session for decryption - path: {output_file_path}, filename: {output_filename}")
        logging.info(f"Session now contains keys: {list(session.keys())}")
        
        # Save decryption history to database
        decrypted_file_size = os.path.getsize(output_file_path)
        decrypted_file_hash = calculate_file_hash(output_file_path)
        
        # Create a new decryption history record
        history_entry = EncryptionHistory(
            user_id=current_user.id if current_user.is_authenticated else None,
            original_filename=filename,
            encrypted_filename=output_filename,
            encryption_method=decryption_method,
            operation_type='decrypt',
            file_size=decrypted_file_size,
            file_hash=decrypted_file_hash
        )
        db.session.add(history_entry)
        db.session.commit()
        
        flash('File decrypted successfully!', 'success')
        return redirect(url_for('download_decrypted'))
        
    except Exception as e:
        logging.error(f"Decryption error: {str(e)}")
        flash(f'Error during decryption: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/download_decrypted')
def download_decrypted():
    logging.debug("Session keys for decryption: %s", list(session.keys()))
    
    if 'decrypted_file_path' not in session or 'decrypted_filename' not in session:
        logging.error("Missing decrypted file information in session")
        flash('No decrypted file available for download', 'danger')
        return redirect(url_for('index'))
    
    file_path = session['decrypted_file_path']
    filename = session['decrypted_filename']
    
    logging.info(f"Showing decrypted download page for: {file_path} as {filename}")
    
    # Mark that we're on the download page to prevent cleanup
    session['on_download_page'] = True
    
    # Verify the file exists
    if not os.path.exists(file_path):
        logging.error(f"Decrypted file does not exist at path: {file_path}")
        session.pop('on_download_page', None)
        flash('Decrypted file not found on server', 'danger')
        return redirect(url_for('index'))
    
    return render_template('index.html', decrypted_file=filename)

@app.route('/get_decrypted_file')
def get_decrypted_file():
    logging.debug(f"Download decrypted file - Session keys: {list(session.keys())}")
    
    if 'decrypted_file_path' not in session or 'decrypted_filename' not in session:
        logging.error("Missing decrypted file path or filename in session during download")
        flash('No decrypted file available for download', 'danger')
        return redirect(url_for('index'))
    
    file_path = session['decrypted_file_path']
    filename = session['decrypted_filename']
    
    # Flag that we're in the process of downloading - don't delete the file
    session['downloading'] = True
    
    # Check if file exists before sending
    if not os.path.exists(file_path):
        logging.error(f"Decrypted file not found at path: {file_path}")
        session.pop('downloading', None)
        flash('Decrypted file not found on server', 'danger')
        return redirect(url_for('index'))
        
    try:
        logging.info(f"Attempting to send decrypted file: {file_path} as {filename}")
        response = send_file(file_path, as_attachment=True, download_name=filename)
        
        # Add a callback to clear the downloading flag when the response is closed
        @response.call_on_close
        def on_close():
            logging.info("Download decrypted file response closed, removing download flag")
            session.pop('downloading', None)
            
        return response
    except Exception as e:
        logging.error(f"Error sending decrypted file: {str(e)}")
        session.pop('downloading', None)
        flash(f'Error downloading file: {str(e)}', 'danger')
        return redirect(url_for('index'))

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

# User authentication and management routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
            
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('register.html')
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return render_template('register.html')
            
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = 'remember' in request.form
        
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('login.html')
            
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            flash('Invalid username or password', 'danger')
            return render_template('login.html')
            
        login_user(user, remember=remember)
        flash('Logged in successfully!', 'success')
        
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('index')
            
        return redirect(next_page)
        
    return render_template('login.html')
    
@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))
    
@app.route('/history')
@login_required
def encryption_history():
    """Display user's encryption/decryption history."""
    history = EncryptionHistory.query.filter_by(user_id=current_user.id).order_by(EncryptionHistory.timestamp.desc()).all()
    return render_template('history.html', history=history)
    
@app.route('/keys')
@login_required
def encryption_keys():
    """Display user's stored encryption keys."""
    keys = EncryptionKey.query.filter_by(user_id=current_user.id).order_by(EncryptionKey.created_at.desc()).all()
    return render_template('keys.html', keys=keys)

# Clean up temporary files only when necessary
@app.route('/clear_files')
def clear_files():
    """Explicitly clear temporary files"""
    if has_request_context():
        # Don't clean if we're in the middle of a download or on download page
        if session.get('downloading'):
            flash('Cannot clear files while a download is in progress', 'warning')
            return redirect(url_for('index'))
        
        if session.get('on_download_page'):
            flash('Cannot clear files while on download page', 'warning')
            return redirect(url_for('index'))
            
        for key in ['temp_file_path', 'output_file_path', 'encrypted_file_path', 'decrypted_file_path']:
            if key in session:
                try:
                    path = session[key]
                    if os.path.exists(path):
                        logging.info(f"Removing file: {path}")
                        os.remove(path)
                    else:
                        logging.warning(f"File not found when clearing: {path}")
                    session.pop(key, None)
                except (OSError, FileNotFoundError) as e:
                    logging.error(f"Error clearing file {key}: {str(e)}")
        
        # Clear any leftover flags
        session.pop('downloading', None)
        session.pop('on_download_page', None)
        flash('Temporary files cleared', 'info')
    return redirect(url_for('index'))
