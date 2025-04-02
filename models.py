from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    
    # Relationships
    encryption_history = db.relationship('EncryptionHistory', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def __repr__(self):
        return f'<User {self.username}>'
        
class EncryptionHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=True)
    encryption_method = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    operation_type = db.Column(db.String(20), nullable=False)  # 'encrypt' or 'decrypt'
    file_size = db.Column(db.Integer, nullable=True)  # Size in bytes
    file_hash = db.Column(db.String(64), nullable=True)  # SHA-256 hash for integrity check
    
    def __repr__(self):
        return f'<EncryptionHistory {self.original_filename} - {self.operation_type}>'
        
class EncryptionKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    key_name = db.Column(db.String(64), nullable=False)
    key_type = db.Column(db.String(20), nullable=False)  # 'rsa', 'ecc', etc.
    public_key = db.Column(db.Text, nullable=True)
    private_key = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<EncryptionKey {self.key_name} - {self.key_type}>'