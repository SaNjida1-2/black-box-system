# security/hash_engine.py
# security/hash_engine.py
import hashlib

def hash_password(password):
    # If password is None or empty, return an empty string instead of crashing
    if not password:
        return ""
        
    salt = "static_lab_salt_123"
    # Force 'password' to be a string just in case
    salted_pass = str(password) + salt 
    return hashlib.sha256(salted_pass.encode()).hexdigest()