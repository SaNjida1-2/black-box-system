import hashlib
import json
import base64

# --- ECC CURVE CONFIGURATION (Lab Specification) ---
CURVE_A = 2
CURVE_B = 3
CURVE_P = 9739 # Prime modulus for the curve points
G = (3, 6)     # Base Point

# --- CHARACTER ENCODING CONFIGURATION ---
# Use 65521 (a prime) to ensure the multiplier 123 is ALWAYS invertible
CHAR_MODULUS = 65521 

def point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return None
    try:
        if x1 == x2:
            m = (3 * x1**2 + CURVE_A) * pow(2 * y1, -1, CURVE_P)
        else:
            m = (y2 - y1) * pow(x2 - x1, -1, CURVE_P)
        x3 = (m**2 - x1 - x2) % CURVE_P
        y3 = (m * (x1 - x3) - y1) % CURVE_P
        return (x3, y3)
    except ValueError:
        return None

def point_mult(k, P):
    R = None
    while k > 0:
        if k % 2 == 1:
            R = point_add(R, P)
        P = point_add(P, P)
        k //= 2
    return R

def generate_ecc_keys():
    """Generates a static pair for lab consistency."""
    priv_key = 123 
    pub_key = point_mult(priv_key, G)
    return pub_key, priv_key

def ecc_encrypt(message, pub_key):
    """
    Encrypts message using: (ord(char) * 123 + shift) % CHAR_MODULUS
    """
    shift = pub_key[0] if isinstance(pub_key, tuple) else 0
    encrypted_list = [(ord(char) * 123 + shift) % CHAR_MODULUS for char in message]
    
    # Pack into SECURE_V3 format
    json_data = json.dumps(encrypted_list)
    b64_data = base64.b64encode(json_data.encode()).decode()
    return f"SECURE_V3:{b64_data}"

def ecc_decrypt(ciphertext, priv_key):
    """
    Decrypts message using modular inverse of 123 over CHAR_MODULUS.
    """
    if not ciphertext.startswith("SECURE_V3:"):
        return ciphertext
    
    try:
        # Extract and Decode
        b64_data = ciphertext.split(":", 1)[1]
        json_data = base64.b64decode(b64_data).decode()
        encrypted_list = json.loads(json_data)
        
        # Derive shift from private key
        pub_key = point_mult(priv_key, G)
        shift = pub_key[0]
        
        # Calculate modular inverse of the multiplier (123)
        # This only works because CHAR_MODULUS is prime
        inv_123 = pow(123, -1, CHAR_MODULUS)
        
        # Reverse the math
        decrypted_chars = [
            chr(((val - shift) % CHAR_MODULUS) * inv_123 % CHAR_MODULUS) 
            for val in encrypted_list
        ]
        return "".join(decrypted_chars)
    except Exception as e:
        # Graceful error handling for the UI
        return f"[Decryption Error]"

def generate_hmac(message, key="blackbox_secret_key"):
    """Creates SHA-256 signature for data integrity."""
    h = hashlib.sha256()
    h.update(key.encode())
    h.update(message.encode())
    return h.hexdigest()

def verify_hmac(message, mac, key="blackbox_secret_key"):
    """Verifies that the data has not been tampered with."""
    if not mac: return False
    return generate_hmac(message, key) == mac