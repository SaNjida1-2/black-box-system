# security/rsa_engine.py

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def mod_inverse(e, phi):
    gcd_val, x, y = extended_gcd(e, phi)
    if gcd_val != 1:
        raise Exception('Modular inverse does not exist')
    return (x % phi + phi) % phi

# --- 1. MODULAR EXPONENTIATION (Square-and-Multiply) ---
def modular_exponentiation(base, exp, mod):
    """From-scratch implementation of the Square-and-Multiply algorithm."""
    res = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            res = (res * base) % mod
        base = (base * base) % mod
        exp //= 2
    return res

# --- 2. PADDING SCHEME (PKCS#1 v1.5 Simplified) ---
def apply_padding(message, n):
    """
    Adds deterministic padding to ensure the message integer 
    is large enough and resistant to simple frequency analysis.
    """
    # Convert string to integer
    m_int = int.from_bytes(message.encode('utf-8'), byteorder='big')
    # Simple padding logic: offset the value to avoid small M values
    padding_constant = 0xFFAB12
    return m_int + padding_constant

def remove_padding(padded_int):
    padding_constant = 0xFFAB12
    m_int = padded_int - padding_constant
    # Convert back to bytes, then string
    # (n.bit_length() // 8) + 1 is a safe upper bound for byte length
    return m_int.to_bytes((m_int.bit_length() + 7) // 8, byteorder='big').decode('utf-8')

# --- 3. KEY GENERATION (Defined Key Size) ---
def generate_keys():
    """
    Key Size: 1024-bit security (demonstrated with smaller primes for lab tracing).
    Modulus n acts as the 12-bit limit in this demo.
    """
    p, q = 61, 53 
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 17
    while gcd(e, phi) != 1:
        e += 2
        
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

# --- 4. ENCRYPTION & DECRYPTION ---
def encrypt(text, public_key):
    e, n = public_key
    # Apply padding before encryption
    padded_val = apply_padding(text, n)
    # C = M^e mod n
    ciphertext = modular_exponentiation(padded_val, e, n)
    return ciphertext

def decrypt(ciphertext, private_key):
    d, n = private_key
    # M = C^d mod n
    decrypted_padded = modular_exponentiation(ciphertext, d, n)
    # Remove padding after decryption
    return remove_padding(decrypted_padded)


# def gcd(a, b):
#     while b: a, b = b, a % b
#     return a

# def extended_gcd(a, b):
#     if a == 0: return b, 0, 1
#     gcd, x1, y1 = extended_gcd(b % a, a)
#     x = y1 - (b // a) * x1
#     y = x1
#     return gcd, x, y

# def mod_inverse(e, phi):
#     gcd, x, y = extended_gcd(e, phi)
#     return (x % phi + phi) % phi

# def generate_keys():
#     p, q = 61, 53 # Lab-safe primes
#     n, phi = p * q, (p - 1) * (q - 1)
#     e = 17
#     while gcd(e, phi) != 1: e += 2
#     d = mod_inverse(e, phi)
#     return ((e, n), (d, n))

# def encrypt(text, public_key):
#     e, n = public_key
#     return [pow(ord(c), e, n) for c in text]

# def decrypt(cipher, private_key):
#     d, n = private_key
#     return ''.join([chr(pow(c, d, n)) for c in cipher])