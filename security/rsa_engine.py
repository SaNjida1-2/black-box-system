def gcd(a, b):
    while b: a, b = b, a % b
    return a

def extended_gcd(a, b):
    if a == 0: return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e, phi):
    gcd, x, y = extended_gcd(e, phi)
    return (x % phi + phi) % phi

def generate_keys():
    p, q = 61, 53 # Lab-safe primes
    n, phi = p * q, (p - 1) * (q - 1)
    e = 17
    while gcd(e, phi) != 1: e += 2
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt(text, public_key):
    e, n = public_key
    return [pow(ord(c), e, n) for c in text]

def decrypt(cipher, private_key):
    d, n = private_key
    return ''.join([chr(pow(c, d, n)) for c in cipher])