import random
import hashlib

# Utility Functions

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a
 
def generate_large_prime(bits):
    """Generates a large prime number."""
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num

def is_prime(n, k=5):  # Miller-Rabin test
    """Checks if a number is prime."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def modular_inverse(a, m):
    """Finds modular inverse of a under modulo m."""
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1