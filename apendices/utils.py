import secrets
from typing import Tuple


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Calculates gcd using extended Euclidean algorithm
    >>> extended_gcd(240, 46)
    (2, -9, 47)
    """
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def modular_inverse(a: int, n: int) -> int:
    """Calculates modular inverse of a mod n, i.e x such that ax = 1 (mod n)
    >>> modular_inverse(77, 5)
    3
    >>> modular_inverse(55, 7)
    6
    >>> modular_inverse(5, 10)
    Traceback (most recent call last):
        ...
    ValueError: 5 is not relatively prime to 10
    """
    g, x, _ = extended_gcd(a, n)
    if g != 1:
        raise ValueError(f'{a} is not relatively prime to {n}')
    return x % n


def is_probable_prime(n: int, k: int = 100) -> bool:
    """Tests whether n is a probable prime with Miller-Rabin primality test
    >>> is_probable_prime(93)
    False
    >>> is_probable_prime(104789)
    True
    >>> is_probable_prime(15485943)
    False
    >>> is_probable_prime(32416190071)
    True
    """
    if n == 2:  # pragma: no cover
        return True

    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = secrets.randbelow(n - 1) + 1
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r):
            x = pow(x, 2, n)
            if x == 1:
                return False
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(length: int) -> int:
    '''Generates primes of length bits

    >>> p = generate_prime(32)
    >>> p.bit_length()
    32

    p is prime, i.e. not divisible by any numbers up to sqrt(p)

    >>> all(p % n != 0 for n in range(3, 2 ** 16, 2))
    True
    '''
    while True:
        p = (2 ** (length - 1)) | secrets.randbits(length - 1) | 1
        if is_probable_prime(p):
            return p


def generate_safe_prime(length: int) -> int:
    '''Generates safe primes of at least `length` bits

    >>> p, q = generate_safe_prime(32)
    >>> p.bit_length() in [32, 33]
    True
    >>> q.bit_length() in [31, 32]
    True

    p is safe prime, i.e. in the form 2q+1 where q is a prime number

    >>> all(p % n != 0 for n in range(3, 2 ** 17, 2))
    True
    >>> all(q % n != 0 for n in range(3, 2 ** 16, 2))
    True
    '''
    while True:
        p = generate_prime(length)

        # p1 = 2 * p + 1
        p1 = (p << 1) | 1
        if is_probable_prime(p1):
            return p1, p

        # p1 = (p - 1) // 2
        p1 = p >> 1
        if is_probable_prime(p1):
            return p, p1


def eval_poly(poly, x):
    '''
    >>> poly = [4, 3, 2]
    >>> eval_poly(poly, 0)
    4
    >>> eval_poly(poly, 5)
    69
    '''
    return sum(f * x ** i for i, f in enumerate(poly))
