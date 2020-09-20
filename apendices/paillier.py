import functools
import math
import operator
import secrets
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

from swartz.utils import (eval_poly, generate_prime, generate_safe_prime,
                          modular_inverse)

DEFAULT_KEYSIZE = 2048


@dataclass
class PublicKey:
    n: int

    @property
    def g(self):
        return self.n + 1

    def encrypt(self, message: int) -> int:
        n, g = self.n, self.g
        r = choose_multiplicative_inverse(n)
        mod = n ** 2
        return (pow(g, message, mod) * pow(r, n, mod)) % mod


@dataclass
class PrivateKey:
    n: int
    λ: int
    µ: int

    def decrypt(self, cipher: int) -> int:
        n, λ, µ = self.n, self.λ, self.µ
        return ((pow(cipher, λ, n ** 2) - 1) // n * µ) % n


class KeyPair:
    def __init__(self, public_key: PublicKey, private_key: PrivateKey):
        assert public_key.n == private_key.n
        self.public_key = public_key
        self.private_key = private_key

    def decrypt(self, cipher: int) -> int:
        return self.private_key.decrypt(cipher)

    def encrypt(self, cipher: int) -> int:
        return self.public_key.encrypt(cipher)


def generate_keypair(length: int = DEFAULT_KEYSIZE) -> KeyPair:
    p, q = generate_prime(length // 2), generate_prime(length // 2)

    n = p * q
    λ = (p - 1) * (q - 1)
    µ = modular_inverse(λ, n)
    return KeyPair(PublicKey(n), PrivateKey(n, λ, µ))


@dataclass
class ThresholdPublicKey:
    g: int
    n: int
    v: int
    θ: int

    def encrypt(self, message: int) -> int:
        n, g = self.n, self.g
        r = secrets.randbelow(n - 1) + 1
        mod = n ** 2
        return (pow(g, message, mod) * pow(r, n, mod)) % mod


def choose_multiplicative_inverse(n):
    '''
    >>> p = generate_prime(128)
    >>> q = generate_prime(128)
    >>> x = choose_multiplicative_inverse(p * q)
    >>> math.gcd(x, p * q)
    1
    '''
    while True:
        x = secrets.randbelow(n - 1) + 1
        if math.gcd(x, n) == 1:
            return x


@dataclass
class Share:
    id: int
    value: int

    def __hash__(self):
        return hash((self.id, self.value))

    def __iter__(self):
        yield self.id
        yield self.value


def generate_shares(secret, params, nλ) -> List[int]:
    threshold, servers = params.threshold, params.servers
    poly = [secret, *(secrets.randbelow(nλ) for _ in range(threshold - 1))]
    for i in range(1, servers + 1):
        yield Share(i, eval_poly(poly, i) % nλ)


RSAModulus = Tuple[int, int, int, int]


def generate_rsa_modulus(length: int) -> RSAModulus:
    '''
    >>> p, p1, q, q1 = generate_rsa_modulus(128)
    >>> p == 2 * p1 + 1
    True
    >>> q == 2 * q1 + 1
    True
    >>> (p - 1) * (q - 1) == 4 * p1 * q1
    True
    '''
    p, p1 = generate_safe_prime(length // 2)
    q, q1 = generate_safe_prime(length // 2)
    while p1 == q1:
        q, q1 = generate_safe_prime(length // 2)
    return p, p1, q, q1


@dataclass
class Params:
    threshold: int
    servers: int

    @property
    def Δ(self):
        return math.factorial(self.servers)


def generate_key(
        modulus: RSAModulus, params: Params, length: int = DEFAULT_KEYSIZE
) -> Tuple[ThresholdPublicKey, Dict[int, int], Dict[int, int]]:
    p, p1, q, q1 = modulus

    n = p * q

    n_squared = n * n

    # fouque
    λ = 4 * p1 * q1
    print('λ =', λ)
    assert math.gcd(λ, n) == 1

    β = choose_multiplicative_inverse(n)
    print('β =', β)

    m = p1 * q1
    secret_key = β * m

    a = choose_multiplicative_inverse(n)
    b = choose_multiplicative_inverse(n)
    g = (pow(1 + n, a, n_squared) * pow(b, n, n_squared)) % n_squared
    assert math.gcd(a, n) == 1
    assert math.gcd(b, n) == 1
    assert math.gcd(g, n_squared) == 1
    print('a =', a, '\nb =', b, '\ng =', g)


    while True:
        v = pow(secrets.randbelow(n), 2)
        if math.gcd(v, n_squared) == 1:
            break

    publ = ThresholdPublicKey(g, n, v, (a * secret_key) % n)

    # secret_key = β * λ
    shares = [*generate_shares(secret_key, params, n * m)]

    Δ = math.factorial(params.servers)
    vks = [(i, pow(v, Δ * s, n_squared)) for i, s in shares]

    return publ, vks, shares


@dataclass
class Decryption:
    id: int
    value: int
    proof: int

    def __hash__(self):
        return hash((self.id, self.value, self.proof))

    def __lt__(self, rhs):
        return (self.id, self.value) < (rhs.id, rhs.value)


def share_decryption(cipher, share: Share, key, params):
    n, v = key.n, key.v
    i, value = share

    n_squared = n * n
    c = pow(cipher, 2 * math.factorial(params.servers) * value, n_squared)
    proof = pow(v, value, n_squared)
    return Decryption(i, c, proof)


def combine(shares: Set[Decryption], key, params: Params) -> int:
    n, θ = key.n, key.θ
    n_squared = n * n

    threshold, Δ = params.threshold, params.Δ
    c = 1

    shares = sorted(shares[:threshold])
    for i in shares:
        µ = Δ

        for j in shares:
            if i is j:
                continue

            if i.id == j.id:
                raise ValueError('Two shares with same ID')

            µ *= j.id // (j.id - i.id)

        if µ < 0:
            c = pow(modular_inverse(i.value, n_squared), 2 * -µ, n_squared)
        else:
            c *= pow(i.value, 2 * µ, n_squared)
        c %= n_squared
        print('c =', c)

    return ((c - 1) // n * modular_inverse(4 * Δ * Δ * θ, n)) % n
