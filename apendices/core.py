from dataclasses import dataclass
from typing import List, Tuple

from swartz.paillier import PublicKey


@dataclass
class Election:
    votes: List[int]


@dataclass
class Vote:
    ciphers: Tuple[int, ...]
    public_key: PublicKey

    def __add__(self, other):
        assert len(self.ciphers) == len(other.ciphers)
        assert self.public_key == other.public_key
        ciphers = tuple(
            (x * y) % (self.public_key.n ** 2)
            for x, y in zip(self.ciphers, other.ciphers)
        )
        return Vote(ciphers, self.public_key)
