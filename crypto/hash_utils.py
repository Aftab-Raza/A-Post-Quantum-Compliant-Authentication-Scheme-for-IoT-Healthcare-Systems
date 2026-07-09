"""
hash_utils.py
Provides SHA3 hashing functions used throughout the SKEBA protocol.
"""

import hashlib


def sha3_256(data: str) -> str:
    """
    Returns SHA3-256 hash of a string.
    """
    return hashlib.sha3_256(data.encode()).hexdigest()


def sha3_512(data: str) -> str:
    """
    Returns SHA3-512 hash of a string.
    """
    return hashlib.sha3_512(data.encode()).hexdigest()