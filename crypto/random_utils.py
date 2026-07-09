"""
random_utils.py
Generates cryptographically secure random values.
"""

import secrets


def random_hex(length=16):
    """
    Returns a secure random hexadecimal string.
    """
    return secrets.token_hex(length)


def random_int(bits=128):
    """
    Returns a secure random integer.
    """
    return secrets.randbits(bits)