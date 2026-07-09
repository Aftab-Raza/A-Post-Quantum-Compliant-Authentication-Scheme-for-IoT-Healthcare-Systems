"""
Hash Functions used in the SKEBA Protocol

Paper Mapping
-------------
H1 : SHA3-256
H2 : SHA3-512
H3 : SHA3-256
"""

import hashlib


def H1(*args) -> bytes:
    """
    SHA3-256
    """

    h = hashlib.sha3_256()

    for arg in args:

        if isinstance(arg, bytes):
            h.update(arg)
        else:
            h.update(str(arg).encode())

    return h.digest()


def H2(*args) -> bytes:
    """
    SHA3-512
    """

    h = hashlib.sha3_512()

    for arg in args:

        if isinstance(arg, bytes):
            h.update(arg)
        else:
            h.update(str(arg).encode())

    return h.digest()


def H3(*args) -> bytes:
    """
    SHA3-256
    """

    h = hashlib.sha3_256()

    for arg in args:

        if isinstance(arg, bytes):
            h.update(arg)
        else:
            h.update(str(arg).encode())

    return h.digest()