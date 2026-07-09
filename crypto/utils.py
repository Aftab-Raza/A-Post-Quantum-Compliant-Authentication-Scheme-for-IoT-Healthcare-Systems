"""
Utility functions used throughout the SKEBA protocol.
"""

from typing import Final


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    Perform byte-wise XOR.

    Parameters
    ----------
    a : bytes
    b : bytes

    Returns
    -------
    bytes
        XOR(a, b)

    Raises
    ------
    ValueError
        If byte arrays are not of equal length.
    """

    if len(a) != len(b):
        raise ValueError(
            "Both byte arrays must have the same length."
        )

    return bytes(x ^ y for x, y in zip(a, b))


# Default random length used by the protocol.
RANDOM_LENGTH: Final[int] = 32