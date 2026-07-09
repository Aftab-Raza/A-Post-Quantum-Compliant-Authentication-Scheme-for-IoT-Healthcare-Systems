"""
Login Message

Paper Mapping
-------------
Section V-C
Step 2

Message sent from User to Authentication Server.
"""

from dataclasses import dataclass


@dataclass(slots=True)
class LoginMessage:
    """
    Login Request
    """

    # Official Saber Ciphertext
    ciphertext: bytes

    # AES-GCM Protected Payload
    payload: bytes

    # AES-GCM Nonce
    nonce: bytes

    # AES-GCM Authentication Tag
    tag: bytes