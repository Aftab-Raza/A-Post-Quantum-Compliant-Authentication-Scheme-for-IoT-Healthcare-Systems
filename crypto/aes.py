"""
AES-256-GCM Utility

This module provides authenticated encryption using
AES-256-GCM.

Used by the SKEBA protocol after the Official Saber
Key Encapsulation Mechanism (KEM).

Paper Mapping
-------------
Login Phase
Mutual Authentication
"""

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ModuleNotFoundError:
    AES = None
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from os import urandom as get_random_bytes


class AES256:
    """
    AES-256-GCM Encryption Utility
    """

    NONCE_SIZE = 12
    TAG_SIZE = 16
    KEY_SIZE = 32

    def __init__(self, key: bytes):

        if len(key) != self.KEY_SIZE:
            raise ValueError(
                "AES-256 requires a 32-byte key."
            )

        self.key = key

    # ======================================================
    # Encryption
    # ======================================================

    def encrypt(
        self,
        plaintext: bytes,
    ):
        """
        Encrypt plaintext.

        Returns
        -------
        nonce : bytes
        ciphertext : bytes
        tag : bytes
        """

        nonce = get_random_bytes(self.NONCE_SIZE)

        if AES is None:
            ciphertext_with_tag = AESGCM(self.key).encrypt(
                nonce,
                plaintext,
                None,
            )
            ciphertext = ciphertext_with_tag[:-self.TAG_SIZE]
            tag = ciphertext_with_tag[-self.TAG_SIZE:]
        else:
            cipher = AES.new(
                self.key,
                AES.MODE_GCM,
                nonce=nonce,
            )

            ciphertext, tag = cipher.encrypt_and_digest(
                plaintext
            )

        return (
            nonce,
            ciphertext,
            tag,
        )

    # ======================================================
    # Decryption
    # ======================================================

    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
    ):
        """
        Decrypt ciphertext.

        Returns
        -------
        plaintext : bytes
        """

        if AES is None:
            plaintext = AESGCM(self.key).decrypt(
                nonce,
                ciphertext + tag,
                None,
            )
        else:
            cipher = AES.new(
                self.key,
                AES.MODE_GCM,
                nonce=nonce,
            )

            plaintext = cipher.decrypt_and_verify(
                ciphertext,
                tag,
            )

        return plaintext
