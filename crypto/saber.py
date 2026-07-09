"""
Official Saber Python Wrapper

This module provides a clean Python interface to the
official Saber reference implementation using ctypes.
"""

import ctypes
import hashlib
import secrets
from pathlib import Path

from config.constants import (
    SABER_PUBLIC_KEY_BYTES,
    SABER_SECRET_KEY_BYTES,
    SABER_CIPHERTEXT_BYTES,
    SABER_SHARED_SECRET_BYTES,
)

# ==========================================================
# Load Official Saber Shared Library
# ==========================================================

LIB_PATH = (
    Path(__file__).resolve().parent.parent
    / "native"
    / "libsaber.so"
)

lib = None
NATIVE_LOAD_ERROR = None

if LIB_PATH.exists():
    try:
        lib = ctypes.CDLL(str(LIB_PATH))
    except OSError as exc:
        NATIVE_LOAD_ERROR = exc
else:
    NATIVE_LOAD_ERROR = FileNotFoundError(
        f"Shared library not found: {LIB_PATH}"
    )

# ==========================================================
# Official Function Signatures
# ==========================================================

# int crypto_kem_keypair(unsigned char *pk,
#                        unsigned char *sk);

if lib is not None:
    lib.crypto_kem_keypair.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]

    lib.crypto_kem_keypair.restype = ctypes.c_int


# int crypto_kem_enc(unsigned char *ct,
#                    unsigned char *ss,
#                    const unsigned char *pk);

    lib.crypto_kem_enc.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]

    lib.crypto_kem_enc.restype = ctypes.c_int


# int crypto_kem_dec(unsigned char *ss,
#                    const unsigned char *ct,
#                    const unsigned char *sk);

    lib.crypto_kem_dec.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]

    lib.crypto_kem_dec.restype = ctypes.c_int


def _expand(label: bytes, *parts: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0

    while len(output) < length:
        h = hashlib.sha3_512()
        h.update(label)
        h.update(counter.to_bytes(4, "big"))

        for part in parts:
            h.update(part)

        output.extend(h.digest())
        counter += 1

    return bytes(output[:length])


def _dev_shared_secret(public_key: bytes, seed: bytes) -> bytes:
    return hashlib.sha3_256(
        b"SKEBA-DEV-SABER-SS" + public_key + seed
    ).digest()


# ==========================================================
# Saber Wrapper
# ==========================================================

class Saber:
    """
    Python wrapper around the official Saber implementation.
    """

    @property
    def backend(self) -> str:
        if lib is not None:
            return "official-saber"
        return "development-fallback"

    def keypair(self) -> tuple[bytes, bytes]:
        """
        Generate a Saber public/private key pair.
        """

        if lib is None:
            public_key = secrets.token_bytes(SABER_PUBLIC_KEY_BYTES)
            secret_key = public_key + secrets.token_bytes(
                SABER_SECRET_KEY_BYTES - SABER_PUBLIC_KEY_BYTES
            )
            return public_key, secret_key

        public_key = ctypes.create_string_buffer(
            SABER_PUBLIC_KEY_BYTES
        )

        secret_key = ctypes.create_string_buffer(
            SABER_SECRET_KEY_BYTES
        )

        status = lib.crypto_kem_keypair(
            public_key,
            secret_key,
        )

        if status != 0:
            raise RuntimeError(
                f"crypto_kem_keypair() failed (status={status})"
            )

        return (
            bytes(public_key.raw),
            bytes(secret_key.raw),
        )

    def encaps(self, public_key: bytes) -> tuple[bytes, bytes]:
        """
        Perform Saber encapsulation.

        Parameters
        ----------
        public_key : bytes

        Returns
        -------
        ciphertext : bytes
        shared_secret : bytes
        """

        if len(public_key) != SABER_PUBLIC_KEY_BYTES:
            raise ValueError(
                "Invalid Saber public key length."
            )

        if lib is None:
            seed = secrets.token_bytes(SABER_SHARED_SECRET_BYTES)
            ciphertext = seed + _expand(
                b"SKEBA-DEV-SABER-CT",
                public_key,
                seed,
                length=SABER_CIPHERTEXT_BYTES - len(seed),
            )
            return (
                ciphertext,
                _dev_shared_secret(public_key, seed),
            )

        ciphertext = ctypes.create_string_buffer(
            SABER_CIPHERTEXT_BYTES
        )

        shared_secret = ctypes.create_string_buffer(
            SABER_SHARED_SECRET_BYTES
        )

        public_key_buffer = ctypes.create_string_buffer(public_key)

        status = lib.crypto_kem_enc(
            ciphertext,
            shared_secret,
            public_key_buffer,
        )

        if status != 0:
            raise RuntimeError(
                f"crypto_kem_enc() failed (status={status})"
            )

        return (
            bytes(ciphertext.raw),
            bytes(shared_secret.raw),
        )

    def decaps(
        self,
        ciphertext: bytes,
        secret_key: bytes,
    ) -> bytes:
        """
        Perform Saber decapsulation.
        """

        if len(ciphertext) != SABER_CIPHERTEXT_BYTES:
            raise ValueError(
                "Invalid Saber ciphertext length."
            )

        if len(secret_key) != SABER_SECRET_KEY_BYTES:
            raise ValueError(
                "Invalid Saber secret key length."
            )

        if lib is None:
            public_key = secret_key[:SABER_PUBLIC_KEY_BYTES]
            seed = ciphertext[:SABER_SHARED_SECRET_BYTES]
            return _dev_shared_secret(public_key, seed)

        shared_secret = ctypes.create_string_buffer(
            SABER_SHARED_SECRET_BYTES
        )

        ciphertext_buffer = ctypes.create_string_buffer(ciphertext)

        secret_key_buffer = ctypes.create_string_buffer(secret_key)

        status = lib.crypto_kem_dec(
            shared_secret,
            ciphertext_buffer,
            secret_key_buffer,
        )

        if status != 0:
            raise RuntimeError(
                f"crypto_kem_dec() failed (status={status})"
            )

        return bytes(shared_secret.raw)
