"""
AES-256-GCM Test

Tests the AES utility used by the SKEBA protocol.
"""

from crypto.aes import AES256
import secrets


def main():

    print("=" * 60)
    print("AES-256-GCM TEST")
    print("=" * 60)

    # Generate a random 256-bit key
    key = secrets.token_bytes(32)

    aes = AES256(key)

    plaintext = b"Official Saber Hybrid Encryption Test"

    print("[1] Encrypting...")

    nonce, ciphertext, tag = aes.encrypt(plaintext)

    print("[2] Decrypting...")

    recovered = aes.decrypt(
        nonce,
        ciphertext,
        tag,
    )

    assert recovered == plaintext

    print()

    print("Key Size        :", len(key))
    print("Nonce Size      :", len(nonce))
    print("Ciphertext Size :", len(ciphertext))
    print("Tag Size        :", len(tag))

    print()

    print("✓ Encryption Successful")
    print("✓ Decryption Successful")
    print("✓ AES-256-GCM Working")


if __name__ == "__main__":
    main()