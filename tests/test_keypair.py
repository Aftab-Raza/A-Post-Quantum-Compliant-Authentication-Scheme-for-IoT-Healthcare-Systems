from crypto.saber import Saber
from config.constants import (
    SABER_PUBLIC_KEY_BYTES,
    SABER_SECRET_KEY_BYTES,
)

print("=" * 60)
print("OFFICIAL SABER KEYPAIR TEST")
print("=" * 60)

saber = Saber()

pk, sk = saber.keypair()

print(f"Public Key Size : {len(pk)} bytes")
print(f"Secret Key Size : {len(sk)} bytes")

assert len(pk) == SABER_PUBLIC_KEY_BYTES
assert len(sk) == SABER_SECRET_KEY_BYTES

print()
print("✓ Keypair generated successfully.")