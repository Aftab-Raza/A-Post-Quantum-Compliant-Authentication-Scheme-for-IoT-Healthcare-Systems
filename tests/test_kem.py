from crypto.saber import Saber

print("=" * 60)
print("OFFICIAL SABER KEM TEST")
print("=" * 60)

saber = Saber()

print("[1] Generating key pair...")
pk, sk = saber.keypair()

print("[2] Encapsulating...")
ct, ss1 = saber.encaps(pk)

print("[3] Decapsulating...")
ss2 = saber.decaps(ct, sk)

print()

print("Public Key :", len(pk))
print("Secret Key :", len(sk))
print("Ciphertext :", len(ct))
print("Shared Secret :", len(ss1))

assert ss1 == ss2

print()
print("✓ Shared Secret Verified")
print("✓ Official Saber KEM Working")