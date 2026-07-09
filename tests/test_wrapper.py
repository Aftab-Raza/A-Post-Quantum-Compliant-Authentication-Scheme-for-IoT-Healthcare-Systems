from crypto.saber import Saber

print("=" * 60)
print("Official Saber Key Generation")
print("=" * 60)

saber = Saber()

pk, sk = saber.keypair()

print()

print("Public Key Length :", len(pk))
print("Secret Key Length :", len(sk))

print()

print("SUCCESS")