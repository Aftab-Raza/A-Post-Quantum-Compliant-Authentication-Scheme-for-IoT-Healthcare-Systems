import oqs

print("=" * 60)
print("liboqs Python Test")
print("=" * 60)

print("\nEnabled KEMs:\n")

for kem in oqs.get_enabled_kem_mechanisms():
    print(kem)