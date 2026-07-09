from crypto.hash import H1, H2, H3

print("=" * 60)
print("HASH FUNCTION TEST")
print("=" * 60)

h1 = H1("Hello")

h2 = H2("Hello")

h3 = H3("Hello")

print("H1 :", len(h1))

print("H2 :", len(h2))

print("H3 :", len(h3))