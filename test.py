import hashlib

message = "Hello SKEBA"

digest = hashlib.sha3_256(message.encode()).hexdigest()

print("SHA3-256:", digest)