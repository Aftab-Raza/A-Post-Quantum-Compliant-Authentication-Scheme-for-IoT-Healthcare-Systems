from entities.user import User
from protocol.registration import RegistrationProtocol

user = User(
    "vickey",
    "password123"
)

protocol = RegistrationProtocol()

message = protocol.create_registration_request(user)

print("=" * 60)
print("REGISTRATION STEP 2 TEST")
print("=" * 60)

print("User ID :", message.user_id)

print("ri Length :", len(user.ri))

print("β Length :", len(message.beta))

assert len(user.ri) == 32
assert len(message.beta) == 32

print()
print("✓ Registration Request Created Successfully")