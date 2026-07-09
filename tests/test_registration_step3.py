"""
Registration Step 3 Test
"""

from entities.server import Server
from entities.user import User
from protocol.registration import RegistrationProtocol


def main():

    print("=" * 60)
    print("REGISTRATION STEP 3 TEST")
    print("=" * 60)

    server = Server()
    server.initialize()

    user = User(
        "aftab",
        "Password@123",
    )

    protocol = RegistrationProtocol()

    request = protocol.create_registration_request(user)

    card = protocol.process_registration_request(
        server,
        user,
        request,
    )

    assert card.personalized
    assert card.lambda_i is not None
    assert card.public_key is not None
    assert server.database.user_exists(user.user_id)

    print()

    print("✓ Smart Card Personalized")
    print("✓ Registration Secret Stored")
    print("✓ Public Key Stored")
    print("✓ Registration Step 3 Successful")


if __name__ == "__main__":
    main()