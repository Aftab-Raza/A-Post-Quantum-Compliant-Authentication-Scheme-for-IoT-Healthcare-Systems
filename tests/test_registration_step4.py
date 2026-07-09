"""
Registration Step 4 Test
"""

from entities.server import Server
from entities.user import User
from protocol.registration import RegistrationProtocol


def main():

    print("=" * 60)
    print("REGISTRATION STEP 4 TEST")
    print("=" * 60)

    server = Server()
    server.initialize()

    user = User(
        "aftab",
        "Password@123",
    )

    protocol = RegistrationProtocol()

    request = protocol.create_registration_request(user)

    protocol.process_registration_request(
        server,
        user,
        request,
    )

    card = protocol.finalize_registration(user)

    assert card.personalized
    assert card.lambda_i is not None
    assert card.eta_i is not None
    assert card.zeta_i is not None
    assert user.registered

    print()

    print("✓ Gamma Recovered")
    print("✓ Eta Generated")
    print("✓ Zeta Generated")
    print("✓ Registration Completed")


if __name__ == "__main__":
    main()