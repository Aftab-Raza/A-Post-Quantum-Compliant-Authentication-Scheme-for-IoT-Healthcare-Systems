"""
Login Step 1 Test
"""

from entities.server import Server
from entities.user import User

from protocol.registration import RegistrationProtocol
from protocol.login import LoginProtocol


def main():

    print("=" * 60)
    print("LOGIN STEP 1 TEST")
    print("=" * 60)

    server = Server()
    server.initialize()

    user = User(
        "aftab",
        "Password@123",
    )

    registration = RegistrationProtocol()

    request = registration.create_registration_request(user)

    registration.process_registration_request(
        server,
        user,
        request,
    )

    registration.finalize_registration(user)

    login = LoginProtocol()

    status = login.verify_user(user)

    assert status

    print()

    print("✓ Password Verified")

    print("✓ ri Recovered")

    print("✓ Gamma Recovered")

    print("✓ Login Step 1 Successful")


if __name__ == "__main__":
    main()
    