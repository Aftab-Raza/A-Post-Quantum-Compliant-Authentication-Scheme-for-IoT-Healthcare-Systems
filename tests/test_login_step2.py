"""
Login Step 2 Test

Paper Mapping
-------------
Section V-C
Step 2
"""

from entities.server import Server
from entities.user import User

from protocol.registration import RegistrationProtocol
from protocol.login import LoginProtocol


def main():

    print("=" * 60)
    print("LOGIN STEP 2 TEST")
    print("=" * 60)

    # =====================================================
    # Setup
    # =====================================================

    server = Server()
    server.initialize()

    user = User(
        "aftab",
        "Password@123",
    )

    registration = RegistrationProtocol()

    # =====================================================
    # Registration
    # =====================================================

    request = registration.create_registration_request(
        user
    )

    registration.process_registration_request(
        server,
        user,
        request,
    )

    registration.finalize_registration(
        user
    )

    # =====================================================
    # Login
    # =====================================================

    login = LoginProtocol()

    print("\n[1] Verifying User...")

    status = login.verify_user(user)

    assert status

    print("✓ User Verified")

    print("\n[2] Creating Login Request...")

    message = login.create_login_request(user)

    # =====================================================
    # Verify Login Message
    # =====================================================

    assert message.ciphertext is not None
    assert message.payload is not None
    assert message.nonce is not None
    assert message.tag is not None

    print("✓ Saber Ciphertext Generated")
    print("✓ AES Payload Encrypted")
    print("✓ AES Nonce Generated")
    print("✓ AES Tag Generated")

    # =====================================================
    # Verify Cached Session
    # =====================================================

    assert user.session_key is not None
    assert len(user.session_key) == 32

    assert user.timestamp is not None
    assert user.rt is not None

    print()

    print("Session Key :", len(user.session_key))
    print("Ciphertext  :", len(message.ciphertext))
    print("Nonce       :", len(message.nonce))
    print("Tag         :", len(message.tag))

    print()

    print("✓ Login Step 2 Successful")


if __name__ == "__main__":
    main()