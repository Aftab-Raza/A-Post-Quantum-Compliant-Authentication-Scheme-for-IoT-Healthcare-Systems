"""
Login Phase Integration Test

Paper Mapping
-------------
Section V-C
Step 1
Step 2
"""

from entities.server import Server
from entities.user import User

from protocol.registration import RegistrationProtocol
from protocol.login import LoginProtocol


def main():

    print("=" * 70)
    print("SKEBA LOGIN PHASE INTEGRATION TEST")
    print("=" * 70)

    # ======================================================
    # Setup Phase
    # ======================================================

    print("\n[1] Initializing Authentication Server...")

    server = Server()
    server.initialize()

    # ======================================================
    # Create User
    # ======================================================

    print("\n[2] Creating User...")

    user = User(
        user_id="aftab",
        password="Password@123",
    )

    # ======================================================
    # Registration Phase
    # ======================================================

    registration = RegistrationProtocol()

    print("\n[3] Registration Step 2")

    request = registration.create_registration_request(user)

    print("✓ Registration Request Created")

    print("\n[4] Registration Step 3")

    registration.process_registration_request(
        server,
        user,
        request,
    )

    print("✓ Smart Card Personalized")

    print("\n[5] Registration Step 4")

    registration.finalize_registration(user)

    print("✓ Registration Completed")

    # ======================================================
    # Login Phase
    # ======================================================

    login = LoginProtocol()

    print("\n[6] Login Step 1")

    assert login.verify_user(user)

    print("✓ User Verified")

    print("\n[7] Login Step 2")

    login_message = login.create_login_request(user)

    # ======================================================
    # Verify Login Message
    # ======================================================

    # assert login_message.user_id == user.user_id

    assert login_message.ciphertext is not None
    assert len(login_message.ciphertext) > 0

    assert login_message.payload is not None
    assert len(login_message.payload) > 0

    assert login_message.nonce is not None
    assert len(login_message.nonce) > 0

    # assert login_message.timestamp == user.timestamp

    assert user.session_key is not None
    assert len(user.session_key) == 32

    assert user.rt is not None
    assert len(user.rt) == 32

    print("✓ Login Request Generated")

    # ======================================================
    # Success
    # ======================================================

    print()

    print("=" * 70)
    print("✓ LOGIN PHASE (CLIENT SIDE) COMPLETED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    main()