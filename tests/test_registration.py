"""
Registration Phase Integration Test

Paper:
Section V-B

Tests the complete registration workflow:

Step 2
User Registration Request

↓

Step 3
Authentication Server Processing

↓

Step 4
User Smart Card Personalization
"""

from entities.server import Server
from entities.user import User
from protocol.registration import RegistrationProtocol


def main():

    print("=" * 70)
    print("SKEBA REGISTRATION PHASE INTEGRATION TEST")
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
    # Registration Protocol
    # ======================================================

    protocol = RegistrationProtocol()

    # ======================================================
    # Step 2
    # ======================================================

    print("\n[3] Registration Step 2")

    request = protocol.create_registration_request(user)

    assert request.user_id == user.user_id
    assert request.beta is not None

    print("✓ Registration Request Created")

    # ======================================================
    # Step 3
    # ======================================================

    print("\n[4] Registration Step 3")

    card = protocol.process_registration_request(
        server,
        user,
        request,
    )

    assert card.personalized
    assert card.lambda_i is not None
    assert card.public_key is not None

    print("✓ Smart Card Personalized")

    # ======================================================
    # Step 4
    # ======================================================

    print("\n[5] Registration Step 4")

    protocol.finalize_registration(user)

    assert user.registered

    assert user.smartcard.eta_i is not None
    assert user.smartcard.zeta_i is not None

    print("✓ User Registration Finalized")

    # ======================================================
    # Database Verification
    # ======================================================

    print("\n[6] Database Verification")

    assert server.database.user_exists(user.user_id)

    stored = server.database.get_user(user.user_id)

    assert stored is not None
    assert stored["registration_secret"] is not None

    print("✓ User Stored in Database")

    # ======================================================
    # Smart Card Verification
    # ======================================================

    print("\n[7] Smart Card Verification")

    card = user.smartcard

    assert card.lambda_i is not None
    assert card.eta_i is not None
    assert card.zeta_i is not None
    assert card.public_key is not None
    assert card.personalized

    print("✓ Smart Card Verified")

    # ======================================================
    # Success
    # ======================================================

    print()
    print("=" * 70)
    print("✓ REGISTRATION PHASE COMPLETED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    main()