"""
Replay Attack Simulation

Goal
----
Verify that a previously captured LoginMessage cannot be reused.

Procedure
---------
1. Register a user.
2. Login normally.
3. Capture the LoginMessage.
4. Logout.
5. Replay the old LoginMessage.

Expected
--------
Server rejects authentication because the login challenge has already been used.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from entities.server import Server
from entities.user import User
from protocol.login import LoginProtocol
from protocol.registration import RegistrationProtocol


def main() -> None:
    print("=" * 70)
    print("SKEBA REPLAY ATTACK SIMULATION")
    print("=" * 70)

    server = Server()
    server.initialize()

    user = User(
        user_id="replay_demo_user",
        password="Password@123",
    )

    registration = RegistrationProtocol()
    registration_request = registration.create_registration_request(user)
    registration.process_registration_request(
        server,
        user,
        registration_request,
    )
    registration.finalize_registration(user)
    print("[OK] User registered")

    login = LoginProtocol()
    assert login.verify_user(user)

    captured_login_message = login.create_login_request(user)
    login_response = login.process_login_request(
        server,
        captured_login_message,
        now=user.timestamp,
    )
    assert login.verify_server(user, login_response)
    print("[OK] Normal login completed")
    print("[OK] LoginMessage captured")

    assert server.logout(user.user_id)
    print("[OK] User logged out")

    try:
        LoginProtocol().process_login_request(
            server,
            captured_login_message,
            now=user.timestamp,
        )
    except RuntimeError as exc:
        print("[OK] Observed: authentication failed")
        print(f"[OK] Server rejection reason: {exc}")
        print("[OK] Conclusion: replay attack prevented")
        return

    raise AssertionError("Replay attack was accepted.")


if __name__ == "__main__":
    main()
