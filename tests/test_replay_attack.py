"""
Replay Attack Regression Test
"""

from entities.server import Server
from entities.user import User
from protocol.login import LoginProtocol
from protocol.registration import RegistrationProtocol


def main():
    server = Server()
    server.initialize()

    user = User(
        user_id="replay_test_user",
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

    login = LoginProtocol()
    assert login.verify_user(user)

    captured_login_message = login.create_login_request(user)
    login_response = login.process_login_request(
        server,
        captured_login_message,
        now=user.timestamp,
    )

    assert login.verify_server(user, login_response)
    assert server.logout(user.user_id)

    try:
        LoginProtocol().process_login_request(
            server,
            captured_login_message,
            now=user.timestamp,
        )
    except RuntimeError as exc:
        assert "Replay attack detected" in str(exc)
    else:
        raise AssertionError("Replayed LoginMessage was accepted.")

    print("[OK] Replay attack prevented")


if __name__ == "__main__":
    main()
