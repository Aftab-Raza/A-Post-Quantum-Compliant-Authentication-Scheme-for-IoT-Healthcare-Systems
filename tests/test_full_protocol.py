"""
Full SKEBA Protocol Integration Test

Paper Mapping
-------------
Setup, Registration, Login Steps 1-4, Mutual Authentication,
and Access Control.
"""

from entities.device import Device
from entities.server import Server
from entities.user import User
from protocol.access_control import AccessControlProtocol
from protocol.login import LoginProtocol
from protocol.registration import RegistrationProtocol


def main():
    print("=" * 70)
    print("SKEBA FULL PROTOCOL INTEGRATION TEST")
    print("=" * 70)

    server = Server()
    server.initialize()

    user = User(
        user_id="aftab",
        password="Password@123",
    )

    device = Device(
        device_id="medical-device-01",
    )

    server.database.add_device(device)

    registration = RegistrationProtocol()
    registration_request = registration.create_registration_request(user)
    registration.process_registration_request(
        server,
        user,
        registration_request,
    )
    registration.finalize_registration(user)

    assert user.registered
    assert user.smartcard.personalized
    assert server.database.user_exists(user.user_id)
    print("[OK] Registration")

    login = LoginProtocol()

    assert login.verify_user(user)
    login_message = login.create_login_request(user)
    login_response = login.process_login_request(
        server,
        login_message,
        now=user.timestamp,
    )

    assert login.verify_server(user, login_response)
    assert user.server_authenticated
    assert server.active_sessions[user.user_id]["authenticated"]
    print("[OK] Login Steps 1-4")
    print("[OK] Mutual Authentication")

    access = AccessControlProtocol()

    access_response = access.issue_access(
        server,
        user.user_id,
        device,
        now=user.timestamp,
    )

    assert access.process_access_response(
        user,
        access_response,
        now=user.timestamp,
    )

    device_request = access.create_device_request(
        user,
        now=user.timestamp,
    )

    device_session_key = access.process_device_request(
        device,
        device_request,
        now=user.timestamp,
    )

    assert device_session_key == user.access_session_key
    assert device.session_key == user.access_session_key
    assert user.user_id in device.authenticated_users
    print("[OK] Access Control")

    print("=" * 70)
    print("FULL PROTOCOL COMPLETED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    main()
