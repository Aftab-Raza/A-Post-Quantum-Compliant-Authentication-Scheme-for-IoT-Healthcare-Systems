"""
Live SKEBA registration and login demo.

Run:
    python main.py

This script drives the existing protocol implementation end-to-end so it can
be demonstrated live during a presentation or supervisor review.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from getpass import getpass

from entities.device import Device
from entities.server import Server
from entities.user import User
from messages.login_message import LoginMessage
from protocol.access_control import AccessControlProtocol
from protocol.login import LoginProtocol
from protocol.registration import RegistrationProtocol


def line(char: str = "=", width: int = 72) -> None:
    print(char * width)


def heading(title: str) -> None:
    print()
    line()
    print(title)
    line()


def ok(message: str) -> None:
    print(f"[OK] {message}")


def fail(message: str) -> None:
    print(f"[FAIL] {message}")


def short_hex(value: bytes | None, size: int = 16) -> str:
    if value is None:
        return "<none>"
    return value.hex()[:size] + "..."


def prompt_value(label: str, default: str) -> str:
    value = input(f"{label} [{default}]: ").strip()
    return value or default


def prompt_password(label: str, default: str) -> str:
    value = getpass(f"{label} [press Enter for demo default]: ")
    return value or default


@dataclass
class RegisteredCredential:
    user_id: str
    smartcard: object


@dataclass
class LoginDemoResult:
    user: User
    login_message: LoginMessage


def build_login_user(credential: RegisteredCredential, password: str) -> User:
    """
    Simulate a user inserting the personalized smart card and typing a password.
    """

    user = User(
        user_id=credential.user_id,
        password=password,
    )
    user.smartcard = credential.smartcard
    user.registered = True
    return user


def run_registration(server: Server, user_id: str, password: str) -> RegisteredCredential:
    heading("PHASE 2: LIVE USER REGISTRATION")

    user = User(
        user_id=user_id,
        password=password,
    )

    registration = RegistrationProtocol()

    print(f"Registering user ID: {user.user_id}")
    request = registration.create_registration_request(user)
    ok("Registration request created by user")
    print(f"    beta/H1 proof: {short_hex(request.beta)}")

    registration.process_registration_request(
        server,
        user,
        request,
    )
    ok("Authentication server processed registration request")

    registration.finalize_registration(user)
    ok("Smart card personalized")

    assert user.registered
    assert user.smartcard.personalized
    assert server.database.user_exists(user.user_id)

    print("Registration evidence:")
    print(f"    Stored at server       : {server.database.user_exists(user.user_id)}")
    print(f"    Smart card personalized: {user.smartcard.personalized}")
    print(f"    lambda_i               : {short_hex(user.smartcard.lambda_i)}")
    print(f"    eta_i                  : {short_hex(user.smartcard.eta_i)}")
    print(f"    zeta_i                 : {short_hex(user.smartcard.zeta_i)}")

    return RegisteredCredential(
        user_id=user.user_id,
        smartcard=user.smartcard,
    )


def demonstrate_wrong_password(credential: RegisteredCredential) -> None:
    heading("PHASE 3: WRONG PASSWORD REJECTION")

    wrong_password = input(
        "Enter any wrong password to show smart-card rejection "
        "[WrongPassword@123]: "
    ).strip() or "WrongPassword@123"

    login = LoginProtocol()
    attacker = build_login_user(
        credential,
        wrong_password,
    )

    if login.verify_user(attacker):
        fail("Wrong password was accepted")
        raise RuntimeError("Wrong-password test failed.")

    ok("Wrong password rejected locally by smart-card verification")


def run_login(
    server: Server,
    credential: RegisteredCredential,
    password: str,
    title: str,
) -> LoginDemoResult:
    heading(title)

    login_user = build_login_user(
        credential,
        password,
    )

    login = LoginProtocol()

    if not login.verify_user(login_user):
        fail("Smart-card verification failed for the entered password")
        raise RuntimeError("Login stopped because local user verification failed.")

    ok("User verified locally using smart-card values")

    request = login.create_login_request(login_user)
    ok("Login request created")
    print(f"    Saber ciphertext: {short_hex(request.ciphertext)}")
    print(f"    AES-GCM nonce   : {short_hex(request.nonce)}")
    print(f"    AES-GCM tag     : {short_hex(request.tag)}")

    response = login.process_login_request(
        server,
        request,
        now=login_user.timestamp,
    )
    ok("Server decrypted and verified login request")
    print(f"    Server proof: {short_hex(response.verification)}")

    if not login.verify_server(login_user, response):
        fail("Server authentication failed")
        raise RuntimeError("Mutual authentication failed.")

    ok("User verified server response")
    ok("Mutual authentication completed")
    print(f"    Session key: {short_hex(login_user.session_key)}")

    return LoginDemoResult(
        user=login_user,
        login_message=request,
    )


def demonstrate_replay_attack(
    server: Server,
    login_result: LoginDemoResult,
) -> None:
    heading("PHASE 5: REPLAY ATTACK SIMULATION")

    print("Procedure:")
    print("    1. A valid login message has already been captured.")
    print("    2. The user logs out.")
    print("    3. The attacker replays the old LoginMessage.")
    print("Expected: server rejects the replayed authentication request.")

    captured_message = login_result.login_message
    user_id = login_result.user.user_id
    replay_time = login_result.user.timestamp

    ok("Captured the previous LoginMessage")
    print(f"    Captured ciphertext: {short_hex(captured_message.ciphertext)}")
    print(f"    Captured nonce     : {short_hex(captured_message.nonce)}")

    if server.logout(user_id):
        ok("User logged out; active session removed")
    else:
        fail("No active session was available to logout")
        raise RuntimeError("Replay demonstration cannot continue.")

    try:
        LoginProtocol().process_login_request(
            server,
            captured_message,
            now=replay_time,
        )
    except RuntimeError as exc:
        ok("Observed: authentication failed")
        print(f"    Server rejection reason: {exc}")
        ok("Conclusion: replay attack prevented")
        return

    fail("Observed: replayed LoginMessage was accepted")
    raise RuntimeError("Replay attack was not prevented.")


def run_access_control(server: Server, user: User, device: Device) -> None:
    heading("PHASE 7: ACCESS CONTROL AND SESSION KEY AGREEMENT")

    access = AccessControlProtocol()

    response = access.issue_access(
        server,
        user.user_id,
        device,
        now=user.timestamp,
    )
    ok("Server issued access token for medical device")

    if not access.process_access_response(
        user,
        response,
        now=user.timestamp,
    ):
        fail("User rejected access response")
        raise RuntimeError("Access control response verification failed.")

    ok("User verified access response")
    print(f"    Temporary identity: {user.temporary_id}")

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

    ok("Medical device verified user proof")
    ok("User and device derived the same access session key")
    print(f"    Access session key: {short_hex(user.access_session_key)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the live SKEBA registration/login demonstration.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run with built-in demo values without interactive prompts.",
    )
    parser.add_argument(
        "--user-id",
        default="patient_001",
        help="User ID for --demo mode.",
    )
    parser.add_argument(
        "--password",
        default="Password@123",
        help="Password for --demo mode.",
    )
    parser.add_argument(
        "--device-id",
        default="medical-device-01",
        help="Medical IoT device ID for --demo mode.",
    )
    parser.add_argument(
        "--wrong-password",
        default="WrongPassword@123",
        help="Wrong password used for --demo mode rejection.",
    )
    args = parser.parse_args()

    heading("SKEBA LIVE REGISTRATION AND LOGIN DEMO")
    print("A Post-Quantum Compliant Authentication Scheme for IoT Healthcare Systems")
    print("This demo uses the project's actual Setup, Registration, Login, Mutual")
    print("Authentication, Access Control, and Session Key Establishment modules.")

    if args.demo:
        user_id = args.user_id
        password = args.password
        device_id = args.device_id
        print()
        print("Running non-interactive demo mode.")
        print(f"    User ID : {user_id}")
        print(f"    Device  : {device_id}")
    else:
        user_id = prompt_value("Enter patient/user ID", "patient_001")
        password = prompt_password("Create password", "Password@123")
        device_id = prompt_value("Enter medical IoT device ID", "medical-device-01")

    heading("PHASE 1: SETUP")
    server = Server()
    server.initialize()

    device = Device(device_id=device_id)
    server.database.add_device(device)
    ok(f"Registered medical device: {device.device_id}")

    credential = run_registration(
        server,
        user_id,
        password,
    )

    if args.demo:
        heading("PHASE 3: WRONG PASSWORD REJECTION")
        login = LoginProtocol()
        attacker = build_login_user(
            credential,
            args.wrong_password,
        )
        if login.verify_user(attacker):
            fail("Wrong password was accepted")
            raise RuntimeError("Wrong-password test failed.")
        ok("Wrong password rejected locally by smart-card verification")
    else:
        demonstrate_wrong_password(credential)

    typed_password = (
        password
        if args.demo
        else prompt_password("Re-enter correct password for live login", password)
    )
    first_login = run_login(
        server,
        credential,
        typed_password,
        "PHASE 4: LIVE LOGIN AND MUTUAL AUTHENTICATION",
    )

    demonstrate_replay_attack(
        server,
        first_login,
    )

    fresh_login = run_login(
        server,
        credential,
        typed_password,
        "PHASE 6: FRESH LOGIN AFTER REPLAY REJECTION",
    )

    run_access_control(
        server,
        fresh_login.user,
        device,
    )

    heading("DEMO RESULT")
    ok("Live registration completed")
    ok("Wrong password rejection demonstrated")
    ok("Live login completed")
    ok("Replay attack rejection demonstrated")
    ok("Mutual authentication completed")
    ok("Access control and session key agreement completed")
    line()


if __name__ == "__main__":
    main()
