"""
Login Phase

Paper Mapping
-------------
Section V-C
Step 1
Step 2
"""

import json
import hmac
import secrets
import time

from config.constants import TIMESTAMP_WINDOW
from crypto.hash import H1, H2, H3
from crypto.utils import xor_bytes
from crypto.saber import Saber
from crypto.aes import AES256

from messages.login_message import LoginMessage
from messages.login_response import LoginResponse


class LoginProtocol:
    """
    Login Phase
    """

    def __init__(self):

        self.saber = Saber()

    # ======================================================
    # Step 1
    # ======================================================

    def verify_user(
        self,
        user,
    ):
        """
        Verify user locally using the Smart Card.

        Paper
        -----
        r'i = H3(IDi || PWDi) XOR ηi

        γ'i = λi XOR H1(r'i || IDi || PWDi)

        ζ'i = H2(H3(IDi || PWDi) || r'i || γ'i)

        Verify

            ζ'i == ζi
        """

        card = user.smartcard

        # ------------------------------------------
        # Recover r'i
        # ------------------------------------------

        password_hash = H3(
            user.user_id,
            user.password,
        )

        recovered_ri = xor_bytes(
            password_hash,
            card.eta_i,
        )

        # ------------------------------------------
        # Recover γ'i
        # ------------------------------------------

        beta = H1(
            recovered_ri,
            user.user_id,
            user.password,
        )

        recovered_gamma = xor_bytes(
            card.lambda_i,
            beta,
        )

        # ------------------------------------------
        # Recover ζ'
        # ------------------------------------------

        recovered_zeta = H2(
            password_hash,
            recovered_ri,
            recovered_gamma,
        )

        # ------------------------------------------
        # Verify Smart Card
        # ------------------------------------------

        if recovered_zeta != card.zeta_i:
            return False

        # Cache recovered values

        user.ri = recovered_ri
        user.gamma = recovered_gamma

        return True

    # ======================================================
    # Step 2
    # ======================================================

    def create_login_request(
        self,
        user,
    ):
        """
        Login Phase

        Paper Mapping
        -------------
        Section V-C
        Step 2
        """

        if not user.registered:
            raise RuntimeError(
                "User has not completed registration."
            )

        if user.gamma is None:
            raise RuntimeError(
                "User verification must be completed first."
            )

        # ------------------------------------------
        # Timestamp
        # ------------------------------------------

        timestamp = int(time.time())

        # ------------------------------------------
        # Random rt
        # ------------------------------------------

        rt = secrets.token_bytes(32)

        # ------------------------------------------
        # Plaintext
        # ------------------------------------------

        plaintext = json.dumps(
            {
                "user_id": user.user_id,
                "timestamp": timestamp,
                "rt": rt.hex(),
            }
        ).encode()

        # ------------------------------------------
        # Official Saber Encapsulation
        # ------------------------------------------

        saber_ciphertext, session_key = (
            self.saber.encaps(
                user.smartcard.public_key
            )
        )

        # ------------------------------------------
        # AES-256-GCM Encryption
        # ------------------------------------------

        aes = AES256(session_key)

        nonce, encrypted_payload, tag = (
            aes.encrypt(
                plaintext
            )
        )

        # ------------------------------------------
        # Cache Session Values
        # ------------------------------------------

        user.session_key = session_key
        user.timestamp = timestamp
        user.rt = rt

        # ------------------------------------------
        # Login Message
        # ------------------------------------------

        return LoginMessage(
            ciphertext=saber_ciphertext,
            payload=encrypted_payload,
            nonce=nonce,
            tag=tag,
        )

    # ======================================================
    # Step 3
    # ======================================================

    def process_login_request(
        self,
        server,
        message: LoginMessage,
        now: int | None = None,
    ) -> LoginResponse:
        """
        Server verifies the user request and returns

            v = H1(K || gamma_i || T1 || rt)
        """

        if not server.initialized:
            raise RuntimeError("Server setup phase is not complete.")

        now = int(time.time()) if now is None else now

        session_key = self.saber.decaps(
            message.ciphertext,
            server.private_key,
        )

        plaintext = AES256(session_key).decrypt(
            message.nonce,
            message.payload,
            message.tag,
        )

        payload = json.loads(plaintext.decode())
        user_id = payload["user_id"]
        timestamp = int(payload["timestamp"])
        rt = bytes.fromhex(payload["rt"])

        if abs(now - timestamp) > TIMESTAMP_WINDOW:
            raise RuntimeError("Login request timestamp is outside the window.")

        expired_challenges = [
            challenge
            for challenge, seen_timestamp in server.used_login_challenges.items()
            if abs(now - seen_timestamp) > TIMESTAMP_WINDOW
        ]

        for challenge in expired_challenges:
            del server.used_login_challenges[challenge]

        challenge_id = H1(
            "login-challenge",
            user_id,
            timestamp,
            rt,
        )

        if challenge_id in server.used_login_challenges:
            raise RuntimeError("Replay attack detected: login message already used.")

        user_record = server.database.get_user_record(user_id)

        if user_record is None:
            raise RuntimeError("Unknown user.")

        registration_secret = user_record["registration_secret"]

        gamma_i = H1(
            registration_secret,
            user_id,
        )

        verification = H1(
            session_key,
            gamma_i,
            timestamp,
            rt,
        )

        server.active_sessions[user_id] = {
            "session_key": session_key,
            "gamma": gamma_i,
            "timestamp": timestamp,
            "rt": rt,
            "authenticated": True,
        }

        server.used_login_challenges[challenge_id] = timestamp

        return LoginResponse(
            verification=verification,
        )

    # ======================================================
    # Step 4
    # ======================================================

    def verify_server(
        self,
        user,
        response: LoginResponse,
    ) -> bool:
        """
        User verifies the server proof.
        """

        if user.session_key is None or user.gamma is None:
            raise RuntimeError("Login request has not been created.")

        expected = H1(
            user.session_key,
            user.gamma,
            user.timestamp,
            user.rt,
        )

        verified = hmac.compare_digest(
            expected,
            response.verification,
        )

        user.server_authenticated = verified

        return verified
