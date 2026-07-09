"""
Access Control Phase

Paper Mapping
-------------
Section V-D
"""

import hmac
import json
import secrets
import time

from config.constants import TIMESTAMP_WINDOW
from crypto.hash import H1, H2
from crypto.utils import xor_bytes
from messages.access_control_message import (
    AccessControlMessage,
    DeviceAccessRequest,
)


def _mask(*parts, length: int) -> bytes:
    output = bytearray()
    counter = 0

    while len(output) < length:
        output.extend(
            H2(
                *parts,
                counter,
            )
        )
        counter += 1

    return bytes(output[:length])


def _payload(user_id: str, temporary_id: str, timestamp: int) -> bytes:
    return json.dumps(
        {
            "user_id": user_id,
            "temporary_id": temporary_id,
            "timestamp": timestamp,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


class AccessControlProtocol:
    """
    Access Control Phase for Ui, S, and Dj.
    """

    # ======================================================
    # Step 1
    # ======================================================

    def issue_access(
        self,
        server,
        user_id: str,
        device,
        now: int | None = None,
    ) -> AccessControlMessage:
        """
        Server sends {R, W} to Ui and {IDit, T3, K} to Dj.
        """

        session = server.active_sessions.get(user_id)

        if session is None or not session.get("authenticated"):
            raise RuntimeError("User does not have an authenticated session.")

        now = int(time.time()) if now is None else now
        temporary_id = secrets.token_hex(16)
        session_key = session["session_key"]

        payload = _payload(
            user_id,
            temporary_id,
            now,
        )

        theta = _mask(
            user_id,
            session_key,
            length=len(payload),
        )

        response = xor_bytes(
            payload,
            theta,
        )

        verifier = H1(
            user_id,
            temporary_id,
            now,
        )

        device.receive_access_grant(
            temporary_id,
            now,
            session_key,
            user_id,
        )

        session["temporary_id"] = temporary_id
        session["access_timestamp"] = now

        return AccessControlMessage(
            response=response,
            verifier=verifier,
        )

    # ======================================================
    # Step 2
    # ======================================================

    def process_access_response(
        self,
        user,
        message: AccessControlMessage,
        now: int | None = None,
    ) -> bool:
        """
        User verifies {R, W} and derives Kt.
        """

        if not user.server_authenticated:
            raise RuntimeError("Server is not authenticated for this user.")

        now = int(time.time()) if now is None else now

        theta = _mask(
            user.user_id,
            user.session_key,
            length=len(message.response),
        )

        payload = xor_bytes(
            message.response,
            theta,
        )

        data = json.loads(payload.decode())
        user_id = data["user_id"]
        temporary_id = data["temporary_id"]
        timestamp = int(data["timestamp"])

        expected = H1(
            user.user_id,
            temporary_id,
            timestamp,
        )

        if not hmac.compare_digest(expected, message.verifier):
            return False

        if user_id != user.user_id:
            return False

        if abs(now - timestamp) > TIMESTAMP_WINDOW:
            return False

        user.temporary_id = temporary_id
        user.access_timestamp = timestamp
        user.access_session_key = H1(
            temporary_id,
            user.session_key,
            timestamp,
        )

        return True

    # ======================================================
    # Step 2 continued
    # ======================================================

    def create_device_request(
        self,
        user,
        now: int | None = None,
        include_temporary_id: bool = True,
    ) -> DeviceAccessRequest:
        """
        User sends pi = H1(IDit || T4) to Dj.
        """

        if user.temporary_id is None:
            raise RuntimeError("Access control response is not verified.")

        now = int(time.time()) if now is None else now

        proof = H1(
            user.temporary_id,
            now,
        )

        return DeviceAccessRequest(
            proof=proof,
            timestamp=now,
            temporary_id=user.temporary_id if include_temporary_id else None,
        )

    # ======================================================
    # Step 3
    # ======================================================

    def process_device_request(
        self,
        device,
        request: DeviceAccessRequest,
        now: int | None = None,
    ) -> bytes:
        """
        Device verifies pi and derives Kt.
        """

        now = int(time.time()) if now is None else now

        if abs(now - request.timestamp) > TIMESTAMP_WINDOW:
            raise RuntimeError("Device request timestamp is outside the window.")

        if request.temporary_id is None:
            grants = device.access_grants.items()
        else:
            grant = device.access_grants.get(request.temporary_id)
            grants = [] if grant is None else [(request.temporary_id, grant)]

        for temporary_id, grant in grants:
            expected = H1(
                temporary_id,
                request.timestamp,
            )

            if hmac.compare_digest(expected, request.proof):
                session_key = H1(
                    temporary_id,
                    grant["session_key"],
                    grant["timestamp"],
                )
                device.session_key = session_key
                device.authenticated_users.add(grant["user_id"])
                return session_key

        raise RuntimeError("Invalid device access proof.")
