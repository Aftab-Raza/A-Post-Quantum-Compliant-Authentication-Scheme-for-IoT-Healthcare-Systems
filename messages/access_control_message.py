"""
Access Control Messages
"""

from dataclasses import dataclass


@dataclass(slots=True)
class AccessControlMessage:
    """
    Server-to-user access response {R, W}.
    """

    response: bytes
    verifier: bytes


@dataclass(slots=True)
class DeviceAccessRequest:
    """
    User-to-device access request {pi, T4}.
    """

    proof: bytes
    timestamp: int
    temporary_id: str | None = None
