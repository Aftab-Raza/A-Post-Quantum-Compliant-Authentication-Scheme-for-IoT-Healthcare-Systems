"""
Medical IoT Device Entity
"""


class Device:
    """
    Device Dj that receives temporary access grants from S.
    """

    def __init__(self, device_id: str):
        self.device_id = device_id
        self.access_grants = {}
        self.session_key = None
        self.authenticated_users = set()

    def receive_access_grant(
        self,
        temporary_id: str,
        timestamp: int,
        session_key: bytes,
        user_id: str,
    ):
        self.access_grants[temporary_id] = {
            "timestamp": timestamp,
            "session_key": session_key,
            "user_id": user_id,
        }
