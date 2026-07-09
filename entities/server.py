"""
Authentication Server Entity

This class represents the Authentication Server
described in the SKEBA protocol.
"""

from storage.database import Database
from crypto.saber import Saber

from config.constants import (
    PROTOCOL_NAME,
    VERSION,
    HASH_ALGORITHM,
    SECURITY_LEVEL,
)


class Server:
    """
    Authentication Server
    """

    def __init__(self):

        # ==================================================
        # System Information
        # ==================================================

        self.protocol = PROTOCOL_NAME
        self.version = VERSION
        self.hash_algorithm = HASH_ALGORITHM
        self.security_level = SECURITY_LEVEL

        # ==================================================
        # Cryptographic Engine
        # ==================================================

        self.saber = Saber()

        # Official Saber Key Pair

        self.public_key = None
        self.private_key = None

        # ==================================================
        # Registration Secret
        # ==================================================

        # Paper notation:
        # rs

       # Registration secrets are stored securely
# in the database for each registered user.

        # ==================================================
        # Database
        # ==================================================

        self.database = Database()

        # ==================================================
        # Active Sessions
        # ==================================================

        self.active_sessions = {}
        self.used_login_challenges = {}

        # ==================================================
        # Status
        # ==================================================

        self.initialized = False

    def initialize(self):
        """
        Execute the Setup Phase.
        """

        print()

        print("=" * 60)
        print("Initializing Authentication Server")
        print("=" * 60)

        self.public_key, self.private_key = (
            self.saber.keypair()
        )

        self.initialized = True

        print("Protocol :", self.protocol)
        print("Version  :", self.version)

        print()

        print(
            "Public Key Size :",
            len(self.public_key),
        )

        print(
            "Private Key Size:",
            len(self.private_key),
        )

        print()

        print("Server Initialized Successfully")

    def setup(self):
        """
        Backward-compatible alias for older scripts.
        """

        self.initialize()

    def logout(self, user_id: str) -> bool:
        """
        End an authenticated user session.

        Replay protection data is intentionally kept after logout so a captured
        login message cannot be reused to recreate a session.
        """

        return self.active_sessions.pop(user_id, None) is not None

    @property
    def users(self):
        return self.database.users

    @property
    def devices(self):
        return self.database.devices
