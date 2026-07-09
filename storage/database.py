"""
Database Layer

Stores protocol information securely.
"""


class Database:
    """
    Simple in-memory database.
    """

    def __init__(self):

        # Registered Users
        self.users = {}

        # Registered Devices
        self.devices = {}

    # ======================================================
    # USER OPERATIONS
    # ======================================================

    def add_user(
        self,
        user_id,
        registration_secret: bytes = None,
    ):
        """
        Store the server-side registration secret (rs)
        associated with a user.
        """

        if not isinstance(user_id, str):
            user = user_id
            self.users[user.user_id] = {
                "entity": user,
                "registration_secret": registration_secret,
            }
            return

        self.users[user_id] = {
            "registration_secret": registration_secret,
        }

    def get_user(self, user_id: str):

        record = self.users.get(user_id)

        if isinstance(record, dict) and "entity" in record:
            return record["entity"]

        return record

    def get_user_record(self, user_id: str):

        return self.users.get(user_id)

    def user_exists(self, user_id: str):

        return user_id in self.users

    # ======================================================
    # DEVICE OPERATIONS
    # ======================================================

    def add_device(self, device):

        self.devices[device.device_id] = device

    def get_device(self, device_id):

        return self.devices.get(device_id)

    def device_exists(self, device_id):

        return device_id in self.devices
