"""
User Entity
"""

from entities.smartcard import SmartCard


class User:
    """
    User Ui
    """

    def __init__(self, user_id: str, password: str):

        # User Credentials
        self.user_id = user_id
        self.password = password

        # Random Number (ri)
        self.ri = None

        # γi
        self.gamma = None

        # Login State
        
        self.timestamp = None
        self.rt = None
        self.session_key = None
        self.server_authenticated = False
        self.temporary_id = None
        self.access_timestamp = None
        self.access_session_key = None

        # Registration Parameter (βi)
        self.beta = None

        # Smart Card
        self.smartcard = SmartCard()

        # Registration Status
        self.registered = False
