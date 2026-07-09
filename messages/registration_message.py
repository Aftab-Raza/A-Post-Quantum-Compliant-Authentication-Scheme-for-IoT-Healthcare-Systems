"""
Registration Message
"""


class RegistrationMessage:
    """
    Message sent from User to Authentication Server
    during Registration.
    """

    def __init__(self, user_id: str, beta: bytes):

        self.user_id = user_id
        self.beta = beta