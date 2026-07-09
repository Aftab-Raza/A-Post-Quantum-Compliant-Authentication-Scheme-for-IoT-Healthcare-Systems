"""
Mutual Authentication Phase

This module wraps Login Step 3 and Step 4, where the server proves
knowledge of K and gamma_i and the user verifies that proof.
"""

from protocol.login import LoginProtocol


class AuthenticationProtocol:
    """
    Server-user mutual authentication helper.
    """

    def __init__(self):
        self.login = LoginProtocol()

    def authenticate(
        self,
        server,
        user,
        login_message,
        now: int | None = None,
    ):
        response = self.login.process_login_request(
            server,
            login_message,
            now=now,
        )

        if not self.login.verify_server(user, response):
            raise RuntimeError("Server authentication failed.")

        return response
