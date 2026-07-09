"""
Registration Phase

Paper Mapping
-------------
Step 2 : User Registration Request
Step 3 : Authentication Server Processing
Step 4 : User Smart Card Personalization

Paper:
Section V-B
"""

import secrets

from crypto.hash import H1, H2, H3
from crypto.utils import xor_bytes
from messages.registration_message import RegistrationMessage


class RegistrationProtocol:
    """
    Registration Phase
    """

    def __init__(self, server=None):
        self.server = server

    def register(self, user):
        """
        Backward-compatible full registration helper.
        """

        if self.server is None:
            raise RuntimeError("Registration server is not configured.")

        message = self.create_registration_request(user)
        self.process_registration_request(self.server, user, message)
        return self.finalize_registration(user)

    # ======================================================
    # Step 2
    # ======================================================

    def create_registration_request(self, user):
        """
        User computes

            βi = H1(ri || IDi || PWDi)
        """

        user.ri = secrets.token_bytes(32)

        user.beta = H1(
            user.ri,
            user.user_id,
            user.password,
        )

        return RegistrationMessage(
            user.user_id,
            user.beta,
        )

    # ======================================================
    # Step 3
    # ======================================================

    def process_registration_request(
        self,
        server,
        user,
        message,
    ):
        """
        Authentication Server

        γi = H1(rs || IDi)

        λi = βi XOR γi
        """

        rs = secrets.token_bytes(32)

        gamma_i = H1(
            rs,
            message.user_id,
        )

        lambda_i = xor_bytes(
            message.beta,
            gamma_i,
        )

        card = user.smartcard

        card.lambda_i = lambda_i
        card.public_key = server.public_key
        card.personalized = True

        server.database.add_user(
            message.user_id,
            rs,
        )

        return card

    # ======================================================
    # Step 4
    # ======================================================

    def finalize_registration(
        self,
        user,
    ):
        """
        User Side

        γi = λi XOR H1(ri || IDi || PWDi)

        ηi = H3(IDi || PWDi) XOR ri

        ζi = H2(H3(IDi || PWDi) || ri || γi)
        """

        card = user.smartcard

        # ------------------------------------------
        # Recover γi
        # ------------------------------------------

        beta = H1(
            user.ri,
            user.user_id,
            user.password,
        )

        gamma_i = xor_bytes(
            card.lambda_i,
            beta,
        )

        # ------------------------------------------
        # Compute ηi
        # ------------------------------------------

        password_hash = H3(
            user.user_id,
            user.password,
        )

        eta_i = xor_bytes(
            password_hash,
            user.ri,
        )

        # ------------------------------------------
        # Compute ζi
        # ------------------------------------------

        zeta_i = H2(
            password_hash,
            user.ri,
            gamma_i,
        )

        # ------------------------------------------
        # Store values
        # ------------------------------------------

        card.eta_i = eta_i
        card.zeta_i = zeta_i

        user.registered = True

        return card
