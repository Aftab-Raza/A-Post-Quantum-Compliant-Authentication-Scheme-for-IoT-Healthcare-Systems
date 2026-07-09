"""
Smart Card Entity

Stores all information that resides inside the user's
smart card after the registration phase.
"""


class SmartCard:
    """
    Smart Card issued by the Authentication Server.
    """

    def __init__(self):

        # ==================================================
        # Registration Parameters
        # ==================================================

        # Paper notation: λi
        self.lambda_i = None

        # Paper notation: ηi
        self.eta_i = None

        # Paper notation: ζi
        self.zeta_i = None

        # ==================================================
        # Server Public Key
        # ==================================================

        self.public_key = None

        # ==================================================
        # Status
        # ==================================================

        self.personalized = False

    @property
    def lambda_value(self):
        return self.lambda_i

    @property
    def eta(self):
        return self.eta_i

    @property
    def zeta(self):
        return self.zeta_i
