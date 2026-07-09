"""
Smart Card Module
Stores user secret values exactly as described in SKEBA.
"""


class SmartCard:

    def __init__(self):

        self.lambda_i = None

        self.eta_i = None

        self.zeta_i = None

        self.public_key = None

    def store(self,
              lambda_i,
              eta_i,
              zeta_i,
              public_key):

        self.lambda_i = lambda_i
        self.eta_i = eta_i
        self.zeta_i = zeta_i
        self.public_key = public_key

    def show(self):

        print("\n=========== SMART CARD ===========")

        print("Lambda :", self.lambda_i)

        print("Eta    :", self.eta_i)

        print("Zeta   :", self.zeta_i)

        print("Public Key :", self.public_key)

        print("==================================")