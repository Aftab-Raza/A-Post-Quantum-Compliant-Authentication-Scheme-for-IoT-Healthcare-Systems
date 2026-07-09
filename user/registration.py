from crypto.hash_utils import sha3_256
from crypto.random_utils import random_hex

class User:

    def __init__(self, user_id, password):

        self.user_id = user_id

        self.password = password

        self.ri = random_hex()

    def generate_beta(self):

        beta = sha3_256(
            self.ri +
            self.user_id +
            self.password
        )

        return beta