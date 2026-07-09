"""
Abstract Key Encapsulation Mechanism
"""

from abc import ABC, abstractmethod


class KEM(ABC):

    @abstractmethod
    def keypair(self):
        pass

    @abstractmethod
    def encaps(self, public_key):
        pass

    @abstractmethod
    def decaps(self, ciphertext, private_key):
        pass