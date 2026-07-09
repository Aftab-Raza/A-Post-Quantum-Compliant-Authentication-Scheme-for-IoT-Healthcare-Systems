"""
Authentication Response

Paper Mapping
-------------
Section V-C
Step 3
"""

from dataclasses import dataclass


@dataclass(slots=True)
class AuthenticationResponse:
    """
    Authentication response sent by the
    Authentication Server.
    """

    value: bytes