"""
System-wide constants for the SKEBA protocol.
These values remain fixed throughout the project.
"""

# ==========================================================
# Protocol Information
# ==========================================================

PROTOCOL_NAME = "SKEBA"
VERSION = "1.0"

# ==========================================================
# Security Configuration
# ==========================================================

HASH_ALGORITHM = "SHA3-256"
SECURITY_LEVEL = 256
TIMESTAMP_WINDOW = 30

# ==========================================================
# Official Saber Parameters
# (SABER_L = 3)
# ==========================================================

SABER_PUBLIC_KEY_BYTES = 992
SABER_SECRET_KEY_BYTES = 3360
SABER_CIPHERTEXT_BYTES = 1088
SABER_SHARED_SECRET_BYTES = 32