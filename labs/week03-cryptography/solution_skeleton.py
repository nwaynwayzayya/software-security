"""
Week 3 — FIX the misuse here. Fill in the TODOs.
pip install argon2-cffi pycryptodome
"""

import os
import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from Crypto.Cipher import AES


# Argon2id is used by default by PasswordHasher.
ph = PasswordHasher()


def store_password(pw: str) -> str:
    """
    Store a password securely using Argon2id.

    Argon2 automatically generates a unique random salt
    for every password.
    """
    return ph.hash(pw)


def verify_password(hash_: str, pw: str) -> bool:
    """
    Verify an Argon2id password hash.
    """
    try:
        return ph.verify(hash_, pw)
    except (VerifyMismatchError, VerificationError):
        return False


def verify_and_migrate(hash_: str, pw: str) -> tuple[bool, str]:
    """
    Verify either a legacy unsalted MD5 hash or a modern Argon2id hash.

    If the password matches a legacy MD5 hash, return a new Argon2id
    hash so the caller can replace the old hash in the database.

    Returns:
        (authenticated, new_hash)

    new_hash is None when no migration is required.
    """

    # --------------------------------------------------------
    # Legacy MD5 detection
    # --------------------------------------------------------

    if (
        len(hash_) == 32
        and all(c in "0123456789abcdefABCDEF" for c in hash_)
    ):
        legacy_hash = hashlib.md5(
            pw.encode()
        ).hexdigest()

        if hmac.compare_digest(
            hash_.lower(),
            legacy_hash.lower()
        ):
            # Password is correct.
            # Upgrade the old MD5 hash to Argon2id.
            return True, store_password(pw)

        return False, None

    # --------------------------------------------------------
    # Modern Argon2id verification
    # --------------------------------------------------------

    try:
        valid = ph.verify(hash_, pw)

        if not valid:
            return False, None

        # Upgrade the Argon2 parameters if necessary.
        if ph.check_needs_rehash(hash_):
            return True, store_password(pw)

        return True, None

    except (VerifyMismatchError, VerificationError):
        return False, None


def encrypt_gcm(
    data: bytes,
    key: bytes
) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt data using AES-GCM.

    AES-GCM provides both confidentiality and integrity.
    A fresh random nonce is generated for every encryption.
    """

    nonce = os.urandom(12)

    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce
    )

    ciphertext, tag = cipher.encrypt_and_digest(data)

    return nonce, ciphertext, tag


def reset_token() -> str:
    """
    Generate a cryptographically secure reset token.
    """

    return secrets.token_urlsafe(16)


if __name__ == "__main__":

    # Get the encryption key from an environment variable.
    # If it is not provided, generate a temporary random key
    # for demonstration purposes.
    key = bytes.fromhex(
        os.environ.get(
            "ENC_KEY_HEX",
            os.urandom(32).hex()
        )
    )

    # --------------------------------------------------------
    # Argon2 password storage
    # --------------------------------------------------------

    password_hash = store_password("password123")

    print("argon2 hash:", password_hash)

    print(
        "argon2 ok:",
        verify_password(
            password_hash,
            "password123"
        )
    )

    # --------------------------------------------------------
    # Legacy MD5 migration demonstration
    # --------------------------------------------------------

    legacy_md5 = hashlib.md5(
        b"password123"
    ).hexdigest()

    authenticated, new_hash = verify_and_migrate(
        legacy_md5,
        "password123"
    )

    print("legacy md5 ok:", authenticated)

    if new_hash:
        print("migrated to argon2id:", new_hash)

    # --------------------------------------------------------
    # AES-GCM
    # --------------------------------------------------------

    nonce, ciphertext, tag = encrypt_gcm(
        b"secret",
        key
    )

    print("gcm nonce:", nonce.hex())
    print("gcm ciphertext:", ciphertext.hex())
    print("gcm tag:", tag.hex())

    # --------------------------------------------------------
    # Secure reset token
    # --------------------------------------------------------

    print("token:", reset_token())