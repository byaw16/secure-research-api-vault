"""Local encryption and master-password verification for the vault."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CONFIG_PATH = Path("vault_config.json")
ITERATIONS = 600_000
_VERIFICATION_TEXT = b"secure-research-api-vault:v1"


def _derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("A master password is required.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def is_initialized(config_path: Path = CONFIG_PATH) -> bool:
    return config_path.exists()


def initialize(password: str, config_path: Path = CONFIG_PATH) -> Fernet:
    """Create the local verifier and return the new encryption cipher."""
    if config_path.exists():
        raise RuntimeError("The vault has already been initialized.")
    salt = os.urandom(16)
    cipher = Fernet(_derive_key(password, salt))
    config_path.write_text(
        json.dumps(
            {
                "version": 1,
                "salt": base64.b64encode(salt).decode("ascii"),
                "verifier": cipher.encrypt(_VERIFICATION_TEXT).decode("ascii"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return cipher


def unlock(password: str, config_path: Path = CONFIG_PATH) -> Fernet:
    """Return a cipher only when the password decrypts the local verifier."""
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        salt = base64.b64decode(config["salt"])
        cipher = Fernet(_derive_key(password, salt))
        if cipher.decrypt(config["verifier"]) != _VERIFICATION_TEXT:
            raise ValueError("Incorrect master password.")
        return cipher
    except (KeyError, ValueError, InvalidToken, json.JSONDecodeError) as exc:
        raise ValueError("Incorrect master password or invalid vault configuration.") from exc

