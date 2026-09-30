"""SQLite persistence with encrypted secret values and an audit trail."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet

DB_PATH = Path("vault.db")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def managed_connection(db_path: Path = DB_PATH):
    """Commit successful work and always close the SQLite connection."""
    conn = connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def initialize(db_path: Path = DB_PATH) -> None:
    with managed_connection(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY,
                service TEXT NOT NULL,
                project TEXT NOT NULL,
                label TEXT NOT NULL,
                secret_token BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY,
                credential_id INTEGER,
                action TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )


def _audit(conn: sqlite3.Connection, credential_id: int | None, action: str, detail: str) -> None:
    conn.execute(
        "INSERT INTO audit_log (credential_id, action, detail, created_at) VALUES (?, ?, ?, ?)",
        (credential_id, action, detail, _now()),
    )


def add_credential(service: str, project: str, label: str, secret: str, cipher: Fernet, db_path: Path = DB_PATH) -> int:
    if not all(value.strip() for value in (service, project, label, secret)):
        raise ValueError("Service, project, label, and API key are required.")
    now = _now()
    with managed_connection(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO credentials (service, project, label, secret_token, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (service.strip(), project.strip(), label.strip(), cipher.encrypt(secret.encode("utf-8")), now, now),
        )
        credential_id = int(cursor.lastrowid)
        _audit(conn, credential_id, "created", f"Created credential: {service.strip()} / {label.strip()}")
    return credential_id


def list_credentials(db_path: Path = DB_PATH) -> list[dict]:
    with managed_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, service, project, label, created_at, updated_at FROM credentials ORDER BY updated_at DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def get_secret(credential_id: int, cipher: Fernet, db_path: Path = DB_PATH) -> str:
    with managed_connection(db_path) as conn:
        row = conn.execute("SELECT secret_token, service, label FROM credentials WHERE id = ?", (credential_id,)).fetchone()
        if row is None:
            raise KeyError("Credential not found.")
        secret = cipher.decrypt(row["secret_token"]).decode("utf-8")
        _audit(conn, credential_id, "revealed", f"Revealed credential: {row['service']} / {row['label']}")
    return secret


def update_credential(credential_id: int, service: str, project: str, label: str, secret: str | None, cipher: Fernet, db_path: Path = DB_PATH) -> None:
    if not all(value.strip() for value in (service, project, label)):
        raise ValueError("Service, project, and label are required.")
    with managed_connection(db_path) as conn:
        if secret and secret.strip():
            conn.execute(
                """UPDATE credentials SET service=?, project=?, label=?, secret_token=?, updated_at=? WHERE id=?""",
                (service.strip(), project.strip(), label.strip(), cipher.encrypt(secret.strip().encode("utf-8")), _now(), credential_id),
            )
        else:
            conn.execute(
                "UPDATE credentials SET service=?, project=?, label=?, updated_at=? WHERE id=?",
                (service.strip(), project.strip(), label.strip(), _now(), credential_id),
            )
        _audit(conn, credential_id, "updated", f"Updated credential: {service.strip()} / {label.strip()}")


def delete_credential(credential_id: int, db_path: Path = DB_PATH) -> None:
    with managed_connection(db_path) as conn:
        row = conn.execute("SELECT service, label FROM credentials WHERE id = ?", (credential_id,)).fetchone()
        if row is None:
            raise KeyError("Credential not found.")
        _audit(conn, credential_id, "deleted", f"Deleted credential: {row['service']} / {row['label']}")
        conn.execute("DELETE FROM credentials WHERE id = ?", (credential_id,))


def list_audit_log(db_path: Path = DB_PATH) -> list[dict]:
    with managed_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT action, detail, created_at FROM audit_log ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return [dict(row) for row in rows]
