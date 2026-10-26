import sqlite3
from typing import Optional, Dict, List
from passlib.context import CryptContext

DB_PATH = "identity_store.db"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            role_level INTEGER NOT NULL CHECK(role_level BETWEEN 1 AND 4)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL
        )
        """
    )

    conn.commit()
    conn.close()


def get_user(username: str) -> Optional[Dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute(
        "SELECT username, hashed_password, role_level FROM users WHERE username = ?",
        (username,),
    )
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def list_users() -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT username, role_level FROM users ORDER BY username ASC")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def create_user(username: str, password: str, role_level: int) -> None:
    hashed = pwd_context.hash(password)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO users (username, hashed_password, role_level) VALUES (?, ?, ?)",
        (username, hashed, int(role_level)),
    )

    conn.commit()
    conn.close()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_notes() -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT id, content FROM notes ORDER BY id ASC")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_note(content: str) -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("INSERT INTO notes (content) VALUES (?)", (content,))
    conn.commit()
    conn.close()

def delete_user(username: str) -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()