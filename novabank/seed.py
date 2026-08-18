"""
Seeds novabank.db with:
  - 3 dummy "client" accounts with randomly generated passwords
    (hashed before storage - the plaintext is never printed or logged,
     so you don't know them up front. You're meant to compromise one
     via the account-takeover / 2FA / OTP bugs, not by reading the db.)
  - A fresh, empty table ready for you to register your own account
    through the normal /register flow in the running app.

Run this once before starting app.py:
    python3 seed.py
"""

import sqlite3
import os
import random
import string
from werkzeug.security import generate_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "novabank.db")


def gen_account_number():
    return "NB" + "".join(random.choices(string.digits, k=10))


def gen_random_password(length=14):
    alphabet = string.ascii_letters + string.digits + "!@#$%"
    return "".join(random.choices(alphabet, k=length))


def main():
    if os.path.exists(DB_PATH):
        print(f"{DB_PATH} already exists. Delete it first if you want to reseed from scratch.")
        return

    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            account_number TEXT,
            balance REAL DEFAULT 0,
            mfa_enabled INTEGER DEFAULT 0
        );

        CREATE TABLE otp_store (
            user_id INTEGER,
            otp TEXT,
            created_at REAL
        );

        CREATE TABLE reset_tokens (
            token TEXT,
            user_id INTEGER,
            created_at REAL,
            used INTEGER DEFAULT 0
        );
        """
    )

    dummy_clients = [
        ("sarah.mendes", "sarah.mendes@example.com", "Sarah Mendes", 1),
        ("raj.kapoor",   "raj.kapoor@example.com",   "Raj Kapoor",   0),
        ("emily.chen",   "emily.chen@example.com",   "Emily Chen",   1),
    ]

    for username, email, full_name, mfa in dummy_clients:
        pw = gen_random_password()  # generated, hashed, and then forgotten - never printed
        db.execute(
            "INSERT INTO users (username, email, password_hash, full_name, account_number, balance, mfa_enabled) "
            "VALUES (?,?,?,?,?,?,?)",
            (username, email, generate_password_hash(pw), full_name,
             gen_account_number(), round(random.uniform(1000, 25000), 2), mfa),
        )

    db.commit()
    db.close()

    print("Seeded novabank.db with 3 dummy client accounts:")
    for username, email, full_name, mfa in dummy_clients:
        print(f"  - {username}  ({email})  2FA={'on' if mfa else 'off'}")
    print("\nPasswords were randomly generated and hashed - not printed anywhere.")
    print("Compromise these via the app's vulnerabilities, not by reading the db file.")
    print("\nRegister your own account at /register once the app is running.")


if __name__ == "__main__":
    main()
