import mysql.connector
import hashlib
import os
import base64
from mysql.connector import errors as mysql_errors
import hmac

DB_HOST = "127.0.0.1"
DB_PORT = 3307
DB_USER = "scuser"
DB_PASS = "scpass"
DB_NAME = "securechat"

def connect():
    return mysql.connector.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME
    )

def init_db():
    conn = connect()
    cursor = conn.cursor()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE,
            salt VARCHAR(24),          -- Base64-encoded 16 bytes = 24 chars
            password_hash VARCHAR(44)   -- Base64-encoded 32 bytes = 44 chars
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()
    print(" DB initialized")

def add_user(username: str, password: str) -> bool:
    """
    Add a user to the DB.
    Return True on success, False on failure (e.g., duplicate user).
    """
    try:
        # Generate salt and hash
        salt = os.urandom(16)
        pw_hash = hashlib.sha256(salt + password.encode()).digest()

        # Encode as Base64 for safe storage
        salt_b64 = base64.b64encode(salt).decode()
        hash_b64 = base64.b64encode(pw_hash).decode()

        conn = connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, salt, password_hash) VALUES (%s, %s, %s)",
            (username, salt_b64, hash_b64)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return True

    except mysql_errors.IntegrityError:
        # Duplicate username
        if cursor:
            cursor.close()
        if conn:
            conn.close()
        return False
    except Exception as e:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
        print("[DB] add_user unexpected error:", e)
        return False

def verify_user(username: str, password: str) -> bool:
    """
    Verify a username/password pair using constant-time compare.
    """
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("SELECT salt, password_hash FROM users WHERE username=%s", (username,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if row is None:
        return False

    salt_b64, hash_b64 = row
    salt = base64.b64decode(salt_b64)
    pw_hash = base64.b64decode(hash_b64)

    computed = hashlib.sha256(salt + password.encode()).digest()
    return hmac.compare_digest(computed, pw_hash)

#phase 1 working code
# import mysql.connector
# import hashlib
# import os

# DB_HOST = "127.0.0.1"
# DB_PORT = 3307
# DB_USER = "scuser"
# DB_PASS = "scpass"
# DB_NAME = "securechat"

# def connect():
#     return mysql.connector.connect(
#        host=DB_HOST,
#     port=DB_PORT,
#     user=DB_USER,
#     password=DB_PASS,
#     database=DB_NAME
#     )


# def init_db():
#     conn = connect()
#     cursor = conn.cursor()
#     cursor.execute("""
#         CREATE TABLE IF NOT EXISTS users (
#             id INT AUTO_INCREMENT PRIMARY KEY,
#             username VARCHAR(50) UNIQUE,
#             salt BINARY(16),
#             password_hash BINARY(32)
#         )
#     """)
#     conn.commit()
#     cursor.close()
#     conn.close()
#     print(" DB initialized")

# def add_user(username: str, password: str):
#     salt = os.urandom(16)
#     h = hashlib.sha256(salt + password.encode()).digest()
#     conn = connect()
#     cursor = conn.cursor()
#     cursor.execute("INSERT INTO users (username, salt, password_hash) VALUES (%s,%s,%s)", (username, salt, h))
#     conn.commit()
#     cursor.close()
#     conn.close()

# def verify_user(username: str, password: str) -> bool:
#     conn = connect()
#     print("Connecton successful!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
#     cursor = conn.cursor()
#     cursor.execute("SELECT salt, password_hash FROM users WHERE username=%s", (username,))
#     row = cursor.fetchone()
#     cursor.close()
#     conn.close()
#     if row is None:
#         return False
#     salt, pw_hash = row
#     return hashlib.sha256(salt + password.encode()).digest() == pw_hash
