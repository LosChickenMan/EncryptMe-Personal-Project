# database_manager.py
# SQLite persistence and database encryption/decryption operations.

import os
import base64
import sqlite3
from concurrent.futures import ProcessPoolExecutor, as_completed
from tempfile import NamedTemporaryFile

from AES-Algorithm import AES256CTR

def _iter_fetchmany(cursor, batch_size=FETCH_BATCH_ROWS):
    while True:
        rows = cursor.fetchmany(batch_size)
        if not rows:
            return
        yield rows

def worker_encrypt_batch(batch_rows, col_count, key_bytes):
    '''
    Encrypts each non-null cell in batch_rows using AES-256-CTR and returns
    a list of tuples with base64(nonce||ciphertext) strings (or None).
    '''

    aes = AES256CTR(key_bytes)
    out_rows = []
    for row in batch_rows:
        enc_vals = []
        for j in range(col_count):
            v = row[j]
            if v is None:
                enc_vals.append(None)
                continue
            if isinstance(v, (bytes, bytearray)):
                plain = bytes(v)
            else:
                plain = str(v).encode('utf-8', 'ignore')
            ct = aes.AES_256_CTR_encrypt_bytes(plain)
            enc_vals.append(base64.b64encode(ct).decode('ascii'))
        out_rows.append(tuple(enc_vals))
    return out_rows

class DatabaseManager:
    def __init__(self, db_name=None):
        self.db_name = db_name or APP_DB_PATH
        init_app_db(self.db_name)

    def add_user(self, email_hash, password_hash, salt):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute('\n                INSERT INTO users (email_hash, password_hash, salt)\n                VALUES (?, ?, ?)\n            ', (email_hash, password_hash, salt))
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_user_by_email_hash(self, email_hash):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('\n            SELECT id, email_hash, password_hash, salt FROM users WHERE email_hash = ?\n        ', (email_hash,))
        user = cursor.fetchone()
        conn.close()
        return user

    def get_user_id_by_email_hash(self, email_hash):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE email_hash = ?', (email_hash,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

    def encrypt_db_attributes_to_bytes(self, src_db_path: str, key: bytes, progress_cb=None) -> bytes:
        '''
        Single-threaded: encrypt ALL attributes (including keys) of every user table.
        - Builds a TEXT-only shadow table where each non-null cell is base64(nonce||ciphertext).
        - Replaces the original table with the encrypted shadow.
        - Returns the encrypted database bytes.
        '''

        from tempfile import NamedTemporaryFile
        with NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        try:
            with open(src_db_path, 'rb') as rf:
                with open(tmp_path, 'wb') as wf:
                    wf.write(rf.read())
            conn = sqlite3.connect(tmp_path)
            c = conn.cursor()
            c.execute('PRAGMA foreign_keys=OFF')
            c.execute('\n                CREATE TABLE IF NOT EXISTS "__encryptme_meta__" (\n                    table_name TEXT PRIMARY KEY,\n                    create_sql TEXT NOT NULL\n                )\n            ')
            c.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name <> '__encryptme_meta__'")
            tables = c.fetchall()
            total_blocks = 0
