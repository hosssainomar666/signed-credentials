"""SQLite storage. All queries are parameterized."""
import contextlib
import sqlite3
from dataclasses import dataclass, fields

SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
  id INTEGER PRIMARY KEY,
  serial TEXT NOT NULL UNIQUE,
  token TEXT NOT NULL UNIQUE,
  key_id TEXT NOT NULL,
  credential_type TEXT NOT NULL CHECK (credential_type IN ('membership','noc','approval')),
  holder_name TEXT NOT NULL,
  holder_org TEXT NOT NULL DEFAULT '',
  purpose TEXT NOT NULL DEFAULT '',
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  pdf_file TEXT NOT NULL,
  pdf_sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credentials_pdf_sha256 ON credentials(pdf_sha256);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  credential_id INTEGER REFERENCES credentials(id),
  kind TEXT NOT NULL CHECK (kind IN ('issued','verified','pdf_checked','revoked','integrity_failed')),
  detail TEXT NOT NULL DEFAULT '',
  at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_events_credential ON events(credential_id);
"""


@dataclass(frozen=True)
class Credential:
    id: int
    serial: str
    token: str
    key_id: str
    credential_type: str
    holder_name: str
    holder_org: str
    purpose: str
    issued_at: str
    expires_at: str
    status: str
    pdf_file: str
    pdf_sha256: str

    @classmethod
    def from_row(cls, row):
        return cls(**{f.name: row[f.name] for f in fields(cls)}) if row else None


class Store:
    def __init__(self, path):
        self.path = str(path)

    @contextlib.contextmanager
    def connection(self):
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')
        try:
            yield conn
        finally:
            conn.close()

    @contextlib.contextmanager
    def transaction(self):
        """BEGIN IMMEDIATE ... COMMIT, or ROLLBACK if the body raises.
        IMMEDIATE takes the write lock up front so concurrent issuers queue up."""
        with self.connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            try:
                yield conn
            except BaseException:
                try:
                    conn.execute('ROLLBACK')
                except sqlite3.Error:
                    pass
                raise
            else:
                conn.execute('COMMIT')

    def init_schema(self):
        with self.connection() as conn:
            conn.executescript(SCHEMA)

    # ---- writes (take the connection of an open transaction) ----
    def next_number(self, conn):
        return conn.execute('SELECT COALESCE(MAX(id), 0) + 1 FROM credentials').fetchone()[0]

    def insert(self, conn, **v):
        conn.execute(
            'INSERT INTO credentials (id, serial, token, key_id, credential_type, holder_name, '
            'holder_org, purpose, issued_at, expires_at, pdf_file, pdf_sha256) '
            'VALUES (:id, :serial, :token, :key_id, :credential_type, :holder_name, '
            ':holder_org, :purpose, :issued_at, :expires_at, :pdf_file, :pdf_sha256)', v)

    def add_event(self, conn, credential_id, kind, detail=''):
        conn.execute('INSERT INTO events (credential_id, kind, detail) VALUES (?, ?, ?)',
                     (credential_id, kind, detail[:200]))

    def set_revoked(self, conn, serial):
        return conn.execute("UPDATE credentials SET status = 'revoked' WHERE serial = ?",
                            (serial,)).rowcount

    # ---- reads ----
    def _one(self, sql, param):
        with self.connection() as conn:
            return Credential.from_row(conn.execute(sql, (param,)).fetchone())

    def get_by_token(self, token):
        return self._one('SELECT * FROM credentials WHERE token = ?', token)

    def get_by_serial(self, serial):
        return self._one('SELECT * FROM credentials WHERE serial = ?', serial)

    def get_by_hash(self, sha256):
        return self._one('SELECT * FROM credentials WHERE pdf_sha256 = ?', sha256)

    def list_credentials(self):
        with self.connection() as conn:
            rows = conn.execute('SELECT * FROM credentials ORDER BY id').fetchall()
        return [Credential.from_row(r) for r in rows]

    def count_events(self, kind, credential_id=None):
        sql, params = 'SELECT COUNT(*) FROM events WHERE kind = ?', [kind]
        if credential_id is not None:
            sql += ' AND credential_id = ?'
            params.append(credential_id)
        with self.connection() as conn:
            return conn.execute(sql, params).fetchone()[0]
