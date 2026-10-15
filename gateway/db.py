import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from .security import digest, password_hash, redirect_valid, SCOPES

DDL = '''
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS clients (
 client_id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
 secret_hash TEXT, redirect_uris TEXT NOT NULL, cors_origins TEXT NOT NULL, allowed_scopes TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_codes (
 code_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
 redirect_uri TEXT NOT NULL, scope TEXT NOT NULL, challenge TEXT NOT NULL,
 expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
 id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
 scope TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS access_tokens (
 token_hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
 token_hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS provider_states (
 state_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 verifier TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS magister_links (
 user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 access_encrypted TEXT NOT NULL, refresh_encrypted TEXT NOT NULL,
 expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS uosh_keys (
 user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 key_encrypted TEXT NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS calendar_feeds (
 user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 encrypted_url TEXT NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user_id);
'''

class DB:
    def __init__(self, path):
        self.path = path
        with self.connect() as db:
            db.executescript(DDL)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA busy_timeout=10000')
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def transaction(self):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise

    def add_user(self, email, password):
        if '@' not in email or len(email) > 200:
            raise ValueError('Invalid email')
        with self.transaction() as db:
            cur = db.execute('INSERT INTO users(email,password_hash,created_at) VALUES (?,?,?)',
                             (email.lower().strip(), password_hash(password), int(time.time())))
            return cur.lastrowid

    def add_client(self, name, uris, kind, scopes, origins=None):
        if kind not in ('public', 'confidential'):
            raise ValueError('Client kind must be public or confidential')
        if not name or len(name) > 100 or not uris or any(not redirect_valid(uri) for uri in uris):
            raise ValueError('Invalid name or redirect URI')
        if not scopes or not set(scopes).issubset(SCOPES):
            raise ValueError('Invalid scopes')
        origins = origins or []
        for origin in origins:
            from urllib.parse import urlparse
            parsed = urlparse(origin)
            if (parsed.path or parsed.query or parsed.fragment or not parsed.hostname or
                parsed.scheme not in ('https', 'chrome-extension', 'moz-extension', 'http') or
                (parsed.scheme == 'http' and parsed.hostname not in ('localhost', '127.0.0.1'))):
                raise ValueError('Invalid CORS origin')
        from .security import token
        client_id = token('gw_')[:38]
        secret = token('gws_') if kind == 'confidential' else None
        with self.transaction() as db:
            db.execute('INSERT INTO clients VALUES(?,?,?,?,?,?,?,?)',
                       (client_id, name, kind, digest(secret) if secret else None,
                        json.dumps(uris), json.dumps(origins), ' '.join(sorted(set(scopes))), int(time.time())))
        return client_id, secret
