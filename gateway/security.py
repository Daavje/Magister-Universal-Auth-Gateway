import base64
import hashlib
import hmac
import re
import secrets
from urllib.parse import urlparse
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
PKCE = re.compile(r'^[A-Za-z0-9_\-]{43,128}$')
CHALLENGE = re.compile(r'^[A-Za-z0-9_\-]{43}$')
SCOPES = {'profile', 'calendar.read', 'offline_access'}

def token(prefix=''):
    return prefix + secrets.token_urlsafe(48)

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def password_hash(password):
    if len(password) < 12 or len(password) > 256:
        raise ValueError('Password must contain 12-256 characters')
    return ph.hash(password)

def verify_password(hash_value, value):
    try:
        return ph.verify(hash_value, value)
    except (VerifyMismatchError, VerificationError):
        return False

def pkce_challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode()

def verify_pkce(verifier, challenge):
    return bool(PKCE.fullmatch(verifier) and hmac.compare_digest(pkce_challenge(verifier), challenge))

def redirect_valid(uri: str) -> bool:
    try:
        u = urlparse(uri)
        if u.username or u.password or u.fragment or not u.netloc:
            return False
        if u.scheme == 'https':
            return True
        if u.scheme == 'http' and u.hostname in ('localhost', '127.0.0.1'):
            return True
        return False
    except ValueError:
        return False
