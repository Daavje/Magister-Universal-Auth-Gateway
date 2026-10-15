import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

@dataclass(frozen=True)
class Config:
    public_url: str
    database: str
    encryption_key: str
    magister_client_id: str
    magister_client_secret: str
    magister_authorize_url: str
    magister_token_url: str
    magister_calendar_url: str
    magister_scopes: str
    magister_from_param: str
    magister_to_param: str
    allow_test_http: bool
    uosh_url: str

    @property
    def magister_configured(self):
        return all((self.magister_client_id, self.magister_authorize_url,
                    self.magister_token_url, self.magister_calendar_url,
                    self.encryption_key))


def upstream_url(value: str, allow_test_http: bool = False) -> bool:
    try:
        u = urlparse(value)
        if not u.hostname or u.username or u.password or u.fragment:
            return False
        if u.scheme == 'https':
            return True
        return (allow_test_http and u.scheme == 'http' and
                u.hostname in ('127.0.0.1', 'localhost'))
    except ValueError:
        return False


def local_uosh_url(value: str) -> bool:
    """The upstream is safe to use only on literal IPv4 loopback."""
    if not value: return True
    try:
        u = urlparse(value)
        return (u.scheme=='http' and u.hostname=='127.0.0.1' and u.port is not None
                and 1<=u.port<=65535 and u.path in ('','/')
                and not u.query and not u.fragment and not u.username and not u.password
                and u.netloc == f'127.0.0.1:{u.port}')
    except ValueError:
        return False


def load_config() -> Config:
    from dotenv import load_dotenv
    load_dotenv(override=False)
    url = os.getenv('PUBLIC_BASE_URL', 'http://127.0.0.1:8000').rstrip('/')
    p = urlparse(url)
    if p.scheme not in ('http', 'https') or not p.netloc or p.path not in ('', '/') or p.query or p.fragment:
        raise ValueError('PUBLIC_BASE_URL must be an origin, e.g. https://auth.example.nl')
    if p.scheme != 'https' and p.hostname not in ('localhost', '127.0.0.1'):
        raise ValueError('Public hosting requires HTTPS; HTTP is only for localhost')
    path = os.getenv('DATABASE_PATH', './data/gateway.sqlite3')
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    allow_http = os.getenv('ALLOW_HTTP_UPSTREAM_FOR_TESTS') == '1'
    c = Config(
        public_url=url, database=path,
        encryption_key=os.getenv('TOKEN_ENCRYPTION_KEY', ''),
        magister_client_id=os.getenv('MAGISTER_CLIENT_ID', ''),
        magister_client_secret=os.getenv('MAGISTER_CLIENT_SECRET', ''),
        magister_authorize_url=os.getenv('MAGISTER_AUTHORIZE_URL', ''),
        magister_token_url=os.getenv('MAGISTER_TOKEN_URL', ''),
        magister_calendar_url=os.getenv('MAGISTER_CALENDAR_URL', ''),
        magister_scopes=os.getenv('MAGISTER_SCOPES', 'offline_access'),
        magister_from_param=os.getenv('MAGISTER_FROM_PARAM', 'from'),
        magister_to_param=os.getenv('MAGISTER_TO_PARAM', 'to'),
        allow_test_http=allow_http,
        uosh_url=os.getenv('UOSH_LOCAL_URL', '').rstrip('/'),
    )
    if not local_uosh_url(c.uosh_url):
        raise ValueError('UOSH_LOCAL_URL must be http://127.0.0.1:PORT')
    if c.uosh_url and not c.encryption_key:
        raise ValueError('UOSH connector requires TOKEN_ENCRYPTION_KEY')
    for u in (c.magister_authorize_url, c.magister_token_url, c.magister_calendar_url):
        if u and not upstream_url(u, allow_http):
            raise ValueError('Upstream Magister endpoint must be an explicit HTTPS URL')
    for param in (c.magister_from_param, c.magister_to_param):
        if not param.isidentifier():
            raise ValueError('Invalid parameter name')
    if c.magister_configured or c.uosh_url:
        from cryptography.fernet import Fernet
        Fernet(c.encryption_key.encode('ascii'))
    return c
