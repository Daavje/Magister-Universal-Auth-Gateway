"""An OPTIONAL, explicitly configured, authorized upstream OAuth connector.

No undocumented Magister login scraping, QR-code interception, password collection,
or assumption that Magister offers public OAuth client credentials.
"""
import datetime as dt
import json
import secrets
import time
from urllib.parse import urlencode
import httpx
from cryptography.fernet import Fernet
from .security import digest, pkce_challenge, token


class ProviderError(Exception):
    pass


def authorization_url(config, state, challenge):
    return config.magister_authorize_url + ('&' if '?' in config.magister_authorize_url else '?') + urlencode({
        'response_type': 'code', 'client_id': config.magister_client_id,
        'redirect_uri': config.public_url + '/providers/magister/callback',
        'scope': config.magister_scopes, 'state': state,
        'code_challenge': challenge, 'code_challenge_method': 'S256'
    })


def cipher(config):
    return Fernet(config.encryption_key.encode())


async def exchange_code(config, code, verifier):
    body = {'grant_type': 'authorization_code', 'code': code, 'code_verifier': verifier,
            'redirect_uri': config.public_url + '/providers/magister/callback',
            'client_id': config.magister_client_id}
    if config.magister_client_secret:
        body['client_secret'] = config.magister_client_secret
    return await token_request(config, body)


async def token_request(config, body):
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as client:
            r = await client.post(config.magister_token_url, data=body, headers={'Accept':'application/json'})
        if r.status_code != 200:
            raise ProviderError('Provider rejected OAuth request (HTTP '+str(r.status_code)+')')
        if len(r.content) > 1024 * 256:
            raise ProviderError('Provider token response is too large')
        data = r.json()
        if not isinstance(data, dict) or not isinstance(data.get('access_token'), str) or not data['access_token']:
            raise ProviderError('Provider did not return an access token')
        return data
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        raise ProviderError('Unable to contact authorized OAuth provider') from exc


def save_link(db, config, user_id, tokens, previous_refresh=''):
    f = cipher(config)
    access = tokens['access_token']
    refresh = tokens.get('refresh_token') or previous_refresh
    expires = max(1, min(86400, int(tokens.get('expires_in', 3600))))
    now = int(time.time())
    with db.transaction() as conn:
        conn.execute('''INSERT INTO magister_links(user_id,access_encrypted,refresh_encrypted,expires_at,updated_at)
          VALUES(?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET access_encrypted=excluded.access_encrypted,
          refresh_encrypted=excluded.refresh_encrypted,expires_at=excluded.expires_at,updated_at=excluded.updated_at''',
          (user_id, f.encrypt(access.encode()).decode(), f.encrypt(refresh.encode()).decode() if refresh else '',
           now + expires, now))


async def valid_access_token(db, config, user_id):
    with db.connect() as conn:
        link = conn.execute('SELECT * FROM magister_links WHERE user_id=?', (user_id,)).fetchone()
    if not link:
        raise ProviderError('Magister is not connected')
    f = cipher(config)
    access = f.decrypt(link['access_encrypted'].encode()).decode()
    if int(link['expires_at']) > int(time.time()) + 60:
        return access
    if not link['refresh_encrypted']:
        raise ProviderError('Magister session expired: reconnect required')
    refresh = f.decrypt(link['refresh_encrypted'].encode()).decode()
    body = {'grant_type': 'refresh_token', 'refresh_token': refresh, 'client_id':config.magister_client_id}
    if config.magister_client_secret:
        body['client_secret'] = config.magister_client_secret
    tokens = await token_request(config, body)
    save_link(db, config, user_id, tokens, previous_refresh=refresh)
    return tokens['access_token']


def normalize_calendar(payload):
    """Conservative mapper. Adjust only with documented, authorized provider schema."""
    if isinstance(payload, list):
        raw = payload
    elif isinstance(payload, dict):
        raw = next((payload[k] for k in ('items','events','afspraken','Items') if isinstance(payload.get(k),list)), None)
    else:
        raw = None
    if raw is None:
        raise ProviderError('Provider calendar schema is not recognized')
    events = []
    for item in raw[:500]:
        if not isinstance(item, dict):
            continue
        start = item.get('start') or item.get('Start') or item.get('startDateTime')
        end = item.get('end') or item.get('Einde') or item.get('endDateTime')
        if not isinstance(start,str) or not isinstance(end,str):
            continue
        title = item.get('title') or item.get('Omschrijving') or item.get('description') or 'Afspraak'
        location = item.get('location') or item.get('Lokatie') or item.get('lokaal') or ''
        events.append({'id':str(item.get('id',item.get('Id','')))[:100],
                       'title':str(title)[:240], 'start':start[:50], 'end':end[:50],
                       'location':str(location)[:120]})
    return events


async def get_calendar(db, config, user_id, start, end):
    token_value = await valid_access_token(db, config, user_id)
    # No app-supplied URL: targets can only be configured by the gateway operator.
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as client:
            response = await client.get(config.magister_calendar_url,
                params={config.magister_from_param:start, config.magister_to_param:end},
                headers={'Authorization':'Bearer '+token_value, 'Accept':'application/json'})
        if response.status_code == 401:
            raise ProviderError('Provider authorization expired; reconnect Magister')
        if response.status_code != 200 or len(response.content) > 1024*1024:
            raise ProviderError('Calendar provider unavailable (HTTP '+str(response.status_code)+')')
        return normalize_calendar(response.json())
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        raise ProviderError('Could not load calendar from provider') from exc
