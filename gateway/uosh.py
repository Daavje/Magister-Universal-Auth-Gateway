"""Optional local-only UOSHMagisterAPI connector.

UOSH runs a live Chromium session. Its API keys must never be exposed to clients.
Only a preconfigured IPv4 loopback endpoint is allowed, never user-supplied URLs.
"""
import datetime as dt
import json
import time

import httpx
from cryptography.fernet import InvalidToken

from .provider import ProviderError, cipher


class UOSHError(ProviderError):
    pass


def is_linked(db, user_id):
    with db.connect() as conn:
        return conn.execute('SELECT 1 FROM uosh_keys WHERE user_id=?', (user_id,)).fetchone() is not None


def store_key(db, config, user_id, api_key):
    if not config.uosh_url or not config.encryption_key:
        raise UOSHError('Local UOSH adapter is not configured')
    if not isinstance(api_key, str) or not 20 <= len(api_key) <= 256:
        raise UOSHError('Invalid upstream session key')
    encrypted = cipher(config).encrypt(api_key.encode()).decode()
    with db.transaction() as conn:
        conn.execute('''INSERT INTO uosh_keys(user_id,key_encrypted,updated_at) VALUES(?,?,?)
            ON CONFLICT(user_id) DO UPDATE SET key_encrypted=excluded.key_encrypted,
            updated_at=excluded.updated_at''', (user_id, encrypted, int(time.time())))


def load_key(db, config, user_id):
    if not config.uosh_url or not config.encryption_key:
        raise UOSHError('Local UOSH adapter is not configured')
    with db.connect() as conn:
        row = conn.execute('SELECT key_encrypted FROM uosh_keys WHERE user_id=?', (user_id,)).fetchone()
    if not row:
        raise UOSHError('Connect a UOSH session first')
    try:
        return cipher(config).decrypt(row['key_encrypted'].encode()).decode()
    except (InvalidToken, ValueError) as exc:
        raise UOSHError('Unable to decrypt stored UOSH session') from exc


async def _request(config, key, resource, params=None):
    if resource not in {'profile', 'schedule', 'homework', 'grades'} or not config.uosh_url:
        raise UOSHError('Unsupported or unconfigured upstream resource')
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=False, trust_env=False) as client:
            async with client.stream('GET', config.uosh_url + '/' + resource,
                                     params=params,
                                     headers={'X-API-Key': key, 'Accept': 'application/json'}) as response:
                if response.status_code in (401, 403):
                    raise UOSHError('UOSH session expired; reconnect')
                if response.status_code != 200:
                    raise UOSHError('Local UOSH service is unavailable')
                if 'application/json' not in response.headers.get('content-type', ''):
                    raise UOSHError('Unexpected UOSH content type')
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 1024 * 1024:
                        raise UOSHError('UOSH response is too large')
                obj = json.loads(body)
                if not isinstance(obj, dict) or obj.get('error'):
                    raise UOSHError('UOSH returned invalid data')
                return obj
    except (httpx.HTTPError, ValueError, UnicodeError) as exc:
        raise UOSHError('Cannot contact local UOSH service') from exc


async def verify_key(config, key):
    if not isinstance(key, str) or not 20 <= len(key) <= 256:
        raise UOSHError('Invalid upstream session key')
    profile = await _request(config, key, 'profile')
    if not profile or 'person_id' not in profile:
        raise UOSHError('Could not verify UOSH session profile')


async def get_resource(db, config, user_id, name):
    if name not in ('homework', 'grades'):
        raise UOSHError('Unsupported resource')
    return await _request(config, load_key(db, config, user_id), name)


def normalize_schedule(payload, day):
    lessons = payload.get('lessons')
    if not isinstance(lessons, list) or any(isinstance(x, dict) and 'error' in x for x in lessons):
        raise UOSHError('Unrecognized UOSH schedule format')
    result = []
    for index, entry in enumerate(lessons[:100]):
        if not isinstance(entry, dict):
            continue
        start, end = entry.get('start'), entry.get('einde')
        if not isinstance(start, str) or not isinstance(end, str) or not start or not end:
            continue
        result.append({
            'id': f'uosh-{day}-{index}',
            'title': str(entry.get('vak') or 'Les')[:240],
            'start': start[:50], 'end': end[:50],
            'location': str(entry.get('lokaal') or '')[:120],
            'teacher': str(entry.get('docent') or '')[:120],
            'cancelled': entry.get('uitgevallen') is True,
        })
    return result


async def get_calendar(db, config, user_id, start_date, end_date):
    first, last = dt.date.fromisoformat(start_date), dt.date.fromisoformat(end_date)
    if (last - first).days > 13:
        raise UOSHError('UOSH date range is limited to 14 days')
    key = load_key(db, config, user_id)
    events = []
    for days in range((last - first).days + 1):
        day = (first + dt.timedelta(days=days)).isoformat()
        payload = await _request(config, key, 'schedule', {'date': day})
        events.extend(normalize_schedule(payload, day))
    return sorted(events, key=lambda x: x['start'])
