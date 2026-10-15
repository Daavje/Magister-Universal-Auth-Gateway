import asyncio
from unittest.mock import patch

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from gateway.config import local_uosh_url
from gateway.db import DB
from gateway.security import digest, token
from gateway.uosh import UOSHError, is_linked, load_key, normalize_schedule, store_key, verify_key, get_resource


def test_only_literal_ipv4_loopback_allowed():
    assert local_uosh_url('http://127.0.0.1:8010')
    for value in ['http://localhost:8010', 'http://0.0.0.0:8010',
                  'https://evil.test', 'http://127.0.0.1.attacker.test:8010',
                  'http://127.0.0.1:8010/secret', 'http://127.0.0.1:8010?key=abc',
                  'http://user:pass@127.0.0.1:8010', 'http://127.0.0.1:99999']:
        assert not local_uosh_url(value), value


def test_schema_accepts_empty_and_cancelled_lessons():
    assert normalize_schedule({'lessons': []}, '2026-10-15') == []
    result = normalize_schedule({'lessons': [
        {'vak': 'Wiskunde', 'lokaal': 'A1', 'docent': 'Docent',
         'start': '2026-10-15T10:00:00', 'einde': '2026-10-15T10:50:00',
         'uitgevallen': True}]}, '2026-10-15')
    assert result[0]['title'] == 'Wiskunde'
    assert result[0]['teacher'] == 'Docent'
    assert result[0]['cancelled'] is True
    with pytest.raises(UOSHError):
        normalize_schedule({'error': 'upstream'}, '2026-10-15')


def configured(tmp_path):
    import os
    from gateway.config import load_config
    with patch.dict(os.environ, {
        'PUBLIC_BASE_URL': 'http://127.0.0.1:8000',
        'DATABASE_PATH': str(tmp_path/'test.sqlite'),
        'TOKEN_ENCRYPTION_KEY': Fernet.generate_key().decode(),
        'UOSH_LOCAL_URL': 'http://127.0.0.1:8010',
    }):
        return load_config()


def test_encrypted_keys_are_isolated(tmp_path):
    config = configured(tmp_path)
    db = DB(config.database)
    one = db.add_user('one@example.com','very-strong-password-one')
    two = db.add_user('two@example.com','very-strong-password-two')
    key = 'random_uosh_key_' + 'S'*40
    store_key(db, config, one, key)
    assert is_linked(db, one) and not is_linked(db, two)
    assert load_key(db, config, one) == key
    with db.connect() as conn:
        encrypted = conn.execute('SELECT key_encrypted FROM uosh_keys WHERE user_id=?',(one,)).fetchone()[0]
    assert key not in encrypted
    with pytest.raises(UOSHError):
        load_key(db, config, two)


def test_upstream_header_only_with_mock(monkeypatch, tmp_path):
    from gateway import uosh
    config=configured(tmp_path)
    db=DB(config.database)
    user=db.add_user('one@example.com','very-strong-password-one')
    key='random_uosh_key_' + 'S'*40
    store_key(db,config,user,key)
    calls=[]
    def handler(request):
        calls.append(request)
        assert request.headers['x-api-key']==key
        assert 'api_key' not in str(request.url)
        assert request.url.host=='127.0.0.1'
        if request.url.path=='/profile':
            return httpx.Response(200,json={'person_id':123})
        if request.url.path=='/homework':
            return httpx.Response(200,json={'homework':[{'vak':'Wiskunde'}]})
        return httpx.Response(404)
    original=httpx.AsyncClient
    monkeypatch.setattr(uosh.httpx,'AsyncClient',lambda **kw: original(transport=httpx.MockTransport(handler),**kw))
    asyncio.run(verify_key(config,key))
    assert asyncio.run(get_resource(db,config,user,'homework'))['homework'][0]['vak']=='Wiskunde'
    assert len(calls)==2


def test_scoped_gateway_response_uses_uosh(monkeypatch, tmp_path):
    import gateway.app as app_mod
    config=configured(tmp_path)
    db=DB(config.database)
    monkeypatch.setattr(app_mod,'db',db)
    monkeypatch.setattr(app_mod,'settings',config)
    uid=db.add_user('student@example.com','strong-password-student')
    client_id,_=db.add_client('test-app',['http://127.0.0.1:9000/callback'],
                              'public',['homework.read','calendar.read'])
    store_key(db,config,uid,'key_'+'A'*48)
    access=token('access_')
    with db.transaction() as conn:
        conn.execute('INSERT INTO grants VALUES(?,?,?,?,?,?)',('grant123',uid,client_id,'homework.read',0,1800000000))
        conn.execute('INSERT INTO access_tokens VALUES(?,?,?)',(digest(access),'grant123',1800000000))
    async def mock_resource(_db,_settings,_uid,name):
        assert name=='homework' and _uid==uid
        return {'homework':[{'vak':'Biologie'}]}
    monkeypatch.setattr(app_mod,'uosh_resource',mock_resource)
    client=TestClient(app_mod.app)
    result=client.get('/v1/homework',headers={'Authorization':'Bearer '+access})
    assert result.status_code==200 and result.json()['homework'][0]['vak']=='Biologie'
    denied=client.get('/v1/calendar',headers={'Authorization':'Bearer '+access},
                      params={'from_date':'2026-10-15','to_date':'2026-10-17'})
    assert denied.status_code==403
