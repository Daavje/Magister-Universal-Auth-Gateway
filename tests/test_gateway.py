import base64
import hashlib
import importlib
import os
import re
import secrets
from urllib.parse import parse_qs, urlparse
import pytest
from fastapi.testclient import TestClient
from gateway.db import DB
from gateway.security import pkce_challenge, verify_pkce, redirect_valid, password_hash
from gateway.provider import normalize_calendar, ProviderError

@pytest.fixture
def service(tmp_path,monkeypatch):
    import gateway.app as app_mod
    database=DB(str(tmp_path/'test.sqlite3'))
    monkeypatch.setattr(app_mod,'db',database)
    user=database.add_user('hello@example.nl','strong-test-password-2026')
    client_id,_=database.add_client('HWC Extension', ['http://127.0.0.1:9001/callback'], 'public', ['profile','calendar.read','offline_access'], ['chrome-extension://abcdefghijklmnopabcdefghijklmnop'])
    return TestClient(app_mod.app,follow_redirects=False),database,client_id


def csrf_from(response):
    return re.search(r'name="csrf"[^>]*value="([^"]+)"',response.text).group(1)


def login(client):
    r=client.get('/login')
    assert r.status_code==200
    r=client.post('/login',data={'email':'hello@example.nl','password':'strong-test-password-2026','next':'/','csrf':csrf_from(r)})
    assert r.status_code==303


def authorize(client,client_id,scope='profile offline_access',verifier=None,override=None):
    verifier=verifier or secrets.token_urlsafe(48)
    params={'response_type':'code','client_id':client_id,'redirect_uri':'http://127.0.0.1:9001/callback',
        'scope':scope,'code_challenge':pkce_challenge(verifier),'code_challenge_method':'S256','state':'opaque-state-12345'}
    params.update(override or {})
    get=client.get('/authorize',params=params)
    assert get.status_code==200
    consent=csrf_from(get)
    decided=client.post('/authorize/decision',data={**{k:params[k] for k in ('client_id','redirect_uri','scope','code_challenge','state')},'csrf':consent,'decision':'approve'})
    assert decided.status_code==303
    code=parse_qs(urlparse(decided.headers['location']).query)['code'][0]
    return code,verifier


def exchange(client,client_id,code,verifier):
    return client.post('/token',data={'grant_type':'authorization_code','client_id':client_id,
            'redirect_uri':'http://127.0.0.1:9001/callback','code':code,'code_verifier':verifier})


def test_metadata_and_health(service):
    client,_,_=service
    assert client.get('/healthz').json()['ok']
    meta=client.get('/.well-known/oauth-authorization-server').json()
    assert meta['code_challenge_methods_supported']==['S256']
    assert meta['grant_types_supported']==['authorization_code','refresh_token']


def test_login_and_oauth_flow(service):
    client,db,client_id=service
    login(client)
    code,verifier=authorize(client,client_id)
    tokens=exchange(client,client_id,code,verifier)
    assert tokens.status_code==200,tokens.text
    t=tokens.json()
    assert 'refresh_token' in t and 'access_token' in t
    who=client.get('/v1/me',headers={'Authorization':'Bearer '+t['access_token']})
    assert who.json()['email']=='hello@example.nl'
    assert client.get('/v1/calendar',headers={'Authorization':'Bearer '+t['access_token']},params={'from_date':'2026-10-15','to_date':'2026-10-20'}).status_code==403
    assert exchange(client,client_id,code,verifier).json()['error']=='invalid_grant'


def test_pkce_and_redirect_protections(service):
    client,db,cid=service
    login(client)
    bad=client.get('/authorize',params={'response_type':'code','client_id':cid,'redirect_uri':'https://evil.example/callback','scope':'profile',
        'code_challenge':pkce_challenge(secrets.token_urlsafe(48)),'code_challenge_method':'S256','state':'123456789'})
    assert bad.status_code==400 and not bad.headers.get('location')
    missing=client.get('/authorize',params={'response_type':'code','client_id':cid,'redirect_uri':'http://127.0.0.1:9001/callback',
        'scope':'profile','code_challenge_method':'plain','state':'123456789'})
    assert missing.status_code==400
    code,verifier=authorize(client,cid)
    assert exchange(client,cid,code,'wrong-verifier').json()['error']=='invalid_grant'
    assert exchange(client,cid,code,verifier).status_code==200


def test_refresh_rotation_replay_invalidates_entire_family(service):
    client,db,cid=service
    login(client)
    code,verifier=authorize(client,cid,scope='profile offline_access')
    old=exchange(client,cid,code,verifier).json()
    rotated=client.post('/token',data={'grant_type':'refresh_token','client_id':cid,'refresh_token':old['refresh_token']})
    assert rotated.status_code==200
    newest=rotated.json()
    assert newest['refresh_token']!=old['refresh_token']
    repeat=client.post('/token',data={'grant_type':'refresh_token','client_id':cid,'refresh_token':old['refresh_token']})
    assert repeat.json()['error']=='invalid_grant'
    assert client.get('/v1/me',headers={'Authorization':'Bearer '+newest['access_token']}).status_code==401


def test_scope_and_revocation(service):
    client,db,cid=service
    login(client)
    code,verifier=authorize(client,cid,'calendar.read offline_access')
    tokens=exchange(client,cid,code,verifier).json()
    assert client.get('/v1/me',headers={'Authorization':'Bearer '+tokens['access_token']}).status_code==403
    res=client.get('/v1/calendar',params={'from_date':'2026-10-15','to_date':'2026-10-20'},headers={'Authorization':'Bearer '+tokens['access_token']})
    assert res.status_code==503 and res.json()['error']=='provider_not_configured'
    assert client.post('/revoke',data={'client_id':cid,'token':tokens['refresh_token']}).status_code==200
    assert client.post('/token',data={'grant_type':'refresh_token','client_id':cid,'refresh_token':tokens['refresh_token']}).status_code==400


def test_consent_denial_and_local_login_not_open_redirect(service):
    client,db,cid=service
    login(client)
    verifier=secrets.token_urlsafe(48)
    params={'response_type':'code','client_id':cid,'redirect_uri':'http://127.0.0.1:9001/callback','scope':'profile',
            'code_challenge':pkce_challenge(verifier),'code_challenge_method':'S256','state':'valid-state-123'}
    c=client.get('/authorize',params=params)
    denied=client.post('/authorize/decision',data={**{k:params[k] for k in ('client_id','redirect_uri','scope','code_challenge','state')},'decision':'deny','csrf':csrf_from(c)})
    assert parse_qs(urlparse(denied.headers['location']).query)['error']==['access_denied']
    client.cookies.clear()
    p=client.get('/login',params={'next':'//evil.example'})
    login_post=client.post('/login',data={'email':'hello@example.nl','password':'strong-test-password-2026','next':'//evil.example','csrf':csrf_from(p)})
    assert login_post.headers['location']=='/'


def test_cross_origin_is_allowlisted(service):
    client,db,cid=service
    good=client.options('/token',headers={'Origin':'chrome-extension://abcdefghijklmnopabcdefghijklmnop','Access-Control-Request-Method':'POST'})
    assert good.headers.get('Access-Control-Allow-Origin')=='chrome-extension://abcdefghijklmnopabcdefghijklmnop'
    bad=client.options('/token',headers={'Origin':'https://malicious.example','Access-Control-Request-Method':'POST'})
    assert not bad.headers.get('Access-Control-Allow-Origin')


def test_confidential_client_and_introspection(service):
    client,db,cid=service
    other,secret=db.add_client('Server app',['http://localhost:8787/receive'],'confidential',['profile'])
    assert not client.post('/introspect',data={'client_id':other,'token':'fake'}).status_code==200
    assert client.post('/introspect',data={'client_id':other,'client_secret':secret,'token':'fake'}).json()=={'active':False}


def test_provider_events_accepted_and_unknown_schema_rejected():
    events=normalize_calendar({'items':[{'id':123,'title':'Natuurkunde','start':'2026-10-15T09:00:00','end':'2026-10-15T10:00:00','location':'B3'}]})
    assert events[0]['location']=='B3'
    assert events[0]['id']=='123'
    with pytest.raises(ProviderError):normalize_calendar({'error':'not an event list'})


def test_uri_security():
    assert redirect_valid('https://example.com/callback')
    assert not redirect_valid('https://user:pass@example.com')
    assert not redirect_valid('javascript:alert(1)')
    assert not redirect_valid('http://anywhere.example/callback')
    assert verify_pkce(secrets.token_urlsafe(48),pkce_challenge('x'*48)) is False

def test_client_bound_refresh_and_identity_isolation(service):
    client,db,cid=service
    login(client)
    code,verifier=authorize(client,cid,'profile offline_access')
    tokens=exchange(client,cid,code,verifier).json()
    other,_=db.add_client('Other web app',['http://127.0.0.1:2222/cb'],'public',['profile','offline_access'])
    denied=client.post('/token',data={'grant_type':'refresh_token','client_id':other,'refresh_token':tokens['refresh_token']})
    assert denied.json()['error']=='invalid_grant'
    owner=client.get('/v1/me',headers={'Authorization':'Bearer '+tokens['access_token']})
    assert owner.json()['source']=='gateway-local-account'


def test_gateway_dashboard_has_cloudagenda_form(service):
    client,db,cid=service
    login(client)
    home=client.get('/')
    assert home.status_code==200
    assert '/providers/magister/ical/connect' in home.text
    assert 'TOKEN_ENCRYPTION_KEY' not in home.text
