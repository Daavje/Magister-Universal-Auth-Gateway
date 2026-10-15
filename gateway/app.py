"""Small single-instance OAuth2 authorization and resource server.

Supported: Authorization Code + mandatory PKCE S256, opaque bearer access tokens,
rotating refresh tokens, revocation and introspection. This is NOT OIDC, and the
application's local user login is NOT a Magister login.
"""
import datetime as dt
import html
import json
import re
import secrets
import time
from collections import defaultdict, deque
from urllib.parse import quote, urlencode, urlparse
from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from .config import load_config
from .db import DB
from .security import token, digest, verify_password, verify_pkce, pkce_challenge, CHALLENGE, SCOPES
from .provider import (ProviderError, authorization_url, exchange_code, save_link,
                       get_calendar)
from .ical import save_feed, has_feed, calendar_from_feed, CACHE as ICAL_CACHE
from .uosh import (UOSHError, is_linked as uosh_linked, store_key as save_uosh_key,
                   verify_key as verify_uosh_key, get_calendar as uosh_calendar,
                   get_resource as uosh_resource)

settings = load_config()
db = DB(settings.database)
app = FastAPI(title='Universal Auth Gateway', version='0.1.0', docs_url=None, redoc_url=None)
app.mount('/static', StaticFiles(directory=str(Path(__file__).resolve().parent.parent / 'static')), name='static')
LOGIN_WINDOW = defaultdict(deque)
BASE = settings.public_url

def now(): return int(time.time())
def esc(v): return html.escape(str(v), quote=True)
def cookie_secure(): return settings.public_url.startswith('https://')

def err(reason='invalid_request', status=400, detail=None):
    return JSONResponse({'error':reason, **({'error_description':detail} if detail else {})},status_code=status,
        headers={'Cache-Control':'no-store','Pragma':'no-cache'})

def html_page(title, body, status=200):
    return HTMLResponse(f'''<!doctype html><html lang="nl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)} · Auth Gateway</title><link rel="stylesheet" href="/static/style.css"></head><body><main class="wrap"><header><a class="brand" href="/">✦ <b>Universal Auth Gateway</b></a><span class="pill">OAuth 2.0 + PKCE</span></header>{body}<footer>Geïsoleerde, optionele Magister-integratie · Nooit je Magister-wachtwoord invoeren op deze server.</footer></main></body></html>''',status_code=status,
       headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer'})

def client_row(client_id):
    with db.connect() as conn:
        return conn.execute('SELECT * FROM clients WHERE client_id=?',(client_id,)).fetchone()

def session_user(request):
    val=request.cookies.get('gw_session','')
    if not val: return None
    with db.connect() as conn:
        return conn.execute('''SELECT users.* FROM sessions JOIN users ON users.id=sessions.user_id
            WHERE sessions.token_hash=? AND sessions.expires_at>?''',(digest(val),now())).fetchone()

def csrf_new(response):
    val=token('csrf_')
    response.set_cookie('gw_csrf',val,secure=cookie_secure(),httponly=True,samesite='lax',max_age=1800,path='/')
    return val

def csrf_ok(request,value):
    cookie=request.cookies.get('gw_csrf','')
    return bool(cookie and value and secrets.compare_digest(cookie,value))

def same_site(request):
    origin=request.headers.get('origin','')
    return not origin or origin==BASE

def get_next(target):
    # No external redirects or injected authority: only the internal /authorize path.
    if target=='/' or target.startswith('/authorize?') and len(target)<3000 and not any(c in target for c in '\r\n\\'):
        return target
    return '/'

def rate_limit(ip,bucket,max_hits):
    t=time.monotonic(); key=(ip,bucket); q=LOGIN_WINDOW[key]
    while q and q[0]<t-60: q.popleft()
    if len(q)>=max_hits: return False
    q.append(t)
    return True

@app.middleware('http')
async def headers(request, call_next):
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Content-Security-Policy']="default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
    response.headers['Cache-Control']='no-store'
    if cookie_secure(): response.headers['Strict-Transport-Security']='max-age=31536000'
    return response

@app.get('/healthz')
def health(): return {'ok':True, 'version':'0.1.0'}

@app.get('/.well-known/oauth-authorization-server')
def metadata():
    return {'issuer':BASE, 'authorization_endpoint':BASE+'/authorize','token_endpoint':BASE+'/token',
        'revocation_endpoint':BASE+'/revoke', 'introspection_endpoint':BASE+'/introspect',
        'response_types_supported':['code'], 'grant_types_supported':['authorization_code','refresh_token'],
        'token_endpoint_auth_methods_supported':['none','client_secret_basic','client_secret_post'],
        'code_challenge_methods_supported':['S256'],
        'scopes_supported':sorted(SCOPES)}

@app.get('/')
def home(request:Request):
    user=session_user(request)
    if not user:
        return RedirectResponse('/login',status_code=303)
    with db.connect() as conn:
        grants=conn.execute('''SELECT grants.id,clients.name,grants.scope FROM grants JOIN clients
        ON grants.client_id=clients.client_id WHERE grants.user_id=? AND grants.revoked=0 ORDER BY grants.created_at DESC''', (user['id'],)).fetchall()
        linked=bool(conn.execute('SELECT 1 FROM magister_links WHERE user_id=?',(user['id'],)).fetchone())
        calendar_linked=has_feed(db,user['id'])
        browser_linked=uosh_linked(db,user['id'])
    card=''.join(f'<li><strong>{esc(x["name"])}</strong> <small>{esc(x["scope"])}</small><form action="/grants/revoke" method="post"><input name="grant_id" value="{esc(x["id"])}" type="hidden"><input name="csrf" value="_CSRF_" type="hidden"><button class="minor" type="submit">Intrekken</button></form></li>' for x in grants) or '<li>Geen verbonden applicaties.</li>'
    provider='''<p>Je account is gekoppeld aan een geautoriseerde Magister-provider.</p>
      <form method="post" action="/providers/magister/disconnect"><input type="hidden" name="csrf" value="_CSRF_"><button class="minor">Magister ontkoppelen</button></form>''' if linked else (
      '<p>De beheerder heeft een toegestane OAuth-provider geconfigureerd.</p><a class="button" href="/providers/magister/connect">Magister verbinden</a>' if settings.magister_configured else
      '<p>Nog niet geconfigureerd. Een officiële/geautoriseerde OAuth-client is nodig om Magister-gegevens te kunnen ophalen.</p>')
    calendar_controls=('<p>CloudAgenda is verbonden. Het rooster is beschikbaar voor geautoriseerde apps.</p>'
        if calendar_linked else '<p>De officiële Magister-deellink werkt zonder API-toegang. Genereer hem in Magister Web bij Instellingen → Agenda delen.</p>')
    calendar_controls += ('''<form method="post" action="/providers/magister/ical/connect"><label>Officiële Magister CloudAgenda URL
      <input name="url" type="url" required placeholder="https://calendar.magister.net/api/icalendar/feed/..." autocomplete="off"></label>
      <input name="csrf" type="hidden" value="_CSRF_"><button class="button">Agenda-deellink opslaan</button></form>''')
    if calendar_linked:
        calendar_controls += '''<form method="post" action="/providers/magister/ical/disconnect"><input name="csrf" type="hidden" value="_CSRF_"><button class="minor">Deellink verwijderen</button></form>'''
    local_uosh=(
        '<p>Lokale UOSH-sessie verbonden. De Chromium-browser moet blijven draaien.</p>'
        '<form method="post" action="/providers/uosh/disconnect">'
        '<input name="csrf" type="hidden" value="_CSRF_">'
        '<button class="minor">Sessie ontkoppelen</button></form>' if browser_linked else
        ('<p>Experimenteel en alleen lokaal. UOSH mag NOOIT openbaar bereikbaar zijn.</p>'
         '<form method="post" action="/providers/uosh/connect">'
         '<label>UOSH-sessie API-key<input type="password" name="api_key" '
         'minlength="20" maxlength="256" autocomplete="off" required></label>'
         '<input name="csrf" type="hidden" value="_CSRF_">'
         '<button class="button">Verbind lokale sessie</button></form>' if settings.uosh_url else
         '<p>Stel als beheerder UOSH_LOCAL_URL in om de lokale adapter te activeren.</p>')
    )
    page=html_page('Dashboard',f'''<section class="hero"><span class="kicker">JOUW CENTRALE AUTHENTICATIE</span>
     <h1>Welkom, {esc(user['email'].split('@')[0])}<span class="accent">.</span></h1>
     <p>Beheer op één plek welke applicaties toegang hebben tot jouw gegevens.</p></section>
     <div class="grid"><section class="card"><h2>Verbonden applicaties</h2><ul class="apps">{card}</ul></section>
     <section class="card"><h2>Magister-verbinding</h2>{provider}<p class="fine">We halen alleen gegevens op als je deze koppeling bewust activeert.</p></section></div>
     <section class="card bottom"><h2>UOSHMagisterAPI (experimenteel, lokaal)</h2>{local_uosh}</section>
     <section class="card bottom"><h2>Officiële Magister CloudAgenda</h2>{calendar_controls}</section>
     <section class="card bottom"><h2>Voor ontwikkelaars</h2><p>Gebruik OAuth Authorization Code + PKCE. Bekijk de <a href="/.well-known/oauth-authorization-server">metadata</a> of README in de repository.</p></section>
     <form method="post" action="/logout"><input type="hidden" name="csrf" value="_CSRF_"><button class="text-btn">Uitloggen →</button></form>''')
    value=token('csrf_')
    page.body=page.body.replace(b'_CSRF_',value.encode())
    page.headers['content-length']=str(len(page.body))
    page.set_cookie('gw_csrf',value,secure=cookie_secure(),httponly=True,samesite='lax',max_age=1800,path='/')
    return page

@app.get('/login')
def login_page(request:Request,next:str='/'):
    if session_user(request):return RedirectResponse(get_next(next),303)
    page=html_page('Inloggen',f'''<section class="card login"><span class="kicker">EIGEN GATEWAY-ACCOUNT</span><h1>Log in</h1>
      <p>Gebruik het lokale account dat je beheerder heeft aangemaakt. <strong>Niet</strong> je Magister-wachtwoord.</p>
      <form method="post" action="/login"><label>E-mail<input name="email" type="email" maxlength="200" required autocomplete="username"></label>
      <label>Wachtwoord<input name="password" type="password" required autocomplete="current-password"></label>
      <input type="hidden" name="next" value="{esc(get_next(next))}"><input name="csrf" type="hidden" value="_CSRF_">
      <button class="button" type="submit">Inloggen →</button></form></section>''')
    v=token('csrf_');page.body=page.body.replace(b'_CSRF_',v.encode());page.headers['content-length']=str(len(page.body));page.set_cookie('gw_csrf',v,secure=cookie_secure(),httponly=True,samesite='lax',max_age=1800,path='/')
    return page

@app.post('/login')
def do_login(request:Request,email:str=Form(''),password:str=Form(''),next:str=Form('/'),csrf:str=Form('')):
    ip=request.client.host if request.client else 'unknown'
    if not rate_limit(ip,'login',12):return html_page('Te veel verzoeken','<p>Probeer het over een minuut opnieuw.</p>',429)
    if not csrf_ok(request,csrf) or not same_site(request):return html_page('Ongeldig verzoek','<p>Ongeldige formulierbeveiliging.</p>',403)
    with db.connect() as conn:
        user=conn.execute('SELECT * FROM users WHERE email=?',(email.lower().strip(),)).fetchone()
    if not user or not verify_password(user['password_hash'],password):
        return html_page('Inloggen mislukt','<section class="card"><h1>Ongeldige inloggegevens</h1><a href="/login">Opnieuw proberen</a></section>',401)
    session=token('gwsess_')
    with db.transaction() as conn:
        conn.execute('INSERT INTO sessions VALUES(?,?,?)',(digest(session),user['id'],now()+7*86400))
    response=RedirectResponse(get_next(next),303)
    response.set_cookie('gw_session',session,httponly=True,secure=cookie_secure(),samesite='lax',max_age=7*86400,path='/')
    return response

@app.post('/logout')
def logout(request:Request, csrf:str=Form('')):
    if not csrf_ok(request,csrf) or not same_site(request):raise HTTPException(403)
    if request.cookies.get('gw_session'):
        with db.transaction() as conn:
            conn.execute('DELETE FROM sessions WHERE token_hash=?',(digest(request.cookies['gw_session']),))
    response=RedirectResponse('/login',303);response.delete_cookie('gw_session',path='/');return response

def validate_authorize(client_id,redirect_uri,response_type,scope,code_challenge,code_challenge_method,state):
    c=client_row(client_id)
    if not c or redirect_uri not in json.loads(c['redirect_uris']):
        return None,'Unknown application or redirect URI'
    if response_type!='code' or code_challenge_method!='S256' or not CHALLENGE.fullmatch(code_challenge or ''):
        return None,'Only authorization code + PKCE S256 is supported'
    requested=set(scope.split())
    if not requested or len(scope)>200 or not requested.issubset(SCOPES) or not requested.issubset(set(c['allowed_scopes'].split())):
        return None,'Scope is not permitted for this client'
    if not state or len(state)<8 or len(state)>1024:
        return None,'A client-generated state parameter is required'
    return c,None

def redirect_code(uri,**params):
    sep='&' if '?' in uri else '?'
    return RedirectResponse(uri+sep+urlencode(params),status_code=303,headers={'Referrer-Policy':'no-referrer'})

@app.get('/authorize')
def authorize(request:Request,client_id:str='',redirect_uri:str='',response_type:str='',scope:str='',code_challenge:str='',code_challenge_method:str='',state:str=''):
    c,error=validate_authorize(client_id,redirect_uri,response_type,scope,code_challenge,code_challenge_method,state)
    if error:return html_page('Onjuist OAuth-verzoek',f'<section class="card"><h1>Verbinding geweigerd</h1><p>{esc(error)}</p></section>',400)
    user=session_user(request)
    if not user:
        return RedirectResponse('/login?'+urlencode({'next':'/authorize?'+request.url.query}),303)
    v=token('csrf_')
    fields=''.join(f'<input type="hidden" name="{esc(k)}" value="{esc(val)}">' for k,val in (
        ('client_id',client_id),('redirect_uri',redirect_uri),('scope',scope),('code_challenge',code_challenge),('state',state)))
    page=html_page('Toegang verlenen',f'''<section class="card consent"><span class="kicker">TOESTEMMING GEVRAAGD</span>
    <h1>{esc(c['name'])}</h1><p>Deze applicatie vraagt namens <strong>{esc(user['email'])}</strong> toegang tot:</p>
    <ul>{''.join('<li>'+esc(s)+'</li>' for s in sorted(set(scope.split())))}</ul>
    <p class="fine">Controleer of je deze applicatie vertrouwt. Je kunt de toestemming later intrekken.</p>
    <form action="/authorize/decision" method="post">{fields}<input name="csrf" type="hidden" value="{esc(v)}">
    <div class="buttons"><button class="button" name="decision" value="approve">Toestaan</button>
    <button class="minor" name="decision" value="deny">Weigeren</button></div></form></section>''')
    page.set_cookie('gw_csrf',v,secure=cookie_secure(),httponly=True,samesite='lax',max_age=1800,path='/');return page

@app.post('/authorize/decision')
def authorize_decision(request:Request,client_id:str=Form(''),redirect_uri:str=Form(''),scope:str=Form(''),code_challenge:str=Form(''),state:str=Form(''),csrf:str=Form(''),decision:str=Form('deny')):
    user=session_user(request)
    if not user:return RedirectResponse('/login',303)
    if not csrf_ok(request,csrf) or not same_site(request):raise HTTPException(403)
    c,error=validate_authorize(client_id,redirect_uri,'code',scope,code_challenge,'S256',state)
    if error:return html_page('Fout',f'<p>{esc(error)}</p>',400)
    if decision!='approve':return redirect_code(redirect_uri,error='access_denied',state=state,iss=BASE)
    auth_code=token('gcode_')
    with db.transaction() as conn:
        conn.execute('INSERT INTO auth_codes VALUES(?,?,?,?,?,?,?)',
                     (digest(auth_code),user['id'],client_id,redirect_uri,' '.join(sorted(set(scope.split()))),code_challenge,now()+180))
    return redirect_code(redirect_uri,code=auth_code,state=state,iss=BASE)

def auth_client(form,authorization):
    client_id=form.get('client_id','');secret=form.get('client_secret','')
    if authorization and authorization.lower().startswith('basic '):
        import base64
        try:
            raw=base64.b64decode(authorization[6:],validate=True).decode()
            client_id,secret=raw.split(':',1)
            from urllib.parse import unquote_plus
            client_id,secret=unquote_plus(client_id),unquote_plus(secret)
        except Exception:return None
    c=client_row(client_id)
    if not c:return None
    if c['kind']=='confidential':
        if not secret or not secrets.compare_digest(c['secret_hash'],digest(secret)):return None
    elif secret:return None
    return c

def mint_tokens(conn,user_id,client_id,scope,grant_id=None,refresh_expiry=None):
    if grant_id is None:
        grant_id=token('grant_')[:45]
        conn.execute('INSERT INTO grants VALUES(?,?,?,?,?,?)',(grant_id,user_id,client_id,scope,0,now()))
    access=token('gw_at_')
    conn.execute('INSERT INTO access_tokens VALUES(?,?,?)',(digest(access),grant_id,now()+900))
    result={'access_token':access,'token_type':'Bearer','expires_in':900,'scope':scope}
    if 'offline_access' in scope.split():
        refresh=token('gw_rt_')
        conn.execute('INSERT INTO refresh_tokens VALUES(?,?,?,0)',
                     (digest(refresh),grant_id,refresh_expiry or now()+30*86400))
        result['refresh_token']=refresh
    return result

@app.post('/token')
async def token_endpoint(request:Request):
    ip=request.client.host if request.client else 'unknown'
    if not rate_limit(ip,'token',120):return err('slow_down',429)
    form=dict(await request.form())
    c=auth_client(form,request.headers.get('authorization',''))
    if not c:return err('invalid_client',401)
    grant_type=form.get('grant_type','')
    if grant_type=='authorization_code':
        code=form.get('code','');redirect_uri=form.get('redirect_uri','')
        verifier=form.get('code_verifier','')
        with db.transaction() as conn:
            row=conn.execute('SELECT * FROM auth_codes WHERE code_hash=?',(digest(code),)).fetchone()
            if not row or row['expires_at']<=now() or row['client_id']!=c['client_id'] or row['redirect_uri']!=redirect_uri or not verify_pkce(verifier,row['challenge']):
                return err('invalid_grant')
            conn.execute('DELETE FROM auth_codes WHERE code_hash=?',(digest(code),))
            issued=mint_tokens(conn,row['user_id'],c['client_id'],row['scope'])
        return JSONResponse(issued,headers={'Cache-Control':'no-store','Pragma':'no-cache'})
    if grant_type=='refresh_token':
        raw=form.get('refresh_token','')
        with db.transaction() as conn:
            row=conn.execute('''SELECT rt.*,g.user_id,g.client_id,g.scope,g.revoked FROM refresh_tokens rt
              JOIN grants g ON g.id=rt.grant_id WHERE rt.token_hash=?''',(digest(raw),)).fetchone()
            if not row or row['client_id']!=c['client_id'] or row['revoked'] or row['expires_at']<=now():return err('invalid_grant')
            if row['used']:
                # Replay: revoke whole authorization family, not just the old token.
                conn.execute('UPDATE grants SET revoked=1 WHERE id=?',(row['grant_id'],))
                return err('invalid_grant')
            conn.execute('UPDATE refresh_tokens SET used=1 WHERE token_hash=?',(digest(raw),))
            issued=mint_tokens(conn,row['user_id'],c['client_id'],row['scope'],row['grant_id'],row['expires_at'])
        return JSONResponse(issued,headers={'Cache-Control':'no-store','Pragma':'no-cache'})
    return err('unsupported_grant_type')

def bearer(request,required):
    auth=request.headers.get('authorization','')
    if not auth.startswith('Bearer '):raise HTTPException(401,'Bearer access token required',headers={'WWW-Authenticate':'Bearer'})
    with db.connect() as conn:
        row=conn.execute('''SELECT grants.user_id,grants.scope,grants.client_id FROM access_tokens
          JOIN grants ON grants.id=access_tokens.grant_id WHERE access_tokens.token_hash=?
          AND access_tokens.expires_at>? AND grants.revoked=0''',(digest(auth[7:]),now())).fetchone()
    if not row:raise HTTPException(401,'Invalid or expired token',headers={'WWW-Authenticate':'Bearer error="invalid_token"'})
    if required not in row['scope'].split():raise HTTPException(403,'Insufficient OAuth scope')
    return row

@app.get('/v1/me')
def me(request:Request):
    identity=bearer(request,'profile')
    with db.connect() as conn:
        u=conn.execute('SELECT id,email FROM users WHERE id=?',(identity['user_id'],)).fetchone()
    return {'sub':str(u['id']),'email':u['email'],'source':'gateway-local-account'}

@app.get('/v1/calendar')
async def calendar(request:Request,from_date:str='',to_date:str=''):
    identity=bearer(request,'calendar.read')
    if not uosh_linked(db,identity['user_id']) and not has_feed(db,identity['user_id']) and not settings.magister_configured:
        return err('provider_not_configured',503,'Connect local UOSH, CloudAgenda or authorized OAuth')
    try:
        first=dt.date.fromisoformat(from_date);last=dt.date.fromisoformat(to_date)
        if last<first or (last-first).days>31:raise ValueError()
    except ValueError:return err('invalid_date_range',400,'Use ISO dates within a 31-day range')
    try:
        browser_connected=uosh_linked(db,identity['user_id'])
        ical_connected=has_feed(db,identity['user_id'])
        if browser_connected and (last-first).days>13:
            return err('invalid_date_range',400,'UOSH supports up to 14 days')
        events=await (uosh_calendar(db,settings,identity['user_id'],from_date,to_date) if browser_connected else
                      calendar_from_feed(db,settings,identity['user_id'],from_date,to_date) if ical_connected else
                      get_calendar(db,settings,identity['user_id'],from_date,to_date))
        return {'source':'magister-uosh-local' if browser_connected else
                'magister-cloudagenda' if ical_connected else 'magister-oauth',
                'events':events,'from':from_date,'to':to_date}
    except ProviderError as exc:return err('provider_unavailable',503,str(exc))

@app.get('/v1/homework')
async def homework(request:Request):
    identity=bearer(request,'homework.read')
    if not uosh_linked(db,identity['user_id']):
        return err('provider_not_configured',503,'Connect your local UOSH session')
    try:
        result=await uosh_resource(db,settings,identity['user_id'],'homework')
        if not isinstance(result.get('homework'),list):
            return err('provider_unavailable',503,'Unexpected homework data')
        return {'source':'magister-uosh-local','homework':result['homework']}
    except UOSHError as exc:return err('provider_unavailable',503,str(exc))

@app.get('/v1/grades')
async def grades(request:Request):
    identity=bearer(request,'grades.read')
    if not uosh_linked(db,identity['user_id']):
        return err('provider_not_configured',503,'Connect your local UOSH session')
    try:
        result=await uosh_resource(db,settings,identity['user_id'],'grades')
        if not isinstance(result.get('grades'),list):
            return err('provider_unavailable',503,'Unexpected grade data')
        return {'source':'magister-uosh-local','grades':result['grades']}
    except UOSHError as exc:return err('provider_unavailable',503,str(exc))

@app.post('/revoke')
async def revoke(request:Request):
    form=dict(await request.form()); c=auth_client(form,request.headers.get('authorization',''))
    if not c:return err('invalid_client',401)
    value=form.get('token','')
    with db.transaction() as conn:
        row=conn.execute('''SELECT g.id,g.client_id FROM refresh_tokens rt JOIN grants g ON rt.grant_id=g.id WHERE rt.token_hash=?''',(digest(value),)).fetchone()
        if row and row['client_id']==c['client_id']:
            conn.execute('UPDATE grants SET revoked=1 WHERE id=?',(row['id'],))
        conn.execute('DELETE FROM access_tokens WHERE token_hash=? AND grant_id IN (SELECT id FROM grants WHERE client_id=?)',(digest(value),c['client_id']))
    return Response(status_code=200,headers={'Cache-Control':'no-store'})

@app.post('/introspect')
async def introspect(request:Request):
    form=dict(await request.form()); c=auth_client(form,request.headers.get('authorization',''))
    if not c or c['kind']!='confidential':return err('invalid_client',401)
    with db.connect() as conn:
        row=conn.execute('''SELECT g.*,at.expires_at FROM access_tokens at JOIN grants g ON at.grant_id=g.id
          WHERE at.token_hash=?''',(digest(form.get('token','')),)).fetchone()
    if not row or row['revoked'] or row['expires_at']<=now():return {'active':False}
    return {'active':True,'client_id':row['client_id'],'sub':str(row['user_id']),
            'scope':row['scope'],'exp':row['expires_at'],'token_type':'Bearer'}

@app.post('/grants/revoke')
def revoke_grant(request:Request,grant_id:str=Form(''),csrf:str=Form('')):
    user=session_user(request)
    if not user:raise HTTPException(401)
    if not same_site(request) or not csrf_ok(request,csrf):raise HTTPException(403)
    with db.transaction() as conn:
        conn.execute('UPDATE grants SET revoked=1 WHERE id=? AND user_id=?',(grant_id,user['id']))
    return RedirectResponse('/',303)

@app.get('/providers/magister/connect')
def upstream_connect(request:Request):
    user=session_user(request)
    if not user:return RedirectResponse('/login',303)
    if not settings.magister_configured:return html_page('Niet beschikbaar','<p>Provider is nog niet geconfigureerd met geautoriseerde Magister OAuth-toegang.</p>',503)
    state=token('upstate_');verifier=secrets.token_urlsafe(48)
    with db.transaction() as conn:
        conn.execute('INSERT INTO provider_states VALUES(?,?,?,?)',(digest(state),user['id'],verifier,now()+300))
    return RedirectResponse(authorization_url(settings,state,pkce_challenge(verifier)),303)

@app.get('/providers/magister/callback')
async def upstream_callback(request:Request,state:str='',code:str='',error:str=''):
    user=session_user(request)
    if not user:return html_page('Inloggen nodig','<p>Log eerst opnieuw in bij deze gateway.</p>',401)
    with db.transaction() as conn:
        saved=conn.execute('SELECT * FROM provider_states WHERE state_hash=? AND user_id=?',(digest(state),user['id'])).fetchone()
        if saved:conn.execute('DELETE FROM provider_states WHERE state_hash=?',(digest(state),))
    if not saved or saved['expires_at']<now() or error or not code:
        return html_page('Magister mislukt','<p>OAuth-koppeling geweigerd of verlopen.</p>',400)
    try:
        tokens=await exchange_code(settings,code,saved['verifier'])
        save_link(db,settings,user['id'],tokens)
    except ProviderError:
        return html_page('Magister mislukt','<p>De geautoriseerde provider heeft geen geldige toegang geleverd.</p>',502)
    return RedirectResponse('/',303)

@app.post('/providers/magister/disconnect')
def upstream_disconnect(request:Request,csrf:str=Form('')):
    user=session_user(request)
    if not user:raise HTTPException(401)
    if not csrf_ok(request,csrf) or not same_site(request):raise HTTPException(403)
    with db.transaction() as conn:
        conn.execute('DELETE FROM magister_links WHERE user_id=?',(user['id'],))
    return RedirectResponse('/',303)

@app.options('/token')
@app.options('/revoke')
@app.options('/v1/me')
@app.options('/v1/calendar')
@app.options('/v1/homework')
@app.options('/v1/grades')
async def options_cors(request:Request):
    origin=request.headers.get('origin','')
    client_id=request.headers.get('access-control-request-headers','')
    # A static safe subset of origin URLs is registered by operators. The actual
    # CORS policy is enforced for all real responses by the middleware below.
    return Response(status_code=204)

@app.middleware('http')
async def client_cors(request,call_next):
    response=await call_next(request)
    origin=request.headers.get('origin','')
    # Clients with a registered origin may exchange tokens and call APIs.
    # CORS is an additional browser protection; token possession still gates APIs.
    if origin and request.url.path in ('/token','/revoke','/v1/me','/v1/calendar','/v1/homework','/v1/grades'):
        with db.connect() as conn:
            rows=conn.execute('SELECT cors_origins FROM clients').fetchall()
        if any(origin in json.loads(row['cors_origins']) for row in rows):
            response.headers['Access-Control-Allow-Origin']=origin
            response.headers['Vary']='Origin'
            response.headers['Access-Control-Allow-Methods']='GET,POST,OPTIONS'
            response.headers['Access-Control-Allow-Headers']='Authorization,Content-Type'
            response.headers['Access-Control-Max-Age']='300'
    return response

@app.post('/providers/magister/ical/connect')
def ical_connect(request:Request,url:str=Form(''),csrf:str=Form('')):
    user=session_user(request)
    if not user:raise HTTPException(401)
    if not csrf_ok(request,csrf) or not same_site(request):raise HTTPException(403)
    if not settings.encryption_key:
        return html_page('Configuratie vereist','<p>Beheerder moet TOKEN_ENCRYPTION_KEY instellen.</p>',503)
    try:save_feed(db,settings,user['id'],url)
    except ValueError:return html_page('Ongeldige agenda URL','<p>Gebruik alleen de officiële CloudAgenda-link uit Magister Web.</p>',400)
    return RedirectResponse('/',303)

@app.post('/providers/magister/ical/disconnect')
def ical_disconnect(request:Request,csrf:str=Form('')):
    user=session_user(request)
    if not user:raise HTTPException(401)
    if not csrf_ok(request,csrf) or not same_site(request):raise HTTPException(403)
    with db.transaction() as conn:
        conn.execute('DELETE FROM calendar_feeds WHERE user_id=?',(user['id'],))
    ICAL_CACHE.pop(user['id'],None)
    return RedirectResponse('/',303)


@app.post('/providers/uosh/connect')
async def uosh_connect(request:Request,api_key:str=Form(''),csrf:str=Form('')):
    user=session_user(request)
    if not user:raise HTTPException(401)
    if not csrf_ok(request,csrf) or not same_site(request):raise HTTPException(403)
    if not settings.uosh_url or not settings.encryption_key:
        return html_page('Niet beschikbaar','<p>Lokale UOSH-adapter is niet geconfigureerd.</p>',503)
    try:
        await verify_uosh_key(settings,api_key)
        save_uosh_key(db,settings,user['id'],api_key)
    except UOSHError:
        return html_page('UOSH koppeling mislukt','<p>Controleer of UOSH draait en de sessiesleutel klopt.</p>',400)
    return RedirectResponse('/',303)

@app.post('/providers/uosh/disconnect')
def uosh_disconnect(request:Request,csrf:str=Form('')):
    user=session_user(request)
    if not user:raise HTTPException(401)
    if not csrf_ok(request,csrf) or not same_site(request):raise HTTPException(403)
    with db.transaction() as conn:
        conn.execute('DELETE FROM uosh_keys WHERE user_id=?',(user['id'],))
    return RedirectResponse('/',303)
