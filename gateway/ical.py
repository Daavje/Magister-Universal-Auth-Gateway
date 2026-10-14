"""Read-only Magister CloudAgenda iCalendar connector.

An iCalendar sharing URL is a bearer capability: encrypt at rest, never log,
never expose it to apps. Only the verified official Magister calendar host is
allowed; no arbitrary URL fetching or HTTP redirects.
"""
import datetime as dt
import re
import time
from urllib.parse import urlparse, urlunparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import httpx
from cryptography.fernet import Fernet
from dateutil.rrule import rrulestr
from .provider import ProviderError, cipher

OFFICIAL_HOSTS = {'calendar.magister.net', 'magister.net'}
MAGISTER_PATH = re.compile(r'^/api/icalendar/feeds?/[^/\s?#]+/?$',re.I)
CACHE={}

def feed_url(value):
    if not isinstance(value,str) or len(value)>2048:
        raise ValueError('Invalid Magister iCalendar URL')
    u=urlparse(value.strip())
    if (u.scheme not in ('https','webcal') or u.hostname not in OFFICIAL_HOSTS or
        u.port not in (None,443) or u.username or u.password or u.fragment or
        not MAGISTER_PATH.fullmatch(u.path)):
        raise ValueError('Only official Magister CloudAgenda feed links are supported')
    return urlunparse(('https',u.netloc,u.path,'',u.query,''))


def save_feed(db,config,user_id,url):
    normalized=feed_url(url)
    encrypted=cipher(config).encrypt(normalized.encode()).decode()
    with db.transaction() as conn:
        conn.execute('INSERT INTO calendar_feeds(user_id,encrypted_url,updated_at) VALUES (?,?,?) '
         'ON CONFLICT(user_id) DO UPDATE SET encrypted_url=excluded.encrypted_url,updated_at=excluded.updated_at',
         (user_id,encrypted,int(time.time())))
    CACHE.pop(user_id,None)


def has_feed(db,user_id):
    with db.connect() as conn:
        return bool(conn.execute('SELECT 1 FROM calendar_feeds WHERE user_id=?',(user_id,)).fetchone())


def ics_unescape(value):
    return (value.replace('\\n','\n').replace('\\N','\n').replace('\\,',',')
            .replace('\\;',';').replace('\\\\','\\'))


def ics_datetime(value,params):
    try:
        if re.fullmatch(r'\d{8}',value):
            return dt.datetime.strptime(value,'%Y%m%d').replace(tzinfo=ZoneInfo('Europe/Amsterdam'))
        if re.fullmatch(r'\d{8}T\d{6}Z',value):
            return dt.datetime.strptime(value,'%Y%m%dT%H%M%SZ').replace(tzinfo=dt.timezone.utc)
        if re.fullmatch(r'\d{8}T\d{6}',value):
            tz=params.get('TZID','Europe/Amsterdam').strip('"')
            return dt.datetime.strptime(value,'%Y%m%dT%H%M%S').replace(tzinfo=ZoneInfo(tz))
    except (ValueError,ZoneInfoNotFoundError):
        pass
    return None


def parse_ics(contents,first,last):
    if not isinstance(contents,str) or len(contents)>3_000_000:
        raise ProviderError('Calendar file too large')
    lines=[]
    for line in contents.replace('\r\n','\n').replace('\r','\n').split('\n'):
        if line.startswith((' ','\t')) and lines:lines[-1]+=line[1:]
        else:lines.append(line)
    if not any(x.strip()=='BEGIN:VCALENDAR' for x in lines[:8]):
        raise ProviderError('Not an iCalendar file')
    target_start=dt.datetime.combine(first,dt.time.min,tzinfo=dt.timezone.utc)-dt.timedelta(days=2)
    target_end=dt.datetime.combine(last+dt.timedelta(days=1),dt.time.min,tzinfo=dt.timezone.utc)+dt.timedelta(days=2)
    events=[]; current=None; max_events=500
    def put(key,val,params):
        current.setdefault(key,[]).append((val,params))
    for line in lines:
        if line=='BEGIN:VEVENT': current={}; continue
        if line=='END:VEVENT':
            if current is None:continue
            def firstval(k):return current.get(k,[('',{})])[0]
            start,sp=firstval('DTSTART'); end,ep=firstval('DTEND')
            starting=ics_datetime(start,sp); ending=ics_datetime(end,ep)
            if not starting:
                current=None;continue
            if not ending:ending=starting+dt.timedelta(hours=1)
            duration=ending-starting
            dates=[starting]
            rule,_=firstval('RRULE')
            if rule:
                try:
                    dates=list(rrulestr(rule,dtstart=starting).between(target_start.astimezone(starting.tzinfo),
                        target_end.astimezone(starting.tzinfo),inc=True))[:500]
                except (ValueError,TypeError):dates=[starting]
            excluded=set()
            for v,p in current.get('EXDATE',[]):
                for value in v.split(','):
                    parsed=ics_datetime(value,p)
                    if parsed:excluded.add(parsed.astimezone(dt.timezone.utc))
            for occurrence in dates:
                if occurrence.astimezone(dt.timezone.utc) in excluded:continue
                if occurrence.date() < first or occurrence.date()>last:continue
                title,_=firstval('SUMMARY');loc,_=firstval('LOCATION');uid,_=firstval('UID')
                events.append({'id':str(uid)[:100]+'-'+occurrence.isoformat(),
                  'title':ics_unescape(title)[:240], 'start':occurrence.isoformat(),
                  'end':(occurrence+duration).isoformat(), 'location':ics_unescape(loc)[:120]})
                if len(events)>=max_events:break
            current=None
            if len(events)>=max_events:break
            continue
        if current is not None and ':' in line:
            part,value=line.split(':',1)
            pieces=part.split(';');key=pieces[0].upper();params={}
            for p in pieces[1:]:
                if '=' in p:
                    k,v=p.split('=',1);params[k.upper()]=v
            if key in ('DTSTART','DTEND','RRULE','EXDATE','SUMMARY','LOCATION','UID'):
                put(key,value,params)
    return sorted(events,key=lambda x:x['start'])


async def calendar_from_feed(db,config,user_id,start,end):
    record=CACHE.get(user_id)
    if not record or record[0]<time.monotonic():
        with db.connect() as conn:
            row=conn.execute('SELECT encrypted_url FROM calendar_feeds WHERE user_id=?',(user_id,)).fetchone()
        if not row:raise ProviderError('CloudAgenda feed not linked')
        url=cipher(config).decrypt(row['encrypted_url'].encode()).decode()
        # Revalidate on retrieval. Never follow redirects to arbitrary hosts.
        url=feed_url(url)
        try:
            async with httpx.AsyncClient(timeout=10,follow_redirects=False,trust_env=False) as client:
                async with client.stream('GET',url,headers={'Accept':'text/calendar'}) as resp:
                    if resp.status_code!=200:
                        raise ProviderError('CloudAgenda responded with HTTP '+str(resp.status_code))
                    total=0; chunks=[]
                    async for chunk in resp.aiter_bytes():
                        total+=len(chunk)
                        if total>1_500_000:raise ProviderError('CloudAgenda response too large')
                        chunks.append(chunk)
            data=b''.join(chunks).decode('utf-8-sig',errors='replace')
            if 'BEGIN:VCALENDAR' not in data[:2000]:raise ProviderError('CloudAgenda returned no calendar')
        except httpx.HTTPError as exc:
            raise ProviderError('Unable to retrieve CloudAgenda') from exc
        CACHE[user_id]=(time.monotonic()+300,data)
    else:data=record[1]
    return parse_ics(data,dt.date.fromisoformat(start),dt.date.fromisoformat(end))
