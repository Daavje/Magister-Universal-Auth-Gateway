import dataclasses
import datetime as dt
import re
from urllib.parse import parse_qs, urlparse
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from gateway.ical import feed_url, parse_ics, save_feed, has_feed, CACHE
from gateway.db import DB
from gateway.config import load_config
from gateway.provider import ProviderError

SAMPLE='''BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Magister//CloudAgenda//NL
BEGIN:VEVENT
UID:math1
DTSTART;TZID=Europe/Amsterdam:20261015T090000
DTEND;TZID=Europe/Amsterdam:20261015T100000
SUMMARY:Wiskunde B
LOCATION:A201
END:VEVENT
BEGIN:VEVENT
UID:series1
DTSTART;TZID=Europe/Amsterdam:20261012T110000
DTEND;TZID=Europe/Amsterdam:20261012T120000
RRULE:FREQ=WEEKLY;COUNT=4
EXDATE;TZID=Europe/Amsterdam:20261019T110000
SUMMARY:Biologie\\, practicum
LOCATION:Lab 1
END:VEVENT
END:VCALENDAR
'''

def test_cloudagenda_host_allowlist():
    assert feed_url('webcal://calendar.magister.net/api/icalendar/feed/abcd')=='https://calendar.magister.net/api/icalendar/feed/abcd'
    for bad in ('http://calendar.magister.net/api/icalendar/feed/abc',
                'https://calendar.magister.net.evil.io/api/icalendar/feed/abc',
                'https://127.0.0.1/api/icalendar/feed/abc',
                'https://calendar.magister.net.evil.tld/x',
                'https://calendar.magister.net@evil.tld/api/icalendar/feed/abc',
                'https://calendar.magister.net:444/api/icalendar/feed/abc',
                'https://calendar.magister.net/admin',
                'file:///etc/passwd'):
        with pytest.raises(ValueError):feed_url(bad)

def test_ical_timezone_recurrences_and_exclusions():
    result=parse_ics(SAMPLE,dt.date(2026,10,15),dt.date(2026,10,31))
    assert len(result)==2
    assert result[0]['title']=='Wiskunde B'
    assert [e['start'][:10] for e in result if e['title'].startswith('Biologie')]==['2026-10-26']
    assert '2026-10-19' not in [e['start'][:10] for e in result]
    assert all(e['start'].endswith('+02:00') or e['start'].endswith('+01:00') for e in result)
    assert any(e['title']=='Biologie, practicum' for e in result)

def test_invalid_calendar_file_is_rejected():
    with pytest.raises(ProviderError):parse_ics('not a real ICS',dt.date(2026,10,15),dt.date(2026,10,16))

def test_feed_url_encrypted_at_rest(tmp_path):
    db=DB(str(tmp_path/'db.sqlite3'))
    key=Fernet.generate_key().decode()
    settings=dataclasses.replace(load_config(),encryption_key=key)
    user=db.add_user('test@example.com','verystrongpassword2026')
    url='webcal://calendar.magister.net/api/icalendar/feed/example-secret-123'
    save_feed(db,settings,user,url)
    assert has_feed(db,user)
    assert 'example-secret-123' not in (tmp_path/'db.sqlite3').read_bytes().decode('utf-8',errors='ignore')

def test_ical_calendar_endpoint_with_cached_feed(tmp_path,monkeypatch):
    import gateway.app as application
    db=DB(str(tmp_path/'test.sqlite3'))
    key=Fernet.generate_key().decode()
    monkeypatch.setattr(application,'db',db)
    monkeypatch.setattr(application,'settings',dataclasses.replace(application.settings,encryption_key=key))
    owner=db.add_user('a@example.nl','passwordstrong123456')
    cid,_=db.add_client('Student App',['http://127.0.0.1:8888/callback'],'public',['calendar.read'])
    save_feed(db,application.settings,owner,'webcal://calendar.magister.net/api/icalendar/feed/test-private')
    CACHE[owner]=(float('inf'),SAMPLE)
    try:
        with db.transaction() as conn:
            conn.execute('INSERT INTO grants VALUES(?,?,?,?,?,?)',('grant',owner,cid,'calendar.read',0,123))
            from gateway.security import digest
            conn.execute('INSERT INTO access_tokens VALUES(?,?,?)',(digest('valid-access-token'),'grant',9999999999))
        with TestClient(application.app,follow_redirects=False) as client:
            r=client.get('/v1/calendar',params={'from_date':'2026-10-15','to_date':'2026-10-31'},headers={'Authorization':'Bearer valid-access-token'})
            assert r.status_code==200,r.text
            assert r.json()['source']=='magister-cloudagenda'
            assert r.json()['events'][0]['title']=='Wiskunde B'
            forbidden=client.get('/v1/calendar',params={'from_date':'2026-10-15','to_date':'2026-12-01'},headers={'Authorization':'Bearer valid-access-token'})
            assert forbidden.status_code==400
    finally:CACHE.clear()
