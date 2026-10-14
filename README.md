# Universal Auth Gateway ✦

**Zelf te hosten OAuth 2.0-centrale voor meerdere applicaties**, oorspronkelijk bedacht voor schoolprojecten en de HWC-browserextensie. Volledig opnieuw geschreven. Geen onderdeel van Magister, Iddink of Schoologica.

> **Status: bèta voor eigen gebruik/testen.** De kern is getest, maar dit is géén gecertificeerde OpenID Connect-server en de koppeling met een officiële Magister OAuth-API is nog **niet** in de praktijk gevalideerd. Zet dit niet zomaar open als publieke inlogdienst voor een hele school. Laat eerst een beveiligingsreview uitvoeren.

## Wat kan deze gateway?

- **Eén gateway, meerdere apps**: Chrome/Edge-extensies, websites, mobiele apps en backendtools.
- **OAuth 2.0 Authorization Code + PKCE (S256)** voor elke app, ook serverapps.
- **Clientregistratie via CLI**, exacte redirect-URL's, per-app machtigingen (`profile`, `calendar.read`, `offline_access`).
- **Toestemmingsscherm**: elke app vraagt toestemming. Je kunt toegang intrekken in het dashboard.
- **Tokens veilig beheren**: korte access-tokens, éénmalige codes, roterende refresh-tokens en detectie van hergebruik. Alleen hashes van gateway-tokens worden opgeslagen.
- **Optionele vertrouwelijke serverclients** (client-secret, hashed opgeslagen), introspection en token revocation.
- **Officiële Magister CloudAgenda**: koppel een persoonlijke, door Magister zelf uitgegeven iCalendar-deellink. De gateway levert jouw rooster aan apps die toestemming hebben gekregen.
- **Optionele Magister OAuth-provideradapter**: alleen bruikbaar indien je een **geautoriseerde** client en bijbehorende technische documentatie hebt. Geen credentials-/QR-onderschepping.
- Lokale accounts via Argon2, versleutelde bewaarde koppelingen (Fernet), CSRF-bescherming, beperkte CORS, SQLite.

## Eenvoudig lokaal starten

Vereisten: Python 3.12+, of Docker; geen bankgegevens of externe cloud nodig om lokaal te testen.

```bash
git clone https://github.com/Daavje/Magister-Universal-Auth-Gateway.git
cd Magister-Universal-Auth-Gateway
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env   # Windows PowerShell: Copy-Item .env.example .env
```

Maak een encryptiesleutel:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Vul deze in bij `TOKEN_ENCRYPTION_KEY` in `.env`. **Bewaar deze sleutel:** als je hem verliest kun je opgeslagen Magister-deellinks en OAuth-provider-tokens niet meer ontsleutelen. Deel hem nooit via GitHub of chat.

Maak je eigen gateway-account aan:

```bash
python -m gateway.cli create-user --email jij@voorbeeld.nl
```

Start de gateway:

```bash
uvicorn gateway.app:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000** en log in met je zojuist aangemaakte **lokale gateway-wachtwoord** (niet je Magister-wachtwoord).

## Magister automatisch laten synchroniseren (officiële methode)

Magister publiceert zelf een officiële **CloudAgenda / Agenda delen** iCalendar-link. Daarmee kunnen agenda-apps je rooster ophalen. [Officiële handleiding](https://service.magister.nl/support/solutions/articles/101000454924-agenda-delen).

1. Log in op **Magister Web** van je school (rechtstreeks op de officiële website).
2. Ga naar **Instellingen → Agenda delen** en maak een deellink aan. Deze instelling kan door de school zijn uitgeschakeld.
3. Open jouw **Universal Auth Gateway** en plak die link bij **Officiële Magister CloudAgenda**. Bewaar hem als geheim: iedereen met deze link kan jouw gedeelde rooster lezen.
4. Apps met `calendar.read` kunnen via `/v1/calendar` je afspraken ophalen. De gateway leest de feed hooguit één keer per vijf minuten zolang er verzoeken zijn; daarna opnieuw bij het eerstvolgende verzoek.

**Grenzen:** Dit levert het gedeelde **rooster en beschikbaarheid**. Het is geen volledige Magister API: cijfers, privéhuiswerkgegevens en alle toetsdetails zijn niet gegarandeerd aanwezig. Bronwijzigingen kunnen vertraagd zichtbaar worden. Magister blijft de meest actuele bron. iCalendar-bewerkingen van complexe terugkerende afspraken kunnen niet in alle gevallen correct weergegeven worden.

**Beveiliging CloudAgenda:** Alleen Magister-feed-URL's op `calendar.magister.net` of het oudere `magister.net`, met `/api/icalendar/feed...` worden geaccepteerd. Geen redirects, geen willekeurige hostnamen. De URL wordt versleuteld opgeslagen en wordt nooit teruggegeven aan gekoppelde apps.

## Apps registreren

Voor je browserextensie (vervang `EXTENSION_ID` door de echte Chrome extension ID en kopieer exact de redirect-URL van `chrome.identity.getRedirectURL()`):

```bash
python -m gateway.cli register-client \
  --name "HWC Dashboard Next" --kind public \
  --redirect-uri "https://EXTENSION_ID.chromiumapp.org/" \
  --origin "chrome-extension://EXTENSION_ID" \
  --scopes profile calendar.read offline_access
```

Voor een website (serverapp):

```bash
python -m gateway.cli register-client \
  --name "Mijn website" --kind confidential \
  --redirect-uri "https://mijnsite.example/oauth/callback" \
  --scopes profile calendar.read offline_access
```

De CLI toont een `client_id`, en voor vertrouwelijke serverclients éénmalig een `client_secret`. **Plaats dit secret nooit in frontend-code of een browserextensie.**

Voor een lokaal script (open de weergegeven autorisatie-URL in dezelfde browser waarin je op de gateway bent ingelogd):

```bash
python -m gateway.cli register-client --name "CLI demo" \
  --kind public --redirect-uri "http://127.0.0.1:8765/callback" \
  --scopes profile calendar.read offline_access
GATEWAY_URL=http://127.0.0.1:8000 CLIENT_ID=gw_... node examples/cli-pkce-client.mjs
```

Je kunt meer apps registreren zonder een nieuwe gateway te maken. Ze hebben eigen rechten en tokens.

## OAuth API voor developers

OAuth-metadata: `GET /.well-known/oauth-authorization-server`.

| Endpoint | Actie |
|---|---|
| `GET /authorize` | Start Authorization Code + PKCE S256 |
| `POST /token` | Auth-code of refresh-token omwisselen |
| `POST /revoke` | Toegang intrekken |
| `POST /introspect` | Tokenstatus (vertrouwelijke clients) |
| `GET /v1/me` | Gateway-profiel (`profile`) |
| `GET /v1/calendar?from_date=YYYY-MM-DD&to_date=YYYY-MM-DD` | Afspraken binnen maximaal 31 dagen (`calendar.read`) |
| `GET /healthz` | Gezondheidscontrole |

**Voorbeeld kalenderrespons:**

```json
{
  "source": "magister-cloudagenda",
  "from": "2026-10-15",
  "to": "2026-10-22",
  "events": [
    {"id":"voorbeeld", "title":"Wiskunde", "start":"2026-10-15T09:00:00+02:00", "end":"2026-10-15T10:00:00+02:00", "location":"A201"}
  ]
}
```

Deze voorbeelddata is fictief. Een app ontvangt de originele geheime iCalendar-link of upstream Magister-tokens **niet**.

**OAuth-parameters**: `response_type=code`, `client_id`, `redirect_uri` (exact geregistreerd), `scope` (space-delimited), `code_challenge`, `code_challenge_method=S256`, `state` (verplicht). Na toestemming keert alleen een eenmalige code, `state` en `iss` terug. Wissel de code in met `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`. `offline_access` levert roterende refresh-tokens op. Apps moeten `state` en `iss` controleren. Zie `examples/cli-pkce-client.mjs` en `examples/chrome-client.js`.

**Let op:** dit is een OAuth-autorisatieserver, **geen OIDC identity provider**. Er zijn bewust geen `id_token`, Implicit Flow, Resource Owner Password Flow of onbeperkte proxy-endpoints. Browserapps zijn public clients; zij krijgen géén client-secret.

## Magister OAuth-provider (optioneel)

Voor officiële/geautoriseerde Magister API-toegang, indien beschikbaar, kun je deze *server-side* `.env`-waarden instellen:

```
MAGISTER_CLIENT_ID=...
MAGISTER_CLIENT_SECRET=...
MAGISTER_AUTHORIZE_URL=https://<partner-authorize-endpoint>
MAGISTER_TOKEN_URL=https://<partner-token-endpoint>
MAGISTER_CALENDAR_URL=https://<partner-calendar-endpoint>
MAGISTER_SCOPES=...
MAGISTER_FROM_PARAM=from
MAGISTER_TO_PARAM=to
```

Vraag correcte endpoints en toegestane scopes aan Magister of de school. **Dit zijn placeholders, geen werkende Magister-endpoints.** De adapter ondersteunt standaard `authorization_code` + PKCE, optioneel client-secret en refresh. Reële data-mapping moet mogelijk worden aangepast aan het geautoriseerde API-contract. De officiële CloudAgenda is de standaard en heeft geen API-clientregistratie nodig.

Magister verbiedt [ongeautoriseerd API-gebruik](https://magister.nl/voorwaarden). Stuur gebruikers nooit naar een nep-Magister-loginpagina en vraag nooit hun Magister-wachtwoord aan deze gateway.

## Docker / publieke hosting

```bash
cp .env.example .env
# Vul PUBLIC_BASE_URL=https://auth.jouwdomein.nl en TOKEN_ENCRYPTION_KEY in
# Maak gebruikers/clients met dezelfde volume door docker compose exec:
docker compose up -d --build
docker compose exec gateway python -m gateway.cli create-user --email jij@voorbeeld.nl
```

De app luistert alleen op **127.0.0.1:8000** op de host. Zet een HTTPS reverse proxy voor die poort, met correcte Host/HTTPS-afhandeling. Zet PostgreSQL of een gecertificeerde OAuth AS in voor grotere productieopstellingen; dit voorbeeld gebruikt SQLite en is bedoeld voor één kleine instantie. Achter een proxy kan aanvullende rate limiting/WAF nodig zijn. Maak backups van het gateway-volume én van je encryptiesleutel op een **aparte veilige locatie**.

**Niet zomaar voor anderen openen:** stel TLS, firewall, reverse proxy, logging zonder secrets, back-ups, updates, monitoring en een onafhankelijke security review in. Session-cookies zijn `Secure` bij HTTPS; lokaal is HTTP alleen op localhost toegestaan.

## Ontwikkelen en testen

```bash
pip install -r requirements-dev.txt
python -m pytest -q
python -m compileall gateway
```

De tests behandelen login, PKCE, scopes, exact redirects, tokenrotatie en -replay, revocatie, beperkte CORS, vertrouwelijke clients, iCalendar parsing en SSRF-validatie. **Automatische tests bewijzen geen echte Magister-verbinding of volledige productieveiligheid.**

## Structuur

```
gateway/app.py       OAuth endpoints, lokale login, toestemming, dashboard
gateway/db.py        SQLite-schema en opslag
gateway/security.py  PKCE, hashing en URL-validatie
gateway/provider.py  Optionele geautoriseerde OAuth upstream
gateway/ical.py      Officiële CloudAgenda feed + parser
gateway/cli.py       Account- en clientregistratie
static/style.css     Dashboard-interface
examples/            Voorbeelden voor Node en browserextensies
tests/               Automatische tests
```

Licentie: MIT. Nieuwe onafhankelijke implementatie, niet afgeleid van de oude token/QR-omweg.
