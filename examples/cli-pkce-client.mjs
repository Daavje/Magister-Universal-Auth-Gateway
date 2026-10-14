// A PUBLIC CLI OAuth client: authorization code + S256 PKCE.
// Run: GATEWAY_URL=http://127.0.0.1:8000 CLIENT_ID=gw_... node examples/cli-pkce-client.mjs
// First register --redirect-uri http://127.0.0.1:8765/callback.
import http from 'node:http';
import { randomBytes, createHash } from 'node:crypto';
const gateway = process.env.GATEWAY_URL ?? 'http://127.0.0.1:8000';
const clientId = process.env.CLIENT_ID;
if (!clientId) throw new Error('Set CLIENT_ID');
const redirectUri = 'http://127.0.0.1:8765/callback';
const verifier = randomBytes(48).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');
const state = randomBytes(32).toString('base64url');
const authorization = new URL('/authorize', gateway);
for (const [k,v] of Object.entries({response_type:'code',client_id:clientId,redirect_uri:redirectUri,
    scope:'profile calendar.read offline_access',code_challenge:challenge,
    code_challenge_method:'S256',state})) authorization.searchParams.set(k,v);
const server = http.createServer(async (req,res) => {
  try {
    const callback = new URL(req.url,redirectUri);
    if (callback.pathname !== '/callback' || callback.searchParams.get('state') !== state ||
        callback.searchParams.get('iss') !== gateway) throw Error('Unexpected OAuth callback');
    if (callback.searchParams.get('error')) throw Error('Consent rejected');
    const code = callback.searchParams.get('code');
    if (!code) throw Error('Missing authorization code');
    const response = await fetch(new URL('/token',gateway),{method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:new URLSearchParams({grant_type:'authorization_code',client_id:clientId,
        redirect_uri:redirectUri,code,code_verifier:verifier})});
    const tokens = await response.json();
    if (!response.ok) throw Error('Token exchange failed: '+tokens.error);
    const profileResponse = await fetch(new URL('/v1/me',gateway),{
        headers:{Authorization:'Bearer '+tokens.access_token}});
    console.log('Authenticated profile:',await profileResponse.json());
    const from = new Date().toISOString().slice(0,10);
    const to = new Date(Date.now()+7*86400_000).toISOString().slice(0,10);
    const cal = new URL('/v1/calendar',gateway);
    cal.searchParams.set('from_date',from);cal.searchParams.set('to_date',to);
    const calendarResponse = await fetch(cal,{headers:{Authorization:'Bearer '+tokens.access_token}});
    console.log('Calendar:',await calendarResponse.json());
    console.log('This demo intentionally does not save or print secrets/tokens.');
    res.writeHead(200,{'Content-Type':'text/plain; charset=utf-8'});
    res.end('Login successful. You may close this tab.');
  } catch(e) {
    console.error(e.message);
    res.writeHead(400,{'Content-Type':'text/plain; charset=utf-8'});res.end('Authorization failed.');
  } finally { server.close(); }
});
server.listen(8765,'127.0.0.1',()=>console.log('\nOpen this URL in your browser:\n'+authorization.toString()+'\n'));
