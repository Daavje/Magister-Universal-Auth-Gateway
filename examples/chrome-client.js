/** Sample OAuth integration for Chrome/Edge MV3 extensions.
 * Requires permissions: ["identity"], host_permissions: ["https://YOUR-AUTH-HOST/*"].
 * Register the EXACT chrome.identity.getRedirectURL() result as a public redirect URI,
 * and chrome-extension://EXTENSION_ID as the allowed CORS origin.
 * Run from the extension's background service worker or another extension context.
 * Store tokens in chrome.storage.session (not localStorage) and avoid logging secrets.
 */
export async function connectGateway({ gatewayBase, clientId }) {
  const bytes = crypto.getRandomValues(new Uint8Array(48));
  const b64url = arr => btoa(String.fromCharCode(...arr)).replaceAll('+','-').replaceAll('/','_').replace(/=+$/, '');
  const verifier = b64url(bytes);
  const challenge = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier))));
  const state = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const callbackUri = chrome.identity.getRedirectURL();
  const origin = new URL(gatewayBase).origin;
  const url = new URL('/authorize', origin);
  for (const [key,value] of Object.entries({response_type:'code',client_id:clientId,
      redirect_uri:callbackUri,scope:'profile calendar.read offline_access',
      code_challenge:challenge,code_challenge_method:'S256',state})) url.searchParams.set(key,value);
  const callback = await chrome.identity.launchWebAuthFlow({url:url.toString(),interactive:true});
  const params = new URL(callback).searchParams;
  if (params.get('state')!==state || params.get('iss')!==origin || !params.get('code'))
    throw new Error('Invalid OAuth response');
  const result = await fetch(new URL('/token',origin),{method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:new URLSearchParams({grant_type:'authorization_code',client_id:clientId,
      redirect_uri:callbackUri,code:params.get('code'),code_verifier:verifier})});
  if (!result.ok) throw new Error('Token request rejected ('+result.status+')');
  const tokens = await result.json();
  await chrome.storage.session.set({ gatewayOAuthTokens: tokens });
  return {connected:true,expiresIn:tokens.expires_in};
}
