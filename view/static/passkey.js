function b64urlToBuffer(b) {
  const base64 = b.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0)).buffer;
}

function bufferToB64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function doPasskeyAuth(data, oauthPath) {
  const opts = data.options.publicKey;
  opts.challenge = b64urlToBuffer(opts.challenge);
  if (opts.allowCredentials) {
    opts.allowCredentials = opts.allowCredentials.map(c => ({ ...c, id: b64urlToBuffer(c.id) }));
  }
  let cred;
  try {
    cred = await navigator.credentials.get({ publicKey: opts });
  } catch (e) {
    showPasskeyError('Passkey cancelled or not available.');
    return;
  }
  const body = {
    id: cred.id,
    rawId: bufferToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
      authenticatorData: bufferToB64url(cred.response.authenticatorData),
      signature: bufferToB64url(cred.response.signature),
      userHandle: cred.response.userHandle ? bufferToB64url(cred.response.userHandle) : null,
    },
  };
  const finishResp = await fetch(oauthPath + '/passkey/login/finish?challenge_id=' + data.challenge_id, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const result = await finishResp.json();
  if (!finishResp.ok) { showPasskeyError(result.error || 'Authentication failed'); return; }
  window.location.href = result.redirect;
}

async function doPasskeyRegister(data, oauthPath) {
  const opts = data.options.publicKey;
  opts.challenge = b64urlToBuffer(opts.challenge);
  opts.user.id = b64urlToBuffer(opts.user.id);
  if (opts.excludeCredentials) {
    opts.excludeCredentials = opts.excludeCredentials.map(c => ({ ...c, id: b64urlToBuffer(c.id) }));
  }
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey: opts });
  } catch (e) {
    showPasskeyError('Passkey registration cancelled or not available.');
    return;
  }
  const body = {
    id: cred.id,
    rawId: bufferToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
      attestationObject: bufferToB64url(cred.response.attestationObject),
      transports: typeof cred.response.getTransports === 'function' ? cred.response.getTransports() : [],
    },
  };
  const finishResp = await fetch(oauthPath + '/passkey/register/finish?challenge_id=' + data.challenge_id, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const result = await finishResp.json();
  if (!finishResp.ok) { showPasskeyError(result.error || 'Registration failed'); return; }
  window.location.href = result.redirect;
}
