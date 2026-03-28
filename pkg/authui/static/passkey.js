function b64urlToBuffer(b) {
  const base64 = b.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + (4 - (base64.length % 4)) % 4, '=');
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0)).buffer;
}

function bufferToB64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function passkeyLogin(oauthPath, params) {
  const qs = new URLSearchParams(params).toString();
  const beginResp = await fetch(`${oauthPath}/passkey/login/begin?${qs}`);
  const data = await beginResp.json();
  if (!beginResp.ok) return { ok: false, error: data.error || 'Passkey login failed' };

  const opts = data.options.publicKey;
  opts.challenge = b64urlToBuffer(opts.challenge);
  if (opts.allowCredentials) {
    opts.allowCredentials = opts.allowCredentials.map((c) => ({ ...c, id: b64urlToBuffer(c.id) }));
  }

  let cred;
  try {
    cred = await navigator.credentials.get({ publicKey: opts });
  } catch {
    return { ok: false, error: 'Passkey cancelled or not available.' };
  }

  const r = cred.response;
  const body = {
    id: cred.id,
    rawId: bufferToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToB64url(r.clientDataJSON),
      authenticatorData: bufferToB64url(r.authenticatorData),
      signature: bufferToB64url(r.signature),
      userHandle: r.userHandle ? bufferToB64url(r.userHandle) : null,
    },
  };

  const finishResp = await fetch(`${oauthPath}/passkey/login/finish?challenge_id=${data.challenge_id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const result = await finishResp.json();
  if (!finishResp.ok) return { ok: false, error: result.error || 'Authentication failed' };
  return { ok: true, redirect: result.redirect };
}

async function passkeyRegister(oauthPath, params) {
  const qs = new URLSearchParams(params).toString();
  const beginResp = await fetch(`${oauthPath}/passkey/register/begin?${qs}`);
  const data = await beginResp.json();
  if (!beginResp.ok) return { ok: false, error: data.error || 'Passkey registration failed' };

  const opts = data.options.publicKey;
  opts.challenge = b64urlToBuffer(opts.challenge);
  opts.user.id = b64urlToBuffer(opts.user.id);
  if (opts.excludeCredentials) {
    opts.excludeCredentials = opts.excludeCredentials.map((c) => ({ ...c, id: b64urlToBuffer(c.id) }));
  }

  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey: opts });
  } catch {
    return { ok: false, error: 'Passkey registration cancelled or not available.' };
  }

  const r = cred.response;
  const body = {
    id: cred.id,
    rawId: bufferToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToB64url(r.clientDataJSON),
      attestationObject: bufferToB64url(r.attestationObject),
      transports: typeof r.getTransports === 'function' ? r.getTransports() : [],
    },
  };

  const finishResp = await fetch(`${oauthPath}/passkey/register/finish?challenge_id=${data.challenge_id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const result = await finishResp.json();
  if (!finishResp.ok) return { ok: false, error: result.error || 'Registration failed' };
  return { ok: true, redirect: result.redirect };
}

function showPasskeyError(btn, msg) {
  let el = document.getElementById('passkey-error');
  if (!el) {
    el = document.createElement('div');
    el.id = 'passkey-error';
    el.className = 'auth-error';
    el.setAttribute('role', 'alert');
    btn.parentNode.insertBefore(el, btn);
  }
  el.textContent = msg;
}

document.addEventListener('DOMContentLoaded', () => {
  const loginBtn = document.getElementById('passkey-login-btn');
  if (loginBtn) {
    loginBtn.addEventListener('click', async () => {
      loginBtn.disabled = true;
      loginBtn.textContent = 'Waiting…';
      const d = loginBtn.dataset;
      const result = await passkeyLogin(d.oauthPath, {
        state: d.state, redirect_uri: d.redirectUri, client_id: d.clientId,
        scope: d.scope, nonce: d.nonce,
        code_challenge: d.codeChallenge, code_challenge_method: d.codeChallengeMethod,
      });
      if (result.ok) {
        window.location.href = result.redirect;
      } else {
        showPasskeyError(loginBtn, result.error);
        loginBtn.disabled = false;
        loginBtn.innerHTML = loginBtn.dataset.label;
      }
    });
  }

  const registerBtn = document.getElementById('passkey-register-btn');
  if (registerBtn) {
    registerBtn.addEventListener('click', async () => {
      registerBtn.disabled = true;
      registerBtn.textContent = 'Waiting…';
      const d = registerBtn.dataset;
      const result = await passkeyRegister(d.oauthPath, {
        state: d.state, redirect_uri: d.redirectUri, client_id: d.clientId,
        scope: d.scope, nonce: d.nonce,
        code_challenge: d.codeChallenge, code_challenge_method: d.codeChallengeMethod,
        username: document.querySelector('[name="username"]')?.value || '',
      });
      if (result.ok) {
        window.location.href = result.redirect;
      } else {
        showPasskeyError(registerBtn, result.error);
        registerBtn.disabled = false;
        registerBtn.innerHTML = registerBtn.dataset.label;
      }
    });
  }
});
