function b64urlToBuffer(b: string): ArrayBuffer {
  const base64 = b.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + (4 - (base64.length % 4)) % 4, '=');
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0)).buffer;
}

function bufferToB64url(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

export async function performPasskeyRegistration(data: {
  challenge_id: string;
  options: { publicKey: PublicKeyCredentialCreationOptions & { challenge: string; user: { id: string }; excludeCredentials?: Array<{ id: string; type: string }> } };
}): Promise<{ id: string; rawId: string; type: string; response: object }> {
  const opts = data.options.publicKey;
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...opts,
    challenge: b64urlToBuffer(opts.challenge as unknown as string),
    user: {
      ...opts.user,
      id: b64urlToBuffer(opts.user.id as unknown as string),
    },
    excludeCredentials: opts.excludeCredentials?.map((c) => ({
      ...c,
      id: b64urlToBuffer(c.id as unknown as string),
    })),
  };

  const cred = await navigator.credentials.create({ publicKey }) as PublicKeyCredential;
  if (!cred) throw new Error('No credential returned');

  const response = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: bufferToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToB64url(response.clientDataJSON),
      attestationObject: bufferToB64url(response.attestationObject),
      transports: typeof response.getTransports === 'function' ? response.getTransports() : [],
    },
  };
}
