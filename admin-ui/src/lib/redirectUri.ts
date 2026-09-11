export function isValidRedirectURI(uri: string): boolean {
  if (!uri) return false;

  try {
    const parsedURI = new URL(uri);
    const scheme = parsedURI.protocol.replace(/:$/, "").toLowerCase();

    if (!scheme) return false;

    if (scheme === "http" || scheme === "https") {
      return parsedURI.host !== "";
    }

    // Private-use/native-app schemes may use either an authority
    // (myapp://callback) or an absolute path without an authority
    // (app.immich:///oauth-callback).
    return parsedURI.host !== "" || parsedURI.pathname.startsWith("/");
  } catch {
    return false;
  }
}
