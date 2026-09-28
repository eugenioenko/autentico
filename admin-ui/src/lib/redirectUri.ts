export function isValidRedirectURI(uri: string): boolean {
  if (!uri) return false;

  try {
    const parsedURI = new URL(uri);
    const scheme = parsedURI.protocol.replace(/:$/, "").toLowerCase();

    if (!scheme) return false;

    if (scheme === "http" || scheme === "https") {
      // Keep the authority check on the original URI. The WHATWG URL parser
      // may normalize malformed input such as "http:///callback" into a URL
      // with "callback" as its host.
      const authority = uri.slice(`${scheme}://`.length).split(/[/?#]/, 1)[0];
      return uri.startsWith(`${scheme}://`) && authority !== "" && parsedURI.host !== "";
    }

    // Private-use/native-app schemes may use either an authority
    // (myapp://callback) or an absolute path without an authority
    // (app.immich:///oauth-callback).
    return parsedURI.host !== "" || parsedURI.pathname.startsWith("/");
  } catch {
    return false;
  }
}
