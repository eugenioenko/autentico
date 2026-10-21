package testutils

import "github.com/eugenioenko/autentico/pkg/tokenstore"

// StoredTokenClientID supplies metadata when tests insert signed JWTs directly.
// Opaque fixture credentials have no claims and retain empty metadata.
func StoredTokenClientID(raw string) string {
	claims, err := tokenstore.ReadIssuedMetadata(raw)
	if err != nil {
		return ""
	}
	return claims.ClientID
}

func StoredTokenACR(raw string) string {
	claims, err := tokenstore.ReadIssuedMetadata(raw)
	if err != nil {
		return ""
	}
	return claims.ACR
}
