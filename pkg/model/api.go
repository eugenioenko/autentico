package model

type ApiError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type ApiResponse[T any] struct {
	Data  T         `json:"data,omitempty"`
	Error *ApiError `json:"error,omitempty"`
}

type AuthErrorResponse struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// JWKSResponse represents a JSON Web Key Set response for OIDC
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key Type (e.g., RSA)
	Kid string `json:"kid"` // Key ID
	Use string `json:"use"` // Public Key Use (e.g., sig)
	Alg string `json:"alg"` // Algorithm (e.g., RS256)
	N   string `json:"n"`   // Modulus (base64url-encoded)
	E   string `json:"e"`   // Exponent (base64url-encoded)
}
