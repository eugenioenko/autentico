package passkey

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sampleChallengeData returns a JSON-encoded webauthn.SessionData for test use.
func sampleChallengeData() string {
	session := webauthn.SessionData{
		Challenge:      "dGVzdC1jaGFsbGVuZ2U",
		RelyingPartyID: "localhost",
		Expires:        time.Now().Add(5 * time.Minute),
	}
	b, _ := json.Marshal(session)
	return string(b)
}

// sampleCredentialJSON returns a JSON-encoded webauthn.Credential for test use.
func sampleCredentialJSON() string {
	cred := webauthn.Credential{
		ID:              []byte("testcredentialid12345678"),
		PublicKey:       []byte{},
		AttestationType: "none",
	}
	b, _ := json.Marshal(cred)
	return string(b)
}

// --- CreatePasskeyChallenge ---

func TestCreatePasskeyChallenge(t *testing.T) {
	testutils.WithTestDB(t)

	challenge := PasskeyChallenge{
		ID:            "challenge-1",
		UserID:        "user-1",
		ChallengeData: sampleChallengeData(),
		Type:          "authentication",
		LoginState:    `{"redirect":"http://localhost/cb","state":"s1","client_id":"c1","scope":"openid","nonce":"","code_challenge":"","code_challenge_method":""}`,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		Used:          false,
	}

	err := CreatePasskeyChallenge(challenge)
	assert.NoError(t, err)

	var id string
	err = db.GetDB().QueryRow(`SELECT id FROM passkey_challenges WHERE id = ?`, "challenge-1").Scan(&id)
	assert.NoError(t, err)
	assert.Equal(t, "challenge-1", id)
}

func TestCreatePasskeyChallenge_DuplicateID(t *testing.T) {
	testutils.WithTestDB(t)

	challenge := PasskeyChallenge{
		ID:            "dup-challenge",
		UserID:        "user-1",
		ChallengeData: sampleChallengeData(),
		Type:          "authentication",
		LoginState:    `{}`,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}

	require.NoError(t, CreatePasskeyChallenge(challenge))
	err := CreatePasskeyChallenge(challenge)
	assert.Error(t, err)
}

// --- CreatePasskeyCredential ---

func TestCreatePasskeyCredential(t *testing.T) {
	testutils.WithTestDB(t)

	cred := PasskeyCredential{
		ID:         "cred-1",
		UserID:     "user-1",
		Name:       "My iPhone",
		Credential: sampleCredentialJSON(),
	}

	err := CreatePasskeyCredential(cred)
	assert.NoError(t, err)

	var id string
	err = db.GetDB().QueryRow(`SELECT id FROM passkey_credentials WHERE id = ?`, "cred-1").Scan(&id)
	assert.NoError(t, err)
	assert.Equal(t, "cred-1", id)
}

func TestCreatePasskeyCredential_DuplicateID(t *testing.T) {
	testutils.WithTestDB(t)

	cred := PasskeyCredential{
		ID:         "dup-cred",
		UserID:     "user-1",
		Credential: sampleCredentialJSON(),
	}

	require.NoError(t, CreatePasskeyCredential(cred))
	err := CreatePasskeyCredential(cred)
	assert.Error(t, err)
}

// --- PasskeyChallengeByID ---

func TestPasskeyChallengeByID(t *testing.T) {
	testutils.WithTestDB(t)

	challenge := PasskeyChallenge{
		ID:            "read-challenge-1",
		UserID:        "user-1",
		ChallengeData: sampleChallengeData(),
		Type:          "registration",
		LoginState:    `{"redirect":"http://localhost/cb","state":"abc","client_id":"c1","scope":"openid","nonce":"","code_challenge":"","code_challenge_method":""}`,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		Used:          false,
	}
	require.NoError(t, CreatePasskeyChallenge(challenge))

	result, err := PasskeyChallengeByID("read-challenge-1")
	assert.NoError(t, err)
	assert.Equal(t, "read-challenge-1", result.ID)
	assert.Equal(t, "user-1", result.UserID)
	assert.Equal(t, "registration", result.Type)
	assert.False(t, result.Used)
}

func TestPasskeyChallengeByID_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := PasskeyChallengeByID("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- PasskeyCredentialsByUserID ---

func TestPasskeyCredentialsByUserID(t *testing.T) {
	testutils.WithTestDB(t)

	for _, id := range []string{"cred-a", "cred-b"} {
		require.NoError(t, CreatePasskeyCredential(PasskeyCredential{
			ID:         id,
			UserID:     "user-x",
			Credential: sampleCredentialJSON(),
		}))
	}
	// A credential belonging to a different user
	require.NoError(t, CreatePasskeyCredential(PasskeyCredential{
		ID:         "cred-other",
		UserID:     "user-y",
		Credential: sampleCredentialJSON(),
	}))

	creds, err := PasskeyCredentialsByUserID("user-x")
	assert.NoError(t, err)
	assert.Len(t, creds, 2)
}

func TestPasskeyCredentialsByUserID_Empty(t *testing.T) {
	testutils.WithTestDB(t)

	creds, err := PasskeyCredentialsByUserID("no-such-user")
	assert.NoError(t, err)
	assert.Empty(t, creds)
}

// --- CredentialsToWebAuthn ---

func TestCredentialsToWebAuthn(t *testing.T) {
	credJSON := sampleCredentialJSON()
	stored := []PasskeyCredential{
		{ID: "c1", Credential: credJSON},
		{ID: "c2", Credential: credJSON},
		{ID: "c3", Credential: "not valid json {{{"},
	}

	result := CredentialsToWebAuthn(stored)
	// Only the two valid entries should survive
	assert.Len(t, result, 2)
}

func TestCredentialsToWebAuthn_Empty(t *testing.T) {
	result := CredentialsToWebAuthn(nil)
	assert.Empty(t, result)
}

// --- MarkPasskeyChallengeUsed ---

func TestMarkPasskeyChallengeUsed(t *testing.T) {
	testutils.WithTestDB(t)

	challenge := PasskeyChallenge{
		ID:            "used-challenge",
		UserID:        "user-1",
		ChallengeData: sampleChallengeData(),
		Type:          "authentication",
		LoginState:    `{}`,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
		Used:          false,
	}
	require.NoError(t, CreatePasskeyChallenge(challenge))

	err := MarkPasskeyChallengeUsed("used-challenge")
	assert.NoError(t, err)

	result, err := PasskeyChallengeByID("used-challenge")
	assert.NoError(t, err)
	assert.True(t, result.Used)
}

// --- UpdatePasskeyCredential ---

func TestUpdatePasskeyCredential(t *testing.T) {
	testutils.WithTestDB(t)

	require.NoError(t, CreatePasskeyCredential(PasskeyCredential{
		ID:         "update-cred",
		UserID:     "user-1",
		Credential: sampleCredentialJSON(),
	}))

	updated := webauthn.Credential{
		ID:        []byte("testcredentialid12345678"),
		PublicKey: []byte{1, 2, 3},
	}
	err := UpdatePasskeyCredential("update-cred", updated)
	assert.NoError(t, err)

	// Verify last_used_at was set
	var lastUsedAt *string
	err = db.GetDB().QueryRow(`SELECT last_used_at FROM passkey_credentials WHERE id = ?`, "update-cred").Scan(&lastUsedAt)
	assert.NoError(t, err)
	assert.NotNil(t, lastUsedAt)
}

// --- DeletePasskeyCredential ---

func TestDeletePasskeyCredential(t *testing.T) {
	testutils.WithTestDB(t)

	require.NoError(t, CreatePasskeyCredential(PasskeyCredential{
		ID:         "delete-cred",
		UserID:     "user-del",
		Credential: sampleCredentialJSON(),
	}))

	err := DeletePasskeyCredential("delete-cred")
	assert.NoError(t, err)

	creds, err := PasskeyCredentialsByUserID("user-del")
	assert.NoError(t, err)
	assert.Empty(t, creds)
}

func TestDeletePasskeyCredential_NonExistent(t *testing.T) {
	testutils.WithTestDB(t)

	// Deleting a non-existent ID should not error
	err := DeletePasskeyCredential("ghost-cred")
	assert.NoError(t, err)
}
