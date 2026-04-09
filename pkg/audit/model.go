package audit

import (
	"net/http"
	"strings"
	"time"

	"github.com/eugenioenko/autentico/pkg/jwtutil"
)

// Actor represents the user performing an action. Pass nil when the actor
// is unknown (e.g. failed login attempts). The user.User type satisfies
// this interface via GetID() and GetUsername() methods.
type Actor interface {
	GetID() string
	GetUsername() string
}

// TargetType identifies the kind of entity affected by an audit event.
type TargetType string

const (
	TargetUser     TargetType = "user"
	TargetClient   TargetType = "client"
	TargetSession  TargetType = "session"
	TargetSettings   TargetType = "settings"
	TargetFederation TargetType = "federation"
)

// SimpleActor is a lightweight Actor for cases where importing the user
// package would cause circular dependencies.
type SimpleActor struct {
	ID       string
	Username string
}

func (a SimpleActor) GetID() string       { return a.ID }
func (a SimpleActor) GetUsername() string  { return a.Username }

// ActorFromRequest extracts the actor from a request's bearer token.
// Returns nil if the token is missing or invalid. Safe to use in packages
// that can't import pkg/user due to circular dependencies.
func ActorFromRequest(r *http.Request) Actor {
	token := r.Header.Get("Authorization")
	if token == "" {
		return nil
	}
	parts := strings.SplitN(token, " ", 2)
	if len(parts) != 2 {
		return nil
	}
	claims, err := jwtutil.ValidateAccessToken(parts[1])
	if err != nil {
		return nil
	}
	return SimpleActor{ID: claims.UserID}
}

// Event identifies the type of audit event.
type Event string

const (
	EventLoginSuccess           Event = "login_success"
	EventLoginFailed            Event = "login_failed"
	EventMfaSuccess             Event = "mfa_success"
	EventMfaFailed              Event = "mfa_failed"
	EventPasskeyLoginSuccess    Event = "passkey_login_success"
	EventPasskeyLoginFailed     Event = "passkey_login_failed"
	EventPasswordChanged        Event = "password_changed"
	EventPasswordResetRequested Event = "password_reset_requested"
	EventPasswordResetCompleted Event = "password_reset_completed"
	EventUserCreated            Event = "user_created"
	EventUserUpdated            Event = "user_updated"
	EventUserDeactivated        Event = "user_deactivated"
	EventUserReactivated        Event = "user_reactivated"
	EventUserDeleted            Event = "user_deleted"
	EventUserUnlocked           Event = "user_unlocked"
	EventMfaEnrolled            Event = "mfa_enrolled"
	EventMfaDisabled            Event = "mfa_disabled"
	EventPasskeyAdded           Event = "passkey_added"
	EventPasskeyRemoved         Event = "passkey_removed"
	EventLogout                 Event = "logout"
	EventSessionRevoked         Event = "session_revoked"
	EventClientCreated          Event = "client_created"
	EventClientUpdated          Event = "client_updated"
	EventClientDeleted          Event = "client_deleted"
	EventSettingsUpdated        Event = "settings_updated"
	EventSettingsImported       Event = "settings_imported"
	EventFederationCreated     Event = "federation_created"
	EventFederationUpdated     Event = "federation_updated"
	EventFederationDeleted     Event = "federation_deleted"
	EventDeletionApproved      Event = "deletion_approved"
)

// Detail builds a detail map from key-value string pairs.
// Pass nil for events with no detail.
func Detail(kv ...string) map[string]string {
	m := make(map[string]string, len(kv)/2)
	for i := 0; i < len(kv)-1; i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

// AuditLog represents a single audit event stored in the database.
type AuditLog struct {
	ID           string
	Event        string
	ActorID      *string
	ActorUsername string
	TargetType   string
	TargetID     string
	Detail       string
	IPAddress    string
	CreatedAt    time.Time
}

// AuditLogResponse is the JSON representation of an audit event.
type AuditLogResponse struct {
	ID           string  `json:"id"`
	Event        string  `json:"event"`
	ActorID      *string `json:"actor_id"`
	ActorUsername string  `json:"actor_username"`
	TargetType   string  `json:"target_type"`
	TargetID     string  `json:"target_id"`
	Detail       string  `json:"detail"`
	IPAddress    string  `json:"ip_address"`
	CreatedAt    string  `json:"created_at"`
}

// AuditLogListResponse wraps a page of audit events with a total count.
type AuditLogListResponse struct {
	Data  []AuditLogResponse `json:"data"`
	Total int                `json:"total"`
}

func (a *AuditLog) ToResponse() AuditLogResponse {
	return AuditLogResponse{
		ID:           a.ID,
		Event:        a.Event,
		ActorID:      a.ActorID,
		ActorUsername: a.ActorUsername,
		TargetType:   a.TargetType,
		TargetID:     a.TargetID,
		Detail:       a.Detail,
		IPAddress:    a.IPAddress,
		CreatedAt:    a.CreatedAt.Format(time.RFC3339),
	}
}
