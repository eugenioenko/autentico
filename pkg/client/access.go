package client

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"sort"

	"github.com/eugenioenko/autentico/pkg/audit"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
)

const maxAccessEntries = 1000

// ErrAccessDenied reports that a restricted client does not admit the user.
var ErrAccessDenied = errors.New("user is not allowed to access this client")

// ErrInvalidAccess identifies access metadata the server cannot accept.
var ErrInvalidAccess = errors.New("invalid client access metadata")

// IsBuiltInClient reports whether clientID is a client seeded by Autentico itself.
func IsBuiltInClient(clientID string) bool {
	return clientID == config.AdminClientID || clientID == config.AccountClientID
}

// CheckUserAccess returns ErrAccessDenied when c restricts access and the user
// is neither listed directly nor a member of any allowed group.
func CheckUserAccess(c *Client, userID string) error {
	// Client access §2: built-in clients are never restricted.
	if c == nil || !c.RestrictAccess || IsBuiltInClient(c.ClientID) {
		return nil
	}
	var allowed bool
	err := db.GetDB().QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM client_allowed_users WHERE client_id = ? AND user_id = ?
		) OR EXISTS (
			SELECT 1 FROM client_allowed_groups cg
			JOIN user_groups ug ON ug.group_id = cg.group_id
			WHERE cg.client_id = ? AND ug.user_id = ?
		)`, c.ClientID, userID, c.ClientID, userID).Scan(&allowed)
	if err != nil {
		return fmt.Errorf("failed to check client access: %w", err)
	}
	// Client access §2: with restriction on, empty lists admit nobody.
	if !allowed {
		return ErrAccessDenied
	}
	return nil
}

// CheckUserAccessByClientID resolves the active client and applies CheckUserAccess.
func CheckUserAccessByClientID(clientID, userID string) error {
	c, err := ClientByClientID(clientID)
	if err != nil {
		// Client access §3: a missing or inactive client fails closed.
		return ErrAccessDenied
	}
	return CheckUserAccess(c, userID)
}

// LogAccessDenied records a refused sign-in without group or list details.
func LogAccessDenied(userID, username, clientID, flow, ip string) {
	audit.Log(audit.EventClientAccessDenied, audit.SimpleActor{ID: userID, Username: username}, audit.TargetClient, clientID,
		audit.Detail("user_id", userID, "flow", flow), ip)
}

// AccessDeniedRedirect builds the authorization error response for a refused user.
func AccessDeniedRedirect(redirectURI, state string) (string, error) {
	// RFC 6749 §3.1.2: retain the registered callback query.
	callback, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	q := callback.Query()
	// RFC 6749 §4.1.2.1: access_denied: the authorization server denied the request.
	q.Set("error", "access_denied")
	q.Set("error_description", "You do not have access to this application")
	if state != "" {
		q.Set("state", state)
	}
	callback.RawQuery = q.Encode()
	return callback.String(), nil
}

// AccessLists holds the allowed group and user IDs of one client.
type AccessLists struct {
	Groups []string
	Users  []string
}

// AccessListsByClientIDs loads allowed group and user IDs for several clients.
func AccessListsByClientIDs(clientIDs []string) (map[string]AccessLists, error) {
	result := make(map[string]AccessLists, len(clientIDs))
	if len(clientIDs) == 0 {
		return result, nil
	}
	for _, id := range clientIDs {
		result[id] = AccessLists{Groups: []string{}, Users: []string{}}
	}
	placeholders, args := inPlaceholders(clientIDs)
	load := func(query string, add func(lists *AccessLists, value string)) error {
		rows, err := db.GetDB().Query(query, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var clientID, value string
			if err := rows.Scan(&clientID, &value); err != nil {
				return err
			}
			lists := result[clientID]
			add(&lists, value)
			result[clientID] = lists
		}
		return rows.Err()
	}
	if err := load(`SELECT client_id, group_id FROM client_allowed_groups WHERE client_id IN (`+placeholders+`) ORDER BY client_id, group_id`,
		func(l *AccessLists, v string) { l.Groups = append(l.Groups, v) }); err != nil {
		return nil, fmt.Errorf("failed to load allowed groups: %w", err)
	}
	if err := load(`SELECT client_id, user_id FROM client_allowed_users WHERE client_id IN (`+placeholders+`) ORDER BY client_id, user_id`,
		func(l *AccessLists, v string) { l.Users = append(l.Users, v) }); err != nil {
		return nil, fmt.Errorf("failed to load allowed users: %w", err)
	}
	return result, nil
}

func accessListsTx(tx *sql.Tx, clientID string) (AccessLists, error) {
	lists := AccessLists{Groups: []string{}, Users: []string{}}
	load := func(query string, out *[]string) error {
		rows, err := tx.Query(query, clientID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				return err
			}
			*out = append(*out, v)
		}
		return rows.Err()
	}
	if err := load(`SELECT group_id FROM client_allowed_groups WHERE client_id = ? ORDER BY group_id`, &lists.Groups); err != nil {
		return lists, fmt.Errorf("failed to load allowed groups: %w", err)
	}
	if err := load(`SELECT user_id FROM client_allowed_users WHERE client_id = ? ORDER BY user_id`, &lists.Users); err != nil {
		return lists, fmt.Errorf("failed to load allowed users: %w", err)
	}
	return lists, nil
}

// ToInfoResponseWithAccess adds the allowed group and user IDs to the info response.
func ToInfoResponseWithAccess(clients []*Client) ([]*ClientInfoResponse, error) {
	ids := make([]string, len(clients))
	for i, c := range clients {
		ids[i] = c.ClientID
	}
	lists, err := AccessListsByClientIDs(ids)
	if err != nil {
		return nil, err
	}
	items := make([]*ClientInfoResponse, len(clients))
	for i, c := range clients {
		items[i] = c.ToInfoResponse()
		if l, ok := lists[c.ClientID]; ok {
			items[i].AllowedGroups = l.Groups
			items[i].AllowedUsers = l.Users
		}
	}
	return items, nil
}

func inPlaceholders(values []string) (string, []any) {
	placeholders := ""
	args := make([]any, len(values))
	for i, v := range values {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
		args[i] = v
	}
	return placeholders, args
}

type accessUpdate struct {
	restrict *bool
	groups   *[]string
	users    *[]string
}

func (u accessUpdate) empty() bool {
	return u.restrict == nil && u.groups == nil && u.users == nil
}

// validateAccessUpdate rejects restriction of built-in clients and oversized lists.
func validateAccessUpdate(clientID string, u accessUpdate) error {
	if u.empty() {
		return nil
	}
	if IsBuiltInClient(clientID) {
		restricting := u.restrict != nil && *u.restrict
		listed := u.groups != nil && len(*u.groups) > 0 || u.users != nil && len(*u.users) > 0
		// Client access §2: built-in clients cannot be restricted, so a mistaken
		// list can never lock administrators or account owners out.
		if restricting || listed {
			return fmt.Errorf("%w: access restriction is not supported for built-in clients", ErrInvalidAccess)
		}
	}
	if u.groups != nil && len(*u.groups) > maxAccessEntries || u.users != nil && len(*u.users) > maxAccessEntries {
		return fmt.Errorf("%w: at most %d allowed groups and %d allowed users", ErrInvalidAccess, maxAccessEntries, maxAccessEntries)
	}
	return nil
}

// writeAccess applies an access update inside the caller's transaction.
// Unknown group or user IDs fail the whole update.
func writeAccess(tx *sql.Tx, clientID string, u accessUpdate) error {
	if u.restrict != nil {
		if _, err := tx.Exec(`UPDATE clients SET restrict_access = ? WHERE client_id = ?`, *u.restrict, clientID); err != nil {
			return fmt.Errorf("failed to update access restriction: %w", err)
		}
	}
	replace := func(ids *[]string, table, column, source, kind string) error {
		if ids == nil {
			return nil
		}
		if _, err := tx.Exec(`DELETE FROM `+table+` WHERE client_id = ?`, clientID); err != nil {
			return fmt.Errorf("failed to clear allowed %ss: %w", kind, err)
		}
		for _, id := range uniqueSorted(*ids) {
			result, err := tx.Exec(`INSERT INTO `+table+` (client_id, `+column+`) SELECT ?, id FROM `+source+` WHERE id = ?`, clientID, id)
			if err != nil {
				return fmt.Errorf("failed to add allowed %s: %w", kind, err)
			}
			n, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if n != 1 {
				return fmt.Errorf("%w: unknown %s %q", ErrInvalidAccess, kind, id)
			}
		}
		return nil
	}
	if err := replace(u.groups, "client_allowed_groups", "group_id", "groups", "group"); err != nil {
		return err
	}
	return replace(u.users, "client_allowed_users", "user_id", "users", "user")
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
