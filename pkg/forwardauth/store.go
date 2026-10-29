package forwardauth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/rs/xid"
)

const appColumns = `id, name, origin, allowed_return_paths, client_id, session_ttl, is_active`

type scanner interface{ Scan(...any) error }

func scanApp(row scanner) (*App, error) {
	a := &App{}
	var paths string
	if err := row.Scan(&a.ID, &a.Name, &a.Origin, &paths, &a.ClientID, &a.SessionTTL, &a.IsActive); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(paths), &a.AllowedReturnPaths); err != nil {
		return nil, fmt.Errorf("invalid stored app paths: %w", err)
	}
	req := AppRequest{Name: a.Name, Origin: a.Origin, AllowedReturnPaths: a.AllowedReturnPaths, SessionTTL: a.SessionTTL}
	if err := validate(&req); err != nil || req.Origin != a.Origin {
		return nil, fmt.Errorf("invalid stored app configuration")
	}
	return a, nil
}

func AppByID(id string) (*App, error) {
	return scanApp(db.GetDB().QueryRow(`SELECT `+appColumns+` FROM protected_apps WHERE id=?`, id))
}

func ListApps() ([]App, error) {
	rows, err := db.GetDB().Query(`SELECT ` + appColumns + ` FROM protected_apps ORDER BY name,id LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	apps := []App{}
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		apps = append(apps, *a)
	}
	return apps, rows.Err()
}

// SaveApp commits the registration and its private integration client together.
func SaveApp(id string, req AppRequest) (*App, error) {
	if err := validate(&req); err != nil {
		return nil, err
	}
	active := true
	if req.IsActive != nil {
		active = *req.IsActive
	}
	if id != "" {
		old, err := AppByID(id)
		if err != nil {
			return nil, err
		}
		if req.Origin != old.Origin {
			return nil, fmt.Errorf("origin is immutable; register a new app")
		}
	}
	tx, err := db.GetDB().Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	creating := id == ""
	if creating {
		id = xid.New().String()
	}
	clientID := "forward-auth-" + id
	if creating {
		no := false
		_, err = client.CreateClientWithIDTx(tx, clientID, client.ClientCreateRequest{
			ClientName: req.Name + " (ForwardAuth)", ClientType: "public", TokenEndpointAuthMethod: "none",
			RedirectURIs: []string{req.Origin + "/_autentico/" + id + "/callback"}, Scopes: "openid", ConsentRequired: &no,
		})
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(`INSERT INTO protected_apps (id,name,origin,allowed_return_paths,client_id,session_ttl,is_active) VALUES(?,?,?,?,?,?,?)`, id, req.Name, req.Origin, pathsJSON(req.AllowedReturnPaths), clientID, req.SessionTTL, active)
	} else {
		// Read/preserve active status in the writer transaction so an ordinary
		// concurrent edit cannot undo another administrator's disable action.
		result, updateErr := tx.Exec(`UPDATE protected_apps SET name=?,allowed_return_paths=?,session_ttl=?,is_active=COALESCE(?,is_active),updated_at=? WHERE id=?`, req.Name, pathsJSON(req.AllowedReturnPaths), req.SessionTTL, req.IsActive, time.Now().UTC(), id)
		if updateErr != nil {
			return nil, updateErr
		}
		n, countErr := result.RowsAffected()
		if countErr != nil {
			return nil, countErr
		}
		if n != 1 {
			return nil, sql.ErrNoRows
		}
		err = tx.QueryRow(`SELECT is_active FROM protected_apps WHERE id=?`, id).Scan(&active)
	}
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`UPDATE clients SET client_name=?,is_active=?,updated_at=? WHERE client_id=?`, req.Name+" (ForwardAuth)", active, time.Now().UTC(), clientID); err != nil {
		return nil, err
	}
	if !active {
		if _, err = tx.Exec(`UPDATE forward_auth_sessions SET revoked_at=? WHERE app_id=? AND revoked_at IS NULL`, time.Now().UTC(), id); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return AppByID(id)
}

func DeleteApp(id string) error {
	a, err := AppByID(id)
	if err != nil {
		return err
	}
	tx, err := db.GetDB().Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.Exec(`DELETE FROM protected_apps WHERE id=?`, id); err != nil {
		return err
	}
	// The client remains disabled to preserve historical codes/audit references.
	if _, err = tx.Exec(`UPDATE clients SET is_active=FALSE WHERE client_id=?`, a.ClientID); err != nil {
		return err
	}
	return tx.Commit()
}

var errDenied = errors.New("session is not active")
