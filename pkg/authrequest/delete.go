package authrequest

import "github.com/eugenioenko/autentico/pkg/db"

// Delete removes an authorize request by ID. Called after the request
// has been consumed (auth code issued) to prevent reuse.
func Delete(id string) error {
	_, err := db.GetDB().Exec(`DELETE FROM authorize_requests WHERE id = ?`, id)
	return err
}
