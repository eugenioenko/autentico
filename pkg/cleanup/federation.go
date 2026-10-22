package cleanup

import (
	"log/slog"
	"time"

	"github.com/eugenioenko/autentico/pkg/db"
)

// cleanFederationFlows compares integer deadlines without timestamp conversions.
func cleanFederationFlows(threshold time.Time) error {
	result, err := db.GetDB().Exec(`DELETE FROM federation_login_flows WHERE expires_at < ?`, threshold.Unix())
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count > 0 {
		slog.Info("cleanup: deleted expired rows", "table", "federation_login_flows", "count", count)
	}
	return nil
}
