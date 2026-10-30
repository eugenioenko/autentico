package federation

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func UpdateFederationProvider(id string, req FederationProviderRequest) error {
	query := `UPDATE federation_providers SET name = ?, issuer = ?, client_id = ?, client_secret = CASE WHEN ?='' THEN client_secret ELSE ? END, icon_svg = ?, enabled = ?, sort_order = ?`
	args := []any{req.Name, req.Issuer, req.ClientID, req.ClientSecret, req.ClientSecret, req.IconSVG, req.Enabled, req.SortOrder}
	if req.ClaimRequirements != nil {
		encoded, err := encodeRequirements(req.ClaimRequirements)
		if err != nil {
			return err
		}
		query += `, claim_requirements = ?`
		args = append(args, encoded)
	}
	// Omitted requirements do not rewrite or silently repair an invalid policy.
	query += ` WHERE id = ?`
	args = append(args, id)
	_, err := db.GetDB().Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to update federation provider: %w", err)
	}
	return nil
}
