package federation

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
)

func UpdateFederationProvider(id string, req FederationProviderRequest) error {
	_, err := db.GetWriteDB().Exec(
		`UPDATE federation_providers SET name = ?, issuer = ?, client_id = ?, client_secret = ?, icon_svg = ?, enabled = ?, sort_order = ?
		 WHERE id = ?`,
		req.Name, req.Issuer, req.ClientID, req.ClientSecret, req.IconSVG, req.Enabled, req.SortOrder, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update federation provider: %w", err)
	}
	return nil
}
