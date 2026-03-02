package federation

import (
	"fmt"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/rs/xid"
)

func CreateFederationProvider(p FederationProvider) error {
	if p.ID == "" {
		return fmt.Errorf("provider id (slug) is required")
	}
	_, err := db.GetDB().Exec(
		`INSERT INTO federation_providers (id, name, issuer, client_id, client_secret, icon_svg, enabled, sort_order)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.Issuer, p.ClientID, p.ClientSecret, p.IconSVG, p.Enabled, p.SortOrder,
	)
	if err != nil {
		return fmt.Errorf("failed to create federation provider: %w", err)
	}
	return nil
}

func CreateFederatedIdentity(fi FederatedIdentity) error {
	fi.ID = xid.New().String()
	_, err := db.GetDB().Exec(
		`INSERT INTO federated_identities (id, provider_id, provider_user_id, user_id, email)
		 VALUES (?, ?, ?, ?, ?)`,
		fi.ID, fi.ProviderID, fi.ProviderUserID, fi.UserID, fi.Email,
	)
	if err != nil {
		return fmt.Errorf("failed to create federated identity: %w", err)
	}
	return nil
}
