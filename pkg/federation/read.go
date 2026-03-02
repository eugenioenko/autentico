package federation

import (
	"database/sql"
	"fmt"
	"html/template"

	"github.com/eugenioenko/autentico/pkg/db"
)

func ListFederationProviders() ([]*FederationProvider, error) {
	rows, err := db.GetDB().Query(
		`SELECT id, name, issuer, client_id, client_secret, icon_svg, enabled, sort_order, created_at
		 FROM federation_providers ORDER BY sort_order ASC, created_at ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list federation providers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var providers []*FederationProvider
	for rows.Next() {
		var p FederationProvider
		if err := rows.Scan(&p.ID, &p.Name, &p.Issuer, &p.ClientID, &p.ClientSecret, &p.IconSVG, &p.Enabled, &p.SortOrder, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan federation provider: %w", err)
		}
		providers = append(providers, &p)
	}
	return providers, rows.Err()
}

// ListEnabledProviderViews returns only enabled providers as template-safe views,
// ordered by sort_order for display on the login page.
func ListEnabledProviderViews() ([]FederationProviderView, error) {
	rows, err := db.GetDB().Query(
		`SELECT id, name, icon_svg FROM federation_providers
		 WHERE enabled = TRUE ORDER BY sort_order ASC, created_at ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list enabled federation providers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var views []FederationProviderView
	for rows.Next() {
		var id, name string
		var iconSVG sql.NullString
		if err := rows.Scan(&id, &name, &iconSVG); err != nil {
			return nil, fmt.Errorf("failed to scan federation provider view: %w", err)
		}
		views = append(views, FederationProviderView{
			ID:      id,
			Name:    name,
			IconSVG: template.HTML(iconSVG.String),
		})
	}
	return views, rows.Err()
}

func FederationProviderByID(id string) (*FederationProvider, error) {
	var p FederationProvider
	err := db.GetDB().QueryRow(
		`SELECT id, name, issuer, client_id, client_secret, icon_svg, enabled, sort_order, created_at
		 FROM federation_providers WHERE id = ?`, id,
	).Scan(&p.ID, &p.Name, &p.Issuer, &p.ClientID, &p.ClientSecret, &p.IconSVG, &p.Enabled, &p.SortOrder, &p.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("federation provider not found")
		}
		return nil, fmt.Errorf("failed to get federation provider: %w", err)
	}
	return &p, nil
}

func FederatedIdentityByProviderAndSub(providerID, sub string) (*FederatedIdentity, error) {
	var fi FederatedIdentity
	err := db.GetDB().QueryRow(
		`SELECT id, provider_id, provider_user_id, user_id, email, created_at
		 FROM federated_identities WHERE provider_id = ? AND provider_user_id = ?`,
		providerID, sub,
	).Scan(&fi.ID, &fi.ProviderID, &fi.ProviderUserID, &fi.UserID, &fi.Email, &fi.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("federated identity not found")
		}
		return nil, fmt.Errorf("failed to get federated identity: %w", err)
	}
	return &fi, nil
}
