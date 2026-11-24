package signupinvite

import (
	"context"
	"database/sql"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/rs/xid"
	"golang.org/x/crypto/bcrypt"
)

// Accepts checks both identity fields when email is configured as the username (§3).
func (i *Invite) Accepts(username, address string) bool {
	return (i.Email == "" || i.Email == address) && (config.Get().ProfileFieldEmail != "is_username" || username == address)
}

func InsertAccount(tx *sql.Tx, id, username, address string, passwordHash any, verified bool, p user.UserUpdateRequest) error {
	_, err := tx.Exec(`INSERT INTO users(id,username,email,password,is_email_verified,registered_at,role,
 given_name,family_name,phone_number,picture,locale,address_street,address_locality,address_region,address_postal_code,address_country)
 VALUES(?,?,NULLIF(?,''),?,?,CURRENT_TIMESTAMP,'user',?,?,?,?,?,?,?,?,?,?)`, id, username, address, passwordHash, verified, p.GivenName, p.FamilyName, p.PhoneNumber, p.Picture, p.Locale, p.AddressStreet, p.AddressLocality, p.AddressRegion, p.AddressPostalCode, p.AddressCountry)
	return err
}

func (i *Invite) CreatePasswordUser(ctx context.Context, name, password, address string, p user.UserUpdateRequest) (*user.UserResponse, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	u := &user.UserResponse{ID: xid.New().String(), Username: name, Email: address, Role: "user"}
	err = i.Redeem(ctx, address, func(tx *sql.Tx, verified bool) error {
		u.IsEmailVerified = verified
		return InsertAccount(tx, u.ID, name, address, string(hash), verified, p)
	})
	return u, err
}
