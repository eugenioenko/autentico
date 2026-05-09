package devicecode

import "github.com/eugenioenko/autentico/pkg/db"

func DeviceCodeByCode(code string) (*DeviceCode, error) {
	var dc DeviceCode
	err := db.GetDB().QueryRow(
		`SELECT code, user_code, client_id, scope, expires_at, interval_seconds, user_id, status, last_polled_at, created_at
		 FROM device_codes WHERE code = ?`, code,
	).Scan(&dc.Code, &dc.UserCode, &dc.ClientID, &dc.Scope, &dc.ExpiresAt, &dc.IntervalSeconds, &dc.UserID, &dc.Status, &dc.LastPolledAt, &dc.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &dc, nil
}

func DeviceCodeByUserCode(userCode string) (*DeviceCode, error) {
	var dc DeviceCode
	err := db.GetDB().QueryRow(
		`SELECT code, user_code, client_id, scope, expires_at, interval_seconds, user_id, status, last_polled_at, created_at
		 FROM device_codes WHERE user_code = ?`, userCode,
	).Scan(&dc.Code, &dc.UserCode, &dc.ClientID, &dc.Scope, &dc.ExpiresAt, &dc.IntervalSeconds, &dc.UserID, &dc.Status, &dc.LastPolledAt, &dc.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &dc, nil
}
