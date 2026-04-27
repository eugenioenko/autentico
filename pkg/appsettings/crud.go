package appsettings

import (
	"github.com/eugenioenko/autentico/pkg/db"
)

// GetSetting retrieves a single setting value by key from the settings table.
func GetSetting(key string) (string, error) {
	database := db.GetDB()
	var value string
	err := database.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	return value, err
}

// SetSetting inserts or replaces a setting key-value pair.
func SetSetting(key, value string) error {
	database := db.GetDB()
	_, err := database.Exec(
		`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value,
	)
	return err
}

// GetAllSettings returns all settings as a map.
func GetAllSettings() (map[string]string, error) {
	database := db.GetDB()
	rows, err := database.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	result := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		result[k] = v
	}
	return result, rows.Err()
}
