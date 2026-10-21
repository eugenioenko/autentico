package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/eugenioenko/autentico/pkg/totpsecret"
	"github.com/joho/godotenv"
)

func configuredTotpKey() (string, error) {
	if key, exists := os.LookupEnv(totpsecret.EnvName); exists {
		return key, totpsecret.ValidateKey(key)
	}
	return totpsecret.GenerateKey()
}

// addMissingTotpKey only appends; existing settings, comments and keys remain
// byte-for-byte intact. RunInit holds the config lock across this operation.
func addMissingTotpKey(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("init requires a regular .env file")
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, opened) {
		return fmt.Errorf("configuration changed during init; retry with a stable .env file")
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	values, err := godotenv.Unmarshal(string(content))
	if err != nil {
		return fmt.Errorf("read existing .env: %w", err)
	}
	if key := values[totpsecret.EnvName]; key != "" {
		if err := totpsecret.ValidateKey(key); err != nil {
			return err
		}
		fmt.Println("Configuration already includes AUTENTICO_TOTP_ENCRYPTION_KEY; no changes made.")
		return nil
	}
	key, err := configuredTotpKey()
	if err != nil {
		return err
	}
	// Keep existing owner/group access (e.g. root:service 0640), while
	// ensuring the newly added secret is never readable by other users.
	if err := file.Chmod(info.Mode().Perm() & 0660); err != nil {
		return err
	}
	prefix := ""
	if info.Size() > 0 {
		var last [1]byte
		if _, err := file.ReadAt(last[:], info.Size()-1); err != nil {
			return err
		}
		if last[0] != '\n' {
			prefix = "\n"
		}
	}
	addition := prefix + "\n# Persistent TOTP encryption key; keep it with database backups.\n" + totpsecret.EnvName + "=" + key + "\n"
	if _, err := file.WriteString(addition); err != nil {
		_ = file.Truncate(info.Size())
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Truncate(info.Size())
		return err
	}
	fmt.Println("Added AUTENTICO_TOTP_ENCRYPTION_KEY to existing .env; other settings and keys were preserved.")
	return nil
}

func createEnvFile(path, content string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
