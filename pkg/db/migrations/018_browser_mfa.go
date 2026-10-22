package migrations

// Existing sessions have no evidence that local MFA was completed. Preserve
// them, but require fresh authentication when the current policy needs MFA.
const migration018 = `ALTER TABLE idp_sessions ADD COLUMN mfa_method TEXT NOT NULL DEFAULT '';`
