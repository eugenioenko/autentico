package migrations

// Replay state belongs to the enrolled secret and advances only after a
// successful verification (RFC 6238 §5.2). Existing enrollments start unused.
const migration016 = `
ALTER TABLE users ADD COLUMN totp_last_used_step INTEGER NOT NULL DEFAULT -1;
`
