package migrations

// Rules are one provider's ordered configuration; preserve existing providers.
const migration022 = `
ALTER TABLE federation_providers ADD COLUMN claim_requirements TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(claim_requirements) AND json_type(claim_requirements) = 'array');
`
