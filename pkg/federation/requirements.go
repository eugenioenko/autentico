package federation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxClaimRequirements = 32
	MaxClaimPatternBytes = 1024
	maxClaimValueBytes   = 4096
	maxRequirementsBytes = 64 * 1024
)

// ClaimRequirement is one provider login requirement. Value is a JSON string
// or boolean; validation rejects every other type without coercion.
type ClaimRequirement struct {
	Claim string `json:"claim"`
	Match string `json:"match" enums:"equals,not_equals,regex,not_regex"`
	// Value must be a JSON string or boolean. Regex operators require a string.
	Value any `json:"value"`
}

// ClaimRequirements distinguishes an omitted update (nil) from an explicit
// empty array. JSON null and unknown rule fields are configuration errors.
type ClaimRequirements []ClaimRequirement

func (rules *ClaimRequirements) UnmarshalJSON(raw []byte) error {
	if len(raw) > maxRequirementsBytes || !utf8.Valid(raw) || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("claim_requirements must be an array within 64 KiB")
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil {
		return fmt.Errorf("invalid claim_requirements array")
	}
	if len(rows) > MaxClaimRequirements {
		return fmt.Errorf("claim_requirements allows at most 32 rows")
	}
	for _, row := range rows {
		if _, err := decodeClaimObject(row); err != nil {
			return fmt.Errorf("claim requirement must be an unambiguous JSON object")
		}
	}
	type plain []ClaimRequirement
	var decoded plain
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decoded); err != nil {
		return fmt.Errorf("invalid claim_requirements array")
	}
	*rules = ClaimRequirements(decoded)
	return nil
}

// ClaimRuleResult exposes only rule metadata and a category, never token or
// sample values. Index is zero-based and preserves the configured row order.
type ClaimRuleResult struct {
	Index  int    `json:"index"`
	Claim  string `json:"claim"`
	Match  string `json:"match"`
	Passed bool   `json:"passed"`
	Reason string `json:"reason"`
}

type ClaimTestResult struct {
	Passed  bool              `json:"passed"`
	Results []ClaimRuleResult `json:"results"`
}

func ruleValidation(rule ClaimRequirement) (string, *regexp.Regexp) {
	if rule.Claim == "" || len(rule.Claim) > 256 || !utf8.ValidString(rule.Claim) || strings.TrimSpace(rule.Claim) != rule.Claim || strings.ContainsFunc(rule.Claim, unicode.IsControl) {
		return "invalid_claim", nil
	}
	switch v := rule.Value.(type) {
	case string:
		if len(v) > maxClaimValueBytes || !utf8.ValidString(v) {
			return "invalid_value", nil
		}
	case bool:
	default:
		return "invalid_value_type", nil
	}
	switch rule.Match {
	case "equals", "not_equals":
		return "", nil
	case "regex", "not_regex":
		pattern, ok := rule.Value.(string)
		if !ok {
			return "invalid_value_type", nil
		}
		if len(pattern) > MaxClaimPatternBytes {
			return "pattern_too_long", nil
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return "invalid_pattern", nil
		}
		return "", re
	default:
		return "invalid_operator", nil
	}
}

// ValidateClaimRequirements is used before persistence and after storage reads.
func ValidateClaimRequirements(rules ClaimRequirements) error {
	if len(rules) > MaxClaimRequirements {
		return fmt.Errorf("at most 32 claim requirements are allowed")
	}
	for i, rule := range rules {
		if reason, _ := ruleValidation(rule); reason != "" {
			return fmt.Errorf("claim requirement row %d: %s", i+1, reason)
		}
	}
	return nil
}

// EvaluateClaimRequirements is the shared live-login and draft-tester matcher.
// Missing/null/wrong-type values always fail, including negative operators.
func EvaluateClaimRequirements(rules ClaimRequirements, claims map[string]any) ClaimTestResult {
	result := ClaimTestResult{Passed: true, Results: make([]ClaimRuleResult, 0, len(rules))}
	for i, rule := range rules {
		reason, re := ruleValidation(rule)
		actual, exists := claims[rule.Claim]
		if reason == "" {
			switch {
			case !exists:
				reason = "missing_claim"
			case actual == nil:
				reason = "null_claim"
			default:
				matched, typed := false, false
				switch expected := rule.Value.(type) {
				case string:
					value, ok := actual.(string)
					typed = ok
					if ok {
						if re != nil {
							matched = re.MatchString(value)
						} else {
							matched = value == expected
						}
					}
				case bool:
					value, ok := actual.(bool)
					typed, matched = ok, ok && value == expected
				}
				if !typed {
					reason = "wrong_type"
				} else {
					if rule.Match == "not_equals" || rule.Match == "not_regex" {
						matched = !matched
					}
					if !matched {
						reason = "value_mismatch"
					}
				}
			}
		}
		passed := reason == ""
		if passed {
			reason = "matched"
		}
		result.Results = append(result.Results, ClaimRuleResult{Index: i, Claim: rule.Claim, Match: rule.Match, Passed: passed, Reason: reason})
		result.Passed = result.Passed && passed
	}
	return result
}

// decodeClaimObject rejects ambiguous duplicate keys and non-object samples.
// JWT claim names are case-sensitive (OIDC Core §2 / RFC 7519 §4).
func decodeClaimObject(raw []byte) (map[string]any, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("claims must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("claims must be a JSON object")
	}
	claims := map[string]any{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid claims JSON")
		}
		name, ok := key.(string)
		if !ok {
			return nil, fmt.Errorf("invalid claim name")
		}
		if _, exists := claims[name]; exists {
			return nil, fmt.Errorf("duplicate claim name")
		}
		var value any
		if err := dec.Decode(&value); err != nil {
			return nil, fmt.Errorf("invalid claims JSON")
		}
		claims[name] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("invalid claims JSON")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid claims JSON")
	}
	return claims, nil
}

func encodeRequirements(rules ClaimRequirements) (string, error) {
	if err := ValidateClaimRequirements(rules); err != nil {
		return "", err
	}
	if rules == nil {
		rules = ClaimRequirements{}
	}
	raw, err := json.Marshal(rules)
	if len(raw) > maxRequirementsBytes {
		return "", fmt.Errorf("claim_requirements exceeds 64 KiB")
	}
	return string(raw), err
}

func decodeStoredRequirements(p *FederationProvider, raw string) {
	if json.Unmarshal([]byte(raw), &p.ClaimRequirements) != nil || ValidateClaimRequirements(p.ClaimRequirements) != nil {
		p.ClaimRequirements = ClaimRequirements{}
		p.ClaimRequirementsError = "invalid_stored_claim_requirements"
	}
}
