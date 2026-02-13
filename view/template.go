package view

import (
	_ "embed"
)

var (
	//go:embed login.html
	LoginTemplate string

	//go:embed mfa.html
	MfaTemplate string

	//go:embed mfa_enroll.html
	MfaEnrollTemplate string
)
