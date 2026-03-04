package mfa

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestSendEmailOTP_NoHost(t *testing.T) {
	testutils.WithConfigOverride(t, func() {
		config.Values.SmtpHost = ""
		err := SendEmailOTP("test@test.com", "123456")
		assert.Error(t, err)
		assert.Equal(t, "SMTP is not configured", err.Error())
	})
}
