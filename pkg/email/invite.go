package email

import "html/template"

var inviteBody = template.Must(template.New("invite").Parse(`<p>You have been invited to create an account.</p><p><a href="{{.}}">Create your account</a></p>`))

func SendSignupInvite(to, inviteURL string) error {
	body, err := renderBody(inviteBody, inviteURL)
	if err != nil {
		return err
	}
	return SendEmail(to, "Invitation to create an account", "Use your personal signup invitation.", body)
}
