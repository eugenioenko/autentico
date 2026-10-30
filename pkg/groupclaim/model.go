// Package groupclaim manages custom string claims inherited through membership.
package groupclaim

import (
	"fmt"
	"regexp"

	"github.com/eugenioenko/autentico/pkg/userclaim"
)

type GroupClaimRequest = userclaim.UserClaimRequest
type GroupClaimResponse = userclaim.UserClaimResponse

var localClaimNameRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.:/-]*$`)

// ValidateGroupClaimRequest checks bounded local names and literal string values.
// Reserved local words are allowed because emitted keys always include a group prefix.
func ValidateGroupClaimRequest(input GroupClaimRequest) error {
	// OIDC Core §5.1.2: group-local names are always emitted as group.claim;
	// role/email/etc. are safe here because they cannot replace a top-level claim.
	if len(input.Name) > 128 || !localClaimNameRegex.MatchString(input.Name) {
		return fmt.Errorf("name is invalid: must be 1–128 characters, starting with a letter or underscore, followed by letters, numbers, _, ., :, / or -")
	}
	// Group custom claims §3: string values share individual-claim validation.
	return userclaim.ValidateClaimSyntax(input)
}
