package ldapuserbackend

import (
	"context"
	"testing"
)

func TestAuthenticate(t *testing.T) {
	ctx := context.Background()
	ub := New("cerndc.cern.ch", 636, "OU=Users,OU=Organic Units,DC=cern,DC=ch", "(samaccountname=%s)", "CERN\\<username>", "<password>")
	err := ub.Authenticate(ctx, "<username>", "<password>")
	if err != nil {
		t.Error(err)
	}
}
