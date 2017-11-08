package ldapuserbackend

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/cernbox/cboxauthd/pkg"
	"gopkg.in/ldap.v2"
)

func New(hostname string, port int, basedn, filter, bindusername, bindpassword string) pkg.UserBackend {
	return &userBackend{
		hostname:     hostname,
		port:         port,
		baseDN:       basedn,
		filter:       filter,
		bindUsername: bindusername,
		bindPassword: bindpassword,
	}
}

type userBackend struct {
	hostname     string
	port         int
	baseDN       string
	filter       string
	bindUsername string
	bindPassword string
}

func (ub *userBackend) Authenticate(ctx context.Context, username, password string) error {
	l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ub.hostname, ub.port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return err
	}
	defer l.Close()

	// First bind with a read only user
	err = l.Bind(ub.bindUsername, ub.bindPassword)
	if err != nil {
		fmt.Println("bind failed", err)
		return err
	}

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		ub.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(ub.filter, username),
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		fmt.Println("search failed", fmt.Sprintf(ub.filter, username))
		return err
	}

	if len(sr.Entries) != 1 {
		err := pkg.NewUserBackendError(pkg.UserBackendErrorNotFound).WithMessage(fmt.Sprintf("user %s not found", username))
		return err
	}

	userdn := sr.Entries[0].DN

	// Bind as the user to verify their password
	err = l.Bind(userdn, password)
	if err != nil {
		fmt.Println("user bind failed", err)
		return err
	}

	return nil
}
