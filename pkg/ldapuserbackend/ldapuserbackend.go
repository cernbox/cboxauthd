package ldapuserbackend

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/cernbox/cboxauthd/pkg"
	"go.uber.org/zap"
	"gopkg.in/ldap.v2"
)

type Options struct {
	Hostname      string
	Port          int
	BaseDN        string
	Filter        string
	BindUsername  string
	BindPassword  string
	ConTimeout    int
	ReqTimeout    int
	SleepPause    int
	Logger        *zap.Logger
	TTL           int
	CacheValidity int
	Salt          string
}

func (opt *Options) init() {
	if opt.ConTimeout == 0 {
		opt.ConTimeout = 3 // seconds
	}

	if opt.ReqTimeout == 0 {
		opt.ReqTimeout = 10 // seconds
	}

	if opt.Logger == nil {
		l, _ := zap.NewProduction()
		opt.Logger = l
	}

	if opt.TTL == 0 {
		opt.TTL = 86400 // one day
	}

	if opt.CacheValidity == 0 {
		opt.CacheValidity = 300 // five minutes
	}

	if opt.SleepPause == 0 {
		opt.SleepPause = 5 // seconds
	}

	if opt.Salt == "" {
		opt.Salt = "foo"
	}
}

func New(opt *Options) pkg.UserBackend {
	opt.init()

	// set connection timeout at package level
	ldap.DefaultTimeout = time.Second * time.Duration(opt.ConTimeout)

	return &userBackend{
		hostname:      opt.Hostname,
		port:          opt.Port,
		baseDN:        opt.BaseDN,
		filter:        opt.Filter,
		bindUsername:  opt.BindUsername,
		bindPassword:  opt.BindPassword,
		logger:        opt.Logger,
		reqTimeout:    time.Second * time.Duration(opt.ReqTimeout),
		sleepPause:    time.Second * time.Duration(opt.SleepPause),
		ttl:           time.Second * time.Duration(opt.TTL),
		cacheValidity: time.Second * time.Duration(opt.CacheValidity),
		salt:          opt.Salt,
		cache:         &sync.Map{},
	}
}

type userBackend struct {
	hostname      string
	port          int
	baseDN        string
	filter        string
	bindUsername  string
	bindPassword  string
	logger        *zap.Logger
	reqTimeout    time.Duration
	ttl           time.Duration
	cacheValidity time.Duration
	sleepPause    time.Duration
	salt          string

	cache *sync.Map
}

func (ub *userBackend) getEntries(ctx context.Context) (map[string]int64, error) {
	maxNumEntries := 1000000000 // 1 million
	items := map[string]int64{}
	ub.cache.Range(func(key interface{}, val interface{}) bool {
		if len(items) > maxNumEntries {
			panic(fmt.Sprintf("ERROR DUMPING THE CACHE BECAUSE IT CONTAINS MORE THAN %d ITEMS", maxNumEntries))
		}
		keyString, ok := key.(string)
		if !ok {
			panic(fmt.Sprintf("ERROR DUMPING CACHE BECAUSE KEY IS NOT A STRING: KEY=%+v", key))
		}

		valInt64, ok := val.(int64)
		if !ok {
			panic(fmt.Sprintf("ERROR DUMPING CACHE BECAUSE VAL IS NOT A INT64. VAL=%+v", val))
		}

		items[keyString] = valInt64
		return true
	})
	return items, nil
}
func (ub *userBackend) getKey(ctx context.Context, username, password string) string {
	h := sha256.New()
	saltedPassword := password + ub.salt
	_, err := io.WriteString(h, saltedPassword)
	if err != nil {
		ub.logger.Error("CANNOT COMPUTE HASH", zap.Error(err))
		panic(err)
		return ""
	}
	key := fmt.Sprintf("%s:%x", username, h.Sum(nil))
	ub.logger.Debug("CACHE KEY", zap.String("KEY", key))
	return key
}

func (ub *userBackend) checkCachedKey(ctx context.Context, username, password string, ttl time.Duration, deleteExpired bool) bool {
	// the username can come only as gonzalhu, not as fully qualified.
	if !strings.HasSuffix(username, ub.baseDN) {
		username = fmt.Sprintf("CN=%s,%s", username, ub.baseDN)
	}
	key := ub.getKey(ctx, username, password)
	val, ok := ub.cache.Load(key)
	if !ok {
		return false
	}

	cachedTimestamp, ok := val.(int64)
	if !ok {
		ub.sleep()
		return false
	}
	expiration := time.Unix(cachedTimestamp, 0).Add(ttl).Unix()

	if expiration < time.Now().Unix() {
		if deleteExpired {
			// delete expired entry
			ub.cache.Delete(key)
		}
		return false
	}

	return true
}

func (ub *userBackend) isCached(ctx context.Context, username, password string) bool {
	return ub.checkCachedKey(ctx, username, password, ub.ttl, true)
}

func (ub *userBackend) isCacheValid(ctx context.Context, username, password string) bool {
	return ub.checkCachedKey(ctx, username, password, ub.cacheValidity, false)
}

func (ub *userBackend) ClearCache(ctx context.Context) {
	counter := 0
	ub.cache.Range(func(key interface{}, val interface{}) bool {
		ub.cache.Delete(key)
		counter++
		return true
	})
	ub.logger.Info("CACHE CLEARED", zap.Int("ITEMS", counter))
}

func (ub *userBackend) SetExpiration(ctx context.Context, expiration int64) error {
	entries, err := ub.getEntries(ctx)
	if err != nil {
		return err
	}

	// We store the time of creation in the map. So to set the expiration to a
	// particular value, we subtract the ttl from that.
	creationTime := time.Unix(expiration, 0).Add(-ub.ttl).Unix()
	for k := range entries {
		ub.cache.Store(k, creationTime)
	}

	ub.logger.Info("EXPIRATION SET", zap.Int("ITEMS", len(entries)))

	return nil
}

func (ub *userBackend) storeInCache(ctx context.Context, username, password string) {
	key := ub.getKey(ctx, username, password)
	ub.cache.Store(key, time.Now().Unix())
	ub.logger.Info("CACHE SET FOR USER", zap.String("USERNAME", username))
}

func (ub *userBackend) sleep() {
	ub.logger.Info("SLEEPING")
	time.Sleep(ub.sleepPause)
}

func (ub *userBackend) doServiceBind(ctx context.Context, l *ldap.Conn, username, password string) error {
	err := l.Bind(username, password)
	if err == nil {
		ub.logger.Info("SERVICE ACCOUNT BINDING OK", zap.String("USERNAME", username))
		ub.storeInCache(ctx, username, password)
		return nil
	}

	// check for unauthenticated binding with password empty.
	// the handler already protects this condition, but just in case
	// github.com/go-ldap/ldap/issues/93
	if len(password) == 0 {
		ub.sleep()
		err := pkg.NewUserBackendError(pkg.UserBackendErrorInvalidCredentials).WithMessage("PASSWORD IS EMPTY, USERNAME: " + username)
		return err
	}

	ub.logger.Error("ERROR BINDING WITH SERVICE ACCOUNT", zap.Error(err), zap.String("ACCOUNT", username))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		ub.sleep()
		ub.logger.Error("SERVICE ACCOUNT CREDENTIALS ARE WRONG: MANUAL ACTION REQUIRED, CHECK SERVICE ACCOUNT STATUS. USING CACHE.")
		// we still rely on the cache in this case because is a configuration problem from our service, or we have a password expired.
		if !ub.isCached(ctx, username, password) {
			err := pkg.NewUserBackendError(pkg.UserBackendErrorInvalidCredentials).WithMessage(fmt.Sprintf("SERVICE ACCOUNT %s NOT FOUND IN THE CACHE", username))
			return err
		}
		return nil
	}

	ub.logger.Warn("LDAP WENT BANANAS, USING CACHE")
	if !ub.isCached(ctx, username, password) {
		err := pkg.NewUserBackendError(pkg.UserBackendErrorInvalidCredentials).WithMessage(fmt.Sprintf("SERVICE ACCOUNT %s NOT FOUND IN THE CACHE", username))
		return err
	}

	return nil
}
func (ub *userBackend) doBind(ctx context.Context, l *ldap.Conn, username, password string) error {
	err := l.Bind(username, password)
	if err == nil {
		ub.logger.Info("BINDING OK", zap.String("USERNAME", username))
		ub.storeInCache(ctx, username, password)
		return nil
	}

	// check for unauthenticated binding with password empty.
	// the handler already protects this condition, but just in case
	// github.com/go-ldap/ldap/issues/93
	if len(password) == 0 {
		ub.sleep()
		err := pkg.NewUserBackendError(pkg.UserBackendErrorInvalidCredentials).WithMessage("PASSWORD IS EMPTY, USERNAME: " + username)
		return err
	}

	ub.logger.Error("CANNOT BIND USER", zap.Error(err), zap.String("USERNAME", username))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		ub.sleep()
		err := pkg.NewUserBackendError(pkg.UserBackendErrorInvalidCredentials).WithMessage(fmt.Sprintf("USER %s SUBMITTED WRONG CREDENTIALS", username))
		return err

	}

	ub.logger.Warn("LDAP WENT BANANAS, USING CACHE")
	if !ub.isCached(ctx, username, password) {
		err := pkg.NewUserBackendError(pkg.UserBackendErrorInvalidCredentials).WithMessage(fmt.Sprintf("USER %s NOT FOUND IN THE CACHE", username))
		return err
	}

	return nil
}

func (ub *userBackend) Authenticate(ctx context.Context, username, password string) error {
	if ub.isCacheValid(ctx, username, password) {
		ub.logger.Info("USING CACHED KEY FOR USER", zap.String("USERNAME", username))
		return nil
	}

	l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ub.hostname, ub.port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		ub.logger.Error("CANNOT CONNECT TO LDAP SERVER", zap.String("LDAPHOSTNAME", ub.hostname), zap.Int("LDAPPORT", ub.port))
		if !ub.isCached(ctx, username, password) {
			err = pkg.NewUserBackendError(pkg.UserBackendErrorInvalidCredentials).WithMessage(fmt.Sprintf("USER %s NOT FOUND IN THE CACHE", username))
			ub.logger.Error("", zap.Error(err))
			return err
		}

		ub.logger.Info("USER AUTHENTICATED USING THE CACHE", zap.String("USERNAME", username))
		return nil
	}
	defer l.Close()

	err = ub.doServiceBind(ctx, l, ub.bindUsername, ub.bindPassword)
	if err != nil {
		ub.logger.Error("CANNOT BIND SERVICE ACCOUNT", zap.Error(err), zap.String("ACCOUNT", ub.bindUsername))
		return err
	}

	// Search for the given username
	searchTerm := fmt.Sprintf(ub.filter, username)
	searchRequest := ldap.NewSearchRequest(
		ub.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchTerm,
		[]string{"dn", "samaccountname"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		ub.logger.Error("SEARCH FAILED", zap.String("SEARCH", searchTerm))
		if !ub.isCached(ctx, username, password) {
			err = pkg.NewUserBackendError(pkg.UserBackendErrorInvalidCredentials).WithMessage(fmt.Sprintf("USER %s NOT FOUND IN THE CACHE", username))
			ub.logger.Error("", zap.Error(err))
			return err
		}

		ub.logger.Info("USER AUTHENTICATED USING THE CACHE", zap.String("USERNAME", username))
		return nil
	}

	if len(sr.Entries) == 0 {
		err := pkg.NewUserBackendError(pkg.UserBackendErrorNotFound).WithMessage(fmt.Sprintf("USER %s NOT FOUND", username))
		ub.logger.Info("USER NOT FOUND IN LDAP", zap.Error(err), zap.String("USERNAME", username))
		return err
	}

	userdn := sr.Entries[0].DN

	// Bind as the user to verify her password
	err = ub.doBind(ctx, l, userdn, password)
	if err != nil {
		ub.logger.Error("CANNOT BIND USER", zap.Error(err), zap.String("USERDN", userdn))
		return err
	}

	// user has been correctly binded/authenticated
	return nil
}
