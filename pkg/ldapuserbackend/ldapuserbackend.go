package ldapuserbackend

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"github.com/cernbox/cboxauthd/pkg"
	"go.uber.org/zap"
	"gopkg.in/ldap.v2"
	"io"
	"strings"
	"sync"
	"time"
)

type Options struct {
	Hostname     string
	Port         int
	BaseDN       string
	Filter       string
	BindUsername string
	BindPassword string
	ConTimeout   int
	ReqTimeout   int
	SleepPause   int
	Logger       *zap.Logger
	TTL          int
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

	if opt.SleepPause == 0 {
		opt.SleepPause = 5 // seconds
	}
}

func New(opt *Options) pkg.UserBackend {
	opt.init()

	// set connection timeout at package level
	ldap.DefaultTimeout = time.Second * time.Duration(opt.ConTimeout)

	return &userBackend{
		hostname:     opt.Hostname,
		port:         opt.Port,
		baseDN:       opt.BaseDN,
		filter:       opt.Filter,
		bindUsername: opt.BindUsername,
		bindPassword: opt.BindPassword,
		logger:       opt.Logger,
		reqTimeout:   time.Second * time.Duration(opt.ReqTimeout),
		sleepPause:   time.Second * time.Duration(opt.SleepPause),
		ttl:          time.Second * time.Duration(opt.TTL),
		cache:        &sync.Map{},
	}
}

type userBackend struct {
	hostname     string
	port         int
	baseDN       string
	filter       string
	bindUsername string
	bindPassword string
	logger       *zap.Logger
	reqTimeout   time.Duration
	ttl          time.Duration
	sleepPause   time.Duration

	cache *sync.Map
}

func (ub *userBackend) DumpCache(ctx context.Context) (map[string]int64, error) {
	maxNumEntries := 1000000000 // 1 million
	items := map[string]int64{}
	ub.cache.Range(func(key interface{}, val interface{}) bool {
		if len(items) > maxNumEntries {
			panic(fmt.Sprintf("error dumping cache. the cache contains more than %d items", maxNumEntries))
			return false
		}
		keyString, ok := key.(string)
		if !ok {
			panic(fmt.Sprintf("error dumping cache. key is not a string. key=%+v", key))
			return false
		}

		valInt64, ok := val.(int64)
		if !ok {
			panic(fmt.Sprintf("error dumping cache. val is not a int64. val=%+v", val))
			return false
		}

		items[keyString] = valInt64
		return true
	})
	return items, nil
}
func (ub *userBackend) getKey(ctx context.Context, username, password string) string {
	h := md5.New()
	_, err := io.WriteString(h, password)
	if err != nil {
		ub.logger.Error("cannot write to hash", zap.Error(err))
		panic(err)
		return ""
	}
	key := fmt.Sprintf("%s:%x", username, h.Sum(nil))
	ub.logger.Debug("cache key", zap.String("key", key))
	return key
}

func (ub *userBackend) isCached(ctx context.Context, username, password string) bool {
	// the username can come only as gonzalhu, not as fully qualified.
	if !strings.HasSuffix(username, ub.baseDN) {
		username = fmt.Sprintf("CN=%s,%s", username, ub.baseDN)
	}
	key := ub.getKey(ctx, username, password)
	val, ok := ub.cache.Load(key)
	if !ok {
		ub.sleep()
		return false
	}

	expiresIn, ok := val.(int64)
	if !ok {
		ub.sleep()
		return false
	}

	now := time.Now().Unix()
	if now > expiresIn {
		ub.sleep()
		// delete expired entry
		ub.cache.Delete(key)
		return false
	}

	return true
}

func (ub *userBackend) DeleteCacheEntry(ctx context.Context, key string) {
	ub.cache.Delete(key)
}

func (ub *userBackend) SetExpiration(ctx context.Context, key string, expiration int64) {
	_, ok := ub.cache.Load(key)
	if !ok {
		ub.sleep()
		return
	}
	ub.cache.Store(key, expiration)
}

func (ub *userBackend) storeInCache(ctx context.Context, username, password string) {
	key := ub.getKey(ctx, username, password)
	expiresIn := time.Now().Add(ub.ttl).Unix()
	ub.cache.Store(key, expiresIn)
}

func (ub *userBackend) sleep() {
	time.Sleep(ub.sleepPause)
}

func (ub *userBackend) doBind(ctx context.Context, l *ldap.Conn, username, password string) error {
	err := l.Bind(username, password)
	if err == nil {
		ub.logger.Info("binding ok", zap.String("username", username))
		ub.storeInCache(ctx, username, password)
		return nil
	}

	// check for unauthenticated binding with password empty.
	// the handler already protects this condition, but just in case
	// github.com/go-ldap/ldap/issues/93
	if len(password) == 0 {
		ub.sleep()
		err := pkg.NewUserBackendError(pkg.UserBackendErrorInvalidCredentials).WithMessage(fmt.Sprintf("password is empty", username))
		return err
	}

	ub.logger.Error("error binding user", zap.Error(err), zap.String("username", username))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		ub.sleep()
		err := pkg.NewUserBackendError(pkg.UserBackendErrorInvalidCredentials).WithMessage(fmt.Sprintf("user %s submitted bad credentials", username))
		return err

	}

	ub.logger.Warn("transient error to ldap, fallback to cache")
	if !ub.isCached(ctx, username, password) {
		err := pkg.NewUserBackendError(pkg.UserBackendErrorInvalidCredentials).WithMessage(fmt.Sprintf("user %s not found in the cache", username))
		return err
	}

	return nil
}

func (ub *userBackend) Authenticate(ctx context.Context, username, password string) error {
	l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ub.hostname, ub.port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		ub.logger.Error("error connecting to ldap server", zap.String("ldaphostname", ub.hostname), zap.Int("ldapport", ub.port))
		if !ub.isCached(ctx, username, password) {
			err = pkg.NewUserBackendError(pkg.UserBackendErrorInvalidCredentials).WithMessage(fmt.Sprintf("user %s not found in the cache", username))
			ub.logger.Error("", zap.Error(err))
			return err
		}

		ub.logger.Info("user authenticated using the cache", zap.String("username", username))
		return nil
	}
	defer l.Close()

	err = ub.doBind(ctx, l, ub.bindUsername, ub.bindPassword)
	if err != nil {
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
		ub.logger.Error("search failed", zap.String("search", searchTerm))
		if !ub.isCached(ctx, username, password) {
			err = pkg.NewUserBackendError(pkg.UserBackendErrorInvalidCredentials).WithMessage(fmt.Sprintf("user %s not found in the cache", username))
			ub.logger.Error("", zap.Error(err))
			return err
		}

		ub.logger.Info("user authenticated using the cache", zap.String("username", username))
		return nil
	}

	if len(sr.Entries) == 0 {
		err := pkg.NewUserBackendError(pkg.UserBackendErrorNotFound).WithMessage(fmt.Sprintf("user %s not found", username))
		return err
	}

	userdn := sr.Entries[0].DN

	// Bind as the user to verify her password
	err = ub.doBind(ctx, l, userdn, password)
	if err != nil {
		return err
	}

	// user has been correctly binded/authenticated
	return nil
}
