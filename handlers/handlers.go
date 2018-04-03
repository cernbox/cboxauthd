package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/cernbox/cboxauthd/pkg"

	"github.com/dgrijalva/jwt-go"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

func AdminCheck(logger *zap.Logger, secret string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := r.URL.Query().Get("secret")
		if s == "" {
			logger.Error("secret is empty")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if s != secret {
			logger.Error("secrets do not match")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func ExpireCacheEntry(logger *zap.Logger, ub pkg.UserBackend) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		if key == "" {
			logger.Error("key is empty")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ub.DeleteCacheEntry(r.Context(), key)
		return
	})

}

func SetExpiration(logger *zap.Logger, ub pkg.UserBackend) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		if key == "" {
			logger.Error("key is empty")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		expirationString := r.URL.Query().Get("expiration")
		if expirationString == "" {
			logger.Error("expiration is empty")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		expiration, err := strconv.ParseUint(expirationString, 10, 64)
		if err != nil {
			logger.Error("expiration is not a uint64", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ub.SetExpiration(r.Context(), key, int64(expiration))
		return
	})

}

func DumpCache(logger *zap.Logger, ub pkg.UserBackend) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		items, err := ub.DumpCache(r.Context())
		if err != nil {
			logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body, err := json.Marshal(items)
		if err != nil {
			logger.Error("", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(body)
	})
}
func BasicAuthOnly(logger *zap.Logger, userBackend pkg.UserBackend, signingKey string, expireTime int, owncloudCookieName string) http.Handler {
	validBasicAuthsCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "valid_auths_basic",
		Help: "Number of valid authentications using basic authentication.",
	})
	invalidBasicAuthsCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "invalid_auths_basic",
		Help: "Number of valid authentications using basic authentication.",
	})

	prometheus.Register(validBasicAuthsCounter)
	prometheus.Register(invalidBasicAuthsCounter)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok {
			invalidBasicAuthsCounter.Inc()
			logger.Warn("no basic auth provided")
			w.Header().Set("WWW-Authenticate", "Basic Realm='cboxauthd credentials'")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		logger.Debug("basic auth was provided, checking credentials are not empty")
		if u == "" || p == "" {
			invalidBasicAuthsCounter.Inc()
			logger.Warn("empty basic auth credentials")
			w.Header().Set("WWW-Authenticate", "Basic Realm='cboxauthd credentials'")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		logger.Debug("checking credentials on the backend")
		err := userBackend.Authenticate(r.Context(), u, p)
		if err != nil {
			invalidBasicAuthsCounter.Inc()
			if ube, ok := err.(pkg.UserBackendError); ok {
				if ube.Code == pkg.UserBackendErrorNotFound || ube.Code == pkg.UserBackendErrorInvalidCredentials {
					logger.Warn("invalid credentials", zap.String("username", u))
					w.Header().Set("WWW-Authenticate", "Basic Realm='cboxauthd credentials'")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			}
			logger.Error("authentication failed", zap.Error(err), zap.String("username", u))
			w.Header().Set("WWW-Authenticate", "Basic Realm='cboxauthd credentials'")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		validBasicAuthsCounter.Inc()
		logger.Info("user has been authenticated", zap.String("username", u))
		w.WriteHeader(http.StatusOK)
	})
}
func BasicAuth(logger *zap.Logger, userBackend pkg.UserBackend, signingKey string, expireTime int, owncloudCookieName string) http.Handler {
	validBasicAuthsCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "valid_auths_basic",
		Help: "Number of valid authentications using basic authentication.",
	})
	validCookieAuthsCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "valid_auths_cookie",
		Help: "Number of valid authentications based on cookie",
	})
	prometheus.Register(validBasicAuthsCounter)
	prometheus.Register(validCookieAuthsCounter)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("checking if cookie is present", zap.String("cookiename", owncloudCookieName))
		// try to validate token if set on the cookie
		authCookie, err := r.Cookie(owncloudCookieName)
		if err == nil {
			logger.Debug("cookie was present")
			// validate that the jwt token in the cookie is valid
			_, err = jwt.Parse(authCookie.Value, func(token *jwt.Token) (interface{}, error) {
				return []byte(signingKey), nil
			})
			if err == nil {
				logger.Debug("token in cookie is still valid")
				validCookieAuthsCounter.Inc()
				w.WriteHeader(http.StatusOK)
				return
			}
			logger.Warn("token in cookie no longer valid")
		}

		logger.Debug("cookie was not set, trying basic auth")
		u, p, ok := r.BasicAuth()
		if !ok {
			logger.Warn("no basic auth provided")
			w.Header().Set("WWW-Authenticate", "Basic Realm='cboxauthd credentials'")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		logger.Debug("basic auth was provided, checking credentials are not empty")
		if u == "" || p == "" {
			logger.Warn("empty basic auth credentials")
			w.Header().Set("WWW-Authenticate", "Basic Realm='cboxauthd credentials'")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		logger.Debug("credentials were not empty, checking credentials on the backend")
		err = userBackend.Authenticate(r.Context(), u, p)
		if err != nil {
			if ube, ok := err.(pkg.UserBackendError); ok {
				if ube.Code == pkg.UserBackendErrorNotFound {
					logger.Warn("user not found", zap.String("username", u))
					w.Header().Set("WWW-Authenticate", "Basic Realm='cboxauthd credentials'")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			}
			logger.Error("authentication failed", zap.Error(err), zap.String("username", u))
			w.Header().Set("WWW-Authenticate", "Basic Realm='cboxauthd credentials'")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		logger.Debug("user has been authenticated", zap.String("username", u))
		// user is authenticated using basic auth so we can cache it in a JWT token
		expiration := time.Now().Add(time.Second * time.Duration(expireTime))
		token := jwt.New(jwt.GetSigningMethod("HS256"))
		claims := token.Claims.(jwt.MapClaims)
		claims["username"] = u
		claims["exp"] = expiration.Unix()
		tokenString, err := token.SignedString([]byte(signingKey))
		if err != nil {
			logger.Warn("cannot sign token", zap.Error(err))
			w.Header().Set("WWW-Authenticate", "Basic Realm='cboxauthd credentials'")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		logger.Info("token generated", zap.String("username", u), zap.Int64("exp", expiration.Unix()), zap.Int("max-age", expireTime))
		validBasicAuthsCounter.Inc()

		// store jwt token in cookie
		cookie := &http.Cookie{
			Name:   owncloudCookieName,
			Value:  tokenString,
			Path:   "/",
			MaxAge: expireTime,
		}
		http.SetCookie(w, cookie)
		w.WriteHeader(http.StatusOK)
	})
}
