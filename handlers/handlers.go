package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/cernbox/cboxauthd/pkg"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

func AdminCheck(logger *zap.Logger, secret string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := r.URL.Query().Get("secret")
		if s == "" {
			logger.Info("SECRET IS EMPTY")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if s != secret {
			logger.Info("SECRETS DO NOT MATCH")
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
			logger.Info("KEY IS EMPTY")
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
			logger.Info("KEY IS EMPTY")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		expirationString := r.URL.Query().Get("expiration")
		if expirationString == "" {
			logger.Info("EXPIRATION IS EMPTY")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		expiration, err := strconv.ParseUint(expirationString, 10, 64)
		if err != nil {
			logger.Info("EXPIRATION IS NOT A UINT64", zap.Error(err))
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
func BasicAuthOnly(logger *zap.Logger, userBackend pkg.UserBackend, sleepPause int) http.Handler {
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
			logger.Info("NO BASIC AUTH PROVIDED")
			time.Sleep(time.Second * time.Duration(sleepPause))
			w.Header().Set("WWW-Authenticate", "Basic Realm='cboxauthd credentials'")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		logger.Debug("BASIC AUTH PROVIDED")
		if u == "" || p == "" {
			invalidBasicAuthsCounter.Inc()
			logger.Warn("USERNAME OR PASSWORD ARE EMPTY")
			time.Sleep(time.Second * time.Duration(sleepPause))
			w.Header().Set("WWW-Authenticate", "Basic Realm='cboxauthd credentials'")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// TODO(labkode): whitelist username and password? allowed characters

		err := userBackend.Authenticate(r.Context(), u, p)
		if err != nil {
			invalidBasicAuthsCounter.Inc()
			if ube, ok := err.(pkg.UserBackendError); ok {
				if ube.Code == pkg.UserBackendErrorNotFound || ube.Code == pkg.UserBackendErrorInvalidCredentials {
					logger.Info("INVALID CREDENTIALS", zap.String("USERNAME", u))
					w.Header().Set("WWW-Authenticate", "Basic Realm='cboxauthd credentials'")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			}
			logger.Error("AUTHENTICATION FAILED", zap.Error(err), zap.String("USERNAME", u))
			w.Header().Set("WWW-Authenticate", "Basic Realm='cboxauthd credentials'")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		validBasicAuthsCounter.Inc()
		logger.Info("AUTHENTICATION SUCCEDED", zap.String("USERNAME", u))
		w.WriteHeader(http.StatusOK)
	})
}
