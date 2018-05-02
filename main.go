package main

import (
	"net/http"
	"time"

	"github.com/cernbox/cboxauthd/handlers"
	"github.com/cernbox/cboxauthd/pkg/ldapuserbackend"
	"github.com/cernbox/gohub/goconfig"
	"github.com/cernbox/gohub/gologger"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {

	gc := goconfig.New()
	gc.SetConfigName("cboxauthd")
	gc.AddConfigurationPaths("/etc/cboxauthd/")
	gc.Add("tcp-address", "localhost:9991", "tcp address to listen for connections.")
	gc.Add("log-level", "info", "log level to use (debug, info, warn, error).")
	gc.Add("app-log", "stderr", "file to log application information.")
	gc.Add("http-log", "stderr", "file to log HTTP requests.")
	gc.Add("http-read-timeout", 300, "the maximum duration for reading the entire request, including the body.")
	gc.Add("http-write-timeout", 300, "the maximum duration for timing out writes of the response.")
	gc.Add("ldap-hostname", "localhost", "LDAP server hostname.")
	gc.Add("ldap-port", 636, "LDAP server port.")
	gc.Add("ldap-bind-username", "CN=foo,OU=Users,OU=Organic Units,DC=cern,DC=ch", "LDAP bind username.")
	gc.Add("ldap-bind-password", "bar", "LDAP bind password.")
	gc.Add("ldap-base-dn", "OU=Users,OU=Organic Units,DC=cern,DC=ch", "LDAP base DN.")
	gc.Add("ldap-base-filter", "(samaccountname=%s)", "LDAP base search filter.")
	gc.Add("ldap-conn-timeout", 0, "LDAP connection timeout.")
	gc.Add("ldap-req-timeout", 0, "LDAP request timeout.")
	gc.Add("ldap-cache-ttl", 86400, "LDAP cache TTL.")
	gc.Add("safety-sleep", 5, "Seconds to pause requests on authentication failure.")
	gc.Add("admin-secret", "bar", "secreto to access admin APIs for cache manipulation.")
	gc.Add("salt", "foo", "salt to hash passwords.")
	gc.BindFlags()
	gc.ReadConfig()

	logger := gologger.New(gc.GetString("log-level"), gc.GetString("app-log"))

	opt := &ldapuserbackend.Options{
		Hostname:     gc.GetString("ldap-hostname"),
		Port:         gc.GetInt("ldap-port"),
		BaseDN:       gc.GetString("ldap-base-dn"),
		Filter:       gc.GetString("ldap-base-filter"),
		BindUsername: gc.GetString("ldap-bind-username"),
		BindPassword: gc.GetString("ldap-bind-password"),
		Logger:       logger,
		ConTimeout:   gc.GetInt("ldap-conn-timeout"),
		ReqTimeout:   gc.GetInt("ldap-req-timeout"),
		TTL:          gc.GetInt("ldap-cache-ttl"),
		SleepPause:   gc.GetInt("safety-sleep"),
	}
	ub := ldapuserbackend.New(opt)

	router := http.NewServeMux()
	authHandler := handlers.BasicAuthOnly(logger, ub, gc.GetInt("safety-sleep"))
	dumpHandler := handlers.AdminCheck(logger, gc.GetString("admin-secret"), handlers.DumpCache(logger, ub))
	expireHandler := handlers.AdminCheck(logger, gc.GetString("admin-secret"), handlers.ExpireCacheEntry(logger, ub))
	setHandler := handlers.AdminCheck(logger, gc.GetString("admin-secret"), handlers.SetExpiration(logger, ub))

	router.Handle("/api/v1/auth", authHandler)
	router.Handle("/api/v1/cache/dump", dumpHandler)
	router.Handle("/api/v1/cache/expire", expireHandler)     // expire?key=john:hash
	router.Handle("/api/v1/cache/setexpiration", setHandler) // setexpiration?key=john:hash&expiration=1522739593
	router.Handle("/metrics", promhttp.Handler())

	loggedRouter := gologger.GetLoggedHTTPHandler(gc.GetString("http-log"), router)

	s := http.Server{
		Addr:         gc.GetString("tcp-address"),
		ReadTimeout:  time.Second * time.Duration(gc.GetInt("http-read-timeout")),
		WriteTimeout: time.Second * time.Duration(gc.GetInt("http-write-timeout")),
		Handler:      loggedRouter,
	}

	logger.Info("server is listening at: " + gc.GetString("tcp-address"))
	logger.Error(s.ListenAndServe().Error())

}
