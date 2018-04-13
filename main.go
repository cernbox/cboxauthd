package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/cernbox/cboxauthd/handlers"
	"github.com/cernbox/cboxauthd/pkg/ldapuserbackend"

	gh "github.com/gorilla/handlers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	CONFIG_NAME = "cboxauthd"
	CONFIG_PATH = "/etc/cboxauthd"

	KEY_SHOW_CONFIG       = "show-config"
	KEY_SHOW_CONFIG_DEBUG = "show-config-debug"

	KEY_HOST     = "host"
	DEFAULT_HOST = "localhost"

	KEY_PORT     = "port"
	DEFAULT_PORT = 2020

	KEY_ADMIN_SECRET     = "admin-secret"
	DEFAULT_ADMIN_SECRET = "foo"

	KEY_LDAP_HOSTNAME     = "ldap-hostname"
	DEFAULT_LDAP_HOSTNAME = "example.org"

	KEY_LDAP_PORT     = "ldap-port"
	DEFAULT_LDAP_PORT = 636

	KEY_LDAP_BIND_USERNAME     = "ldap-bind-username"
	DEFAULT_LDAP_BIND_USERNAME = "CN=peter,OU=Users,OU=Organic Units,DC=example,DC=org"

	KEY_LDAP_BIND_PASSWORD     = "ldap-bind_password"
	DEFAULT_LDAP_BIND_PASSWORD = "pan"

	KEY_LDAP_BASE_DN     = "ldap-base-dn"
	DEFAULT_LDAP_BASE_DN = "OU=Users,OU=Organic Units,DC=example,DC=org"

	KEY_LDAP_FILTER     = "ldap-filter"
	DEFAULT_LDAP_FILTER = "(samaccountname=%s)"

	KEY_LDAP_CONN_TIMEOUT     = "ldap-conn-timeout"
	DEFAULT_LDAP_CONN_TIMEOUT = 1

	KEY_LDAP_REQ_TIMEOUT     = "ldap-req-timeout"
	DEFAULT_LDAP_REQ_TIMEOUT = 5

	KEY_LDAP_CACHE_TTL     = "ldap-cache-ttl"
	DEFAULT_LDAP_CACHE_TTL = 86400

	KEY_SLEEP     = "sleep"
	DEFAULT_SLEEP = 5

	KEY_APP_LOG     = "app-log"
	DEFAULT_APP_LOG = "stderr"

	KEY_HTTP_LOG     = "http-log"
	DEFAULT_HTTP_LOG = "stderr"

	KEY_LOG_LEVEL     = "log-level"
	DEFAULT_LOG_LEVEL = "info"

	KEY_CONFIG          = "config-file"
	DEFAULT_CONFIG_FILE = ""
)

func init() {

	// SET CONFIGURATION DEFAULTS
	viper.SetDefault(KEY_HOST, DEFAULT_HOST)
	viper.SetDefault(KEY_PORT, DEFAULT_PORT)
	viper.SetDefault(KEY_ADMIN_SECRET, DEFAULT_ADMIN_SECRET)
	viper.SetDefault(KEY_LDAP_HOSTNAME, DEFAULT_LDAP_HOSTNAME)
	viper.SetDefault(KEY_LDAP_PORT, DEFAULT_LDAP_PORT)
	viper.SetDefault(KEY_LDAP_BIND_USERNAME, DEFAULT_LDAP_BIND_USERNAME)
	viper.SetDefault(KEY_LDAP_BIND_PASSWORD, DEFAULT_LDAP_BIND_PASSWORD)
	viper.SetDefault(KEY_LDAP_BASE_DN, DEFAULT_LDAP_BASE_DN)
	viper.SetDefault(KEY_LDAP_FILTER, DEFAULT_LDAP_FILTER)
	viper.SetDefault(KEY_LDAP_CONN_TIMEOUT, DEFAULT_LDAP_CONN_TIMEOUT)
	viper.SetDefault(KEY_LDAP_REQ_TIMEOUT, DEFAULT_LDAP_REQ_TIMEOUT)
	viper.SetDefault(KEY_LDAP_CACHE_TTL, DEFAULT_LDAP_CACHE_TTL)
	viper.SetDefault(KEY_SLEEP, DEFAULT_SLEEP)
	viper.SetDefault(KEY_APP_LOG, DEFAULT_APP_LOG)
	viper.SetDefault(KEY_HTTP_LOG, DEFAULT_HTTP_LOG)
	viper.SetDefault(KEY_LOG_LEVEL, DEFAULT_LOG_LEVEL)

	viper.SetConfigName(CONFIG_NAME)
	viper.AddConfigPath(".")
	viper.AddConfigPath(CONFIG_PATH)

	// SET FLAGS
	// action flags
	flag.Bool(KEY_SHOW_CONFIG, false, "Shows the configuration the server will use")
	flag.Bool(KEY_SHOW_CONFIG_DEBUG, false, "Show the configuration merge used by the server")

	// server configuration
	flag.String(KEY_HOST, DEFAULT_HOST, "Host to listen for connections")
	flag.Int(KEY_PORT, DEFAULT_PORT, "Port to listen for connections")
	flag.String(KEY_CONFIG, "", "Configuration file to use")
	flag.String(KEY_APP_LOG, DEFAULT_APP_LOG, "File to log application data")
	flag.String(KEY_HTTP_LOG, DEFAULT_HTTP_LOG, "File to log HTTP requests")
	flag.String(KEY_LOG_LEVEL, DEFAULT_LOG_LEVEL, "Level to log")

	// ldap configuration
	flag.String(KEY_LDAP_HOSTNAME, DEFAULT_LDAP_HOSTNAME, "Hostname of the LDAP server")
	flag.Int(KEY_LDAP_PORT, DEFAULT_LDAP_PORT, "Port of LDAP server")
	flag.String(KEY_LDAP_BIND_USERNAME, DEFAULT_LDAP_BIND_USERNAME, "The user to bind to LDAP")
	flag.String(KEY_LDAP_BIND_PASSWORD, DEFAULT_LDAP_BIND_PASSWORD, "The password to bind to LDAP")
	flag.Int(KEY_LDAP_CONN_TIMEOUT, DEFAULT_LDAP_CONN_TIMEOUT, "Timeout to create LDAP connection ")
	flag.Int(KEY_LDAP_REQ_TIMEOUT, DEFAULT_LDAP_REQ_TIMEOUT, "Timeout before aborting LDAP request")
	flag.Int(KEY_LDAP_CACHE_TTL, DEFAULT_LDAP_CACHE_TTL, "Lifetime of cached LDAP credentials")
	flag.String(KEY_LDAP_BASE_DN, DEFAULT_LDAP_BASE_DN, "The base dn to use to talk to LDAP")
	flag.String(KEY_LDAP_FILTER, DEFAULT_LDAP_FILTER, "The filter to use in LDAP queries")

	// http endpoints configuration
	flag.String(KEY_ADMIN_SECRET, DEFAULT_ADMIN_SECRET, "Secret to perform admin operations.")
	flag.Int(KEY_SLEEP, DEFAULT_SLEEP, "Time to wait on invalid requests before responding")

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
}

func main() {

	if viper.GetString(KEY_CONFIG) != "" {
		viper.SetConfigFile(viper.GetString(KEY_CONFIG))
	}

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("ERROR READING CONFIGURATION FILE: %s \n", err))
	}

	if viper.GetBool(KEY_SHOW_CONFIG) || viper.GetBool(KEY_SHOW_CONFIG_DEBUG) {
		if viper.GetBool(KEY_SHOW_CONFIG_DEBUG) {
			viper.Debug()
			fmt.Printf("Merged Config:\n%#v\n", viper.AllSettings())
		} else {
			encoded, _ := json.MarshalIndent(viper.AllSettings(), "", "  ")
			fmt.Println(string(encoded))
		}
		os.Exit(1)
	}

	logLevel := zapcore.InfoLevel
	err = logLevel.UnmarshalText([]byte(viper.GetString(KEY_LOG_LEVEL)))
	if err != nil {
		panic(fmt.Errorf("ERROR PARSING LOG LEVEL: %s\n", err))
	}

	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(logLevel)
	config.OutputPaths = []string{viper.GetString(KEY_APP_LOG)}
	logger, err := config.Build()
	if err != nil {
		panic(fmt.Errorf("ERROR CREATING LOGGER: %s\n", err))
	}

	opt := &ldapuserbackend.Options{
		Hostname:     viper.GetString(KEY_LDAP_HOSTNAME),
		Port:         viper.GetInt(KEY_LDAP_PORT),
		BaseDN:       viper.GetString(KEY_LDAP_BASE_DN),
		Filter:       viper.GetString(KEY_LDAP_FILTER),
		BindUsername: viper.GetString(KEY_LDAP_BIND_USERNAME),
		BindPassword: viper.GetString(KEY_LDAP_BIND_PASSWORD),
		Logger:       logger,
		ConTimeout:   viper.GetInt(KEY_LDAP_CONN_TIMEOUT),
		ReqTimeout:   viper.GetInt(KEY_LDAP_REQ_TIMEOUT),
		TTL:          viper.GetInt(KEY_LDAP_CACHE_TTL),
		SleepPause:   viper.GetInt(KEY_SLEEP),
	}
	ub := ldapuserbackend.New(opt)

	router := http.NewServeMux()
	authHandler := handlers.BasicAuthOnly(logger, ub, viper.GetInt(KEY_SLEEP))
	dumpHandler := handlers.AdminCheck(logger, viper.GetString(KEY_ADMIN_SECRET), handlers.DumpCache(logger, ub))
	expireHandler := handlers.AdminCheck(logger, viper.GetString(KEY_ADMIN_SECRET), handlers.ExpireCacheEntry(logger, ub))
	setHandler := handlers.AdminCheck(logger, viper.GetString(KEY_ADMIN_SECRET), handlers.SetExpiration(logger, ub))

	router.Handle("/api/v1/auth", authHandler)
	router.Handle("/api/v1/cache/dump", dumpHandler)
	router.Handle("/api/v1/cache/expire", expireHandler)     // expire?key=john:hash
	router.Handle("/api/v1/cache/setexpiration", setHandler) // setexpiration?key=john:hash&expiration=1522739593
	router.Handle("/metrics", promhttp.Handler())

	out := getHTTPLoggerOut(viper.GetString(KEY_HTTP_LOG))
	loggedRouter := gh.LoggingHandler(out, router)

	logger.Info(fmt.Sprintf("SERVER IS LISTENING AT: %s:%d", viper.GetString(KEY_HOST), viper.GetInt(KEY_PORT)))
	logger.Warn("SERVER STOPPED", zap.Error(http.ListenAndServe(fmt.Sprintf("%s:%d", viper.GetString(KEY_HOST), viper.GetInt(KEY_PORT)), loggedRouter)))
}

func getHTTPLoggerOut(filename string) *os.File {
	if filename == "stderr" {
		return os.Stderr
	} else if filename == "stdout" {
		return os.Stdout
	} else {
		fd, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		return fd
	}
}
