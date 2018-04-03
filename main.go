package main

import (
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

var fVersion bool
var logLevel = zapcore.InfoLevel

func init() {
	viper.SetDefault("port", 2020)
	viper.SetDefault("adminsecret", "doo")
	viper.SetDefault("ldaphostname", "cerndc.cern.ch")
	viper.SetDefault("ldapport", 636)
	viper.SetDefault("ldapbindusername", "testuser")
	viper.SetDefault("ldapbindpassword", "testpassword")
	viper.SetDefault("ldapbasedn", "OU=Users,OU=Organic Units,DC=cern,DC=ch")
	viper.SetDefault("ldapfilter", "(samaccountname=%s)")
	viper.SetDefault("signingkey", "change me!!!")
	viper.SetDefault("applog", "stderr")
	viper.SetDefault("httplog", "stderr")
	viper.SetDefault("expiretime", 3600)
	viper.SetDefault("owncloudcookiename", "oc_sessionpassphrase")
	viper.SetDefault("loglevel", "info")

	viper.SetConfigName("cboxauthd")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/cboxauthd/")

	flag.Int("port", 2020, "Port to listen for connections")
	flag.String("adminsecret", "doo", "Secret to perform admin operations.")
	flag.String("ldaphostname", "cerndc.cern.ch", "Hostname of the LDAP server")
	flag.Int("ldapport", 636, "Port of LDAP server")
	flag.String("ldapbindusername", "CERN\\testuser", "The user to bind to LDAP")
	flag.String("ldapbindpassword", "testpassword", "The password to bind to LDAP")
	flag.String("ldapbasedn", "OU=Users,OU=Organic Units,DC=cern,DC=ch", "The base dn to use to talk to LDAP")
	flag.String("ldapfilter", "(samaccountname=%s)", "The filter to use in LDAP queries")
	flag.String("signingkey", "change me!!!", "The key to use to sign the JWT tokens")
	flag.String("applog", "stderr", "File to log application data")
	flag.String("httplog", "stderr", "File to log HTTP requests")
	flag.String("config", "", "Configuration file to use")
	flag.Int("expiretime", 3600, "Time in seconds the jwt/cookie will be valid")
	flag.String("owncloudcookiename", "oc_sessionpassphrase", "Cookie to store the auth session in the client")
	flag.String("loglevel", "info", "Level to log")

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
}

func main() {

	if viper.GetString("config") != "" {
		viper.SetConfigFile(viper.GetString("config"))
	}

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	err = logLevel.UnmarshalText([]byte(viper.GetString("loglevel")))
	if err != nil {
		panic(err)
	}

	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(logLevel)
	config.OutputPaths = []string{viper.GetString("applog")}
	logger, err := config.Build()
	if err != nil {
		panic(err)
	}

	opt := &ldapuserbackend.Options{
		Hostname:     viper.GetString("ldaphostname"),
		Port:         viper.GetInt("ldapport"),
		BaseDN:       viper.GetString("ldapbasedn"),
		Filter:       viper.GetString("ldapfilter"),
		BindUsername: viper.GetString("ldapbindusername"),
		BindPassword: viper.GetString("ldapbindpassword"),
		Logger:       logger,
	}
	ub := ldapuserbackend.New(opt)

	router := http.NewServeMux()
	authHandler := handlers.BasicAuthOnly(logger, ub, viper.GetString("signingkey"), viper.GetInt("expiretime"), viper.GetString("owncloudcookiename"))
	dumpHandler := handlers.AdminCheck(logger, viper.GetString("adminsecret"), handlers.DumpCache(logger, ub))
	expireHandler := handlers.AdminCheck(logger, viper.GetString("adminsecret"), handlers.ExpireCacheEntry(logger, ub))
	setHandler := handlers.AdminCheck(logger, viper.GetString("adminsecret"), handlers.SetExpiration(logger, ub))

	router.Handle("/api/v1/auth", authHandler)
	router.Handle("/api/v1/cache/dump", dumpHandler)
	router.Handle("/api/v1/cache/expire", expireHandler)     // expire?key=john:hash
	router.Handle("/api/v1/cache/setexpiration", setHandler) // setexpiration?key=john:hash&expiration=1522739593
	router.Handle("/metrics", promhttp.Handler())

	out := getHTTPLoggerOut(viper.GetString("httplog"))
	loggedRouter := gh.LoggingHandler(out, router)

	logger.Info("server is listening", zap.Int("port", viper.GetInt("port")))
	logger.Warn("server stopped", zap.Error(http.ListenAndServe(fmt.Sprintf(":%d", viper.GetInt("port")), loggedRouter)))
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
