# CERNBox Authentication Daemon


This daemon performs authentication against LDAP for basic auth requests.

```
Usage of ./cboxauthd:
      --admin-secret string         secreto to access admin APIs for cache manipulation. (default "bar")
      --app-log string              file to log application information. (default "stderr")
      --config-file string          configuration file to use
      --http-log string             file to log HTTP requests. (default "stderr")
      --http-read-timeout int       the maximum duration for reading the entire request, including the body. (default 300)
      --http-write-timeout int      the maximum duration for timing out writes of the response. (default 300)
      --ldap-base-dn string         LDAP base DN. (default "OU=Users,OU=Organic Units,DC=cern,DC=ch")
      --ldap-base-filter string     LDAP base search filter. (default "(samaccountname=%s)")
      --ldap-bind-password string   LDAP bind password. (default "bar")
      --ldap-bind-username string   LDAP bind username. (default "CN=foo,OU=Users,OU=Organic Units,DC=cern,DC=ch")
      --ldap-cache-ttl int          LDAP cache TTL. (default 86400)
      --ldap-conn-timeout int       LDAP connection timeout.
      --ldap-hostname string        LDAP server hostname. (default "localhost")
      --ldap-port int               LDAP server port. (default 636)
      --ldap-req-timeout int        LDAP request timeout.
      --log-level string            log level to use (debug, info, warn, error). (default "info")
      --safety-sleep int            Seconds to pause requests on authentication failure. (default 5)
      --show-config                 prints the configuration
      --show-config-debug           prints the configuration with resolution steps
      --tcp-address string          tcp address to listen for connections. (default "localhost:9991")
pflag: help requested

```

## Some example requests

```
curl -i localhost:2020/api/v1/auth -u "testuser"

HTTP/1.1 200 OK
Set-Cookie: oc_sessionpassphrase=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MDg5NDcxOTczMTk0MzgzOTAsInVzZXJuYW1lIjoiZ29uemFsaHUifQ.nmozCjrSZmuY79CNa4kDoQFLcANrlWDDlMz_8S0b-GY
Date: Wed, 25 Oct 2017 14:59:57 GMT
Content-Length: 0
Content-Type: text/plain; charset=utf-8


curl -i localhost:2020/api/v1/auth -b "oc_sessionpassphrase=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MDg5NDcxOTczMTk0MzgzOTAsInVzZXJuYW1lIjoiZ29uemFsaHUifQ.nmozCjrSZmuY79CNa4kDoQFLcANrlWDDlMz_8S0b-GY"

HTTP/1.1 200 OK
Date: Wed, 25 Oct 2017 15:01:18 GMT
Content-Length: 0
Content-Type: text/plain; charset=utf-8
```

