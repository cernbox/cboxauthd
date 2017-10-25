# go-nginx-auth daemon

This daemon performs authentication against LDAP for basic auth requests.

```
$ ./go-nginx-auth -h
Usage of ./go-nginx-auth:
      --applog string             File to log application data (default "stderr")
      --config string             Configuration file to use
      --httplog string            File to log HTTP requests (default "stderr")
      --ldapbasedn string         The base dn to use to talk to LDAP (default "OU=Users,OU=Organic Units,DC=cern,DC=ch")
      --ldapbindpassword string   The password to bind to LDAP (default "testpassword")
      --ldapbindusername string   The user to bind to LDAP (default "CERN\\testuser")
      --ldapfilter string         The filter to use in LDAP queries (default "(samaccountname=%s)")
      --ldaphostname string       Hostname of the LDAP server (default "cerndc.cern.ch")
      --ldapport int              Port of LDAP server (default 636)
      --port int                  Port to listen for connections (default 2020)
      --version                   Show version
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

