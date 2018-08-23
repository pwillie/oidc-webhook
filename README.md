# oidc-ingress

A webhook authentication service using OIDC and cookies

Motivation for creating this service is to easily add OIDC authentication to any
service running behind an Nginx Ingress controller in Kubernetes.  By using cookies
there is no need for client side changes and any legacy system/service can be authenticated.

## Kubernetes Nginx Ingress OIDC sequence diagram

![OIDC Sequence Diagram](/images/sequence.png?raw=true "OIDC Sequence Diagram")

Created using: *https://sequencediagram.org/*

## Configuration

| Env Var  | CMD line arg | Default Value | Notes |
|----------|--------------|---------------|-------|
| CLIENTS  | -clients     | -             | OIDC clients config expressed in yaml (see below) |
| ETCD     | -etcd        | localhost:2379 | etcd endpoint to connect to.  This is required |
| LISTEN   | -listen      | :8000         | Web server listen address |
| INTERNAL | -internal    | :9000         | Internal listen address for healthz and metrics endpoints |
| EXTERNALURL | -externalUrl | -          | The url that this application is listening on.  In kubernetes, this will be governed by the ingress setup. |
| VERSION  | -version     | -             | When set will print version and exit |

## Clients

Clients env var (or cmd line arg) is a YAML formated string.  For example:
```
- profile: name-of-app
  provider: https://oauth.provider.url/
  clientid: client_id
  clientsecret: client_secret
  noredirect: false (default: false)
  scopes: (default: - openid)
    - openid
    - email
    - profile
  cookieDomain: example.com
  cookieSecret: super-secret-stuff-used-to-encrypt-the-cookie
```

*note:* `noredirect` will suppress the `?rd={redirect url}` from the path.  Handy for Azure AD as querystring is stripped anyway and redirect url must match exactly.

## Building

```console
$ make build
$ ./bin/oidc-ingress
```

## Testing

```
$ make test
```
Clearly there aren't a lot of tests here yet.  Hopefully that'll change soon.

# TODO's
[ ] Add a reasonably comprehensive set of tests  
[ ] Explain use of ETCD  
[ ] Explain ExternalUrl  
[ ] Expand hashing to full encryption  
[ ] Make logging consistent  
