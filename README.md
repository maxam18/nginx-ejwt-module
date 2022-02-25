# Easy JWT

Simple lightweight JWT authorization module for nginx **[Nginx](https://nignx.org/)** web server

## Lightweight 
Does not use JWT and JSON libraries. Does not validate JSON integrity.

Parses JWT from Authorization or Cookie.

Supports WWW-Authentication request.

## Features
Receives JWT in `Authorization: Bearer` or `Cookie` HTTP request field (configurable)

Decodes JWT, checks expiration (`exp` claim field), checks signature, check "authorization for a resource" by comparing payload (claim) field value with the complex variable string.

Responds with realm and error descriptions in WWW-Authenticate field

Supports second key for signature validation. Useful for key renewal at auth server.


## Logging
Register two nginx variables. 
`ejwt_claim` - keeps value of the payload field configured for logging 
`ejwt_auth` - keeps value of the payload field set for authorization (if any)

## Flexibility
Different behaviour depending on configuration
- JWT parse and expiration check
- JWT parse, expiration check, signature check
- JWT parse, expiration check, signature check, authoriation check


# Try
## Configuration example

    http {
        # this sets cookie name to look token in
        easy_jwt_cookie auth;
        # this sets realm for WWW-Authenticate response
        easy_jwt_realm  "Highly restricted area";

        access_log  ejwt_fmt  '$uri   $ejwt_auth  $ejwt_claim';

    	server {
            listen 8080;
            
            access_log  logs/ejwt.log  ejwt_fmt;

            # this location will only check expiration and dump whole payload to the log by variable ejwt_claim
            location /ejwt_log {
                empty_gif;
                easy_jwt    on;
                easy_jwt_claim '*';
            }
            
            # this location will check token expiration and validate signature 
            location /ejwt_check {
                empty_gif;
                easy_jwt    on;
                # this sets 'Secret' as the key for HS256 signature validation
                easy_jwt_key    HS256   'Secret';
            }

            # this location will check token expiration, validate signature and authorize uri
            location /ejwt_auth {
                empty_gif;
                easy_jwt    on;
                # this sets 'Secret' as the key for HS256 signature validation
                easy_jwt_key    HS256   'Secret';
                # this sets authorization procedure for the location
                easy_jwt_auth   sub  '/ejwt_auth';
            }

            # this location will check token expiration, validate signature and authorize uri
            location /private/folders {
                empty_gif;
                easy_jwt    on;
                # this sets 'Secret' as the key for HS256 signature validation
                easy_jwt_key    HS256   'Secret';
                # this sets authorization procedure for the subfolders locations
                # set the sub to '/private/folders/max' and this will give access to 'max' only
                easy_jwt_auth   sub  '$uri';
            }
       }
	}

# Build

## dependency
Module uses openssl HMAC_ for signature validation. Build nginx with openssl.

## Static build

    ./configure --add-module=/path/to/nginx-kafka-log-module

## Dynamic library
  
	./configure --add-dynamic-module=/path/to/nginx-kafka-log-module

# Configuration

**Nginx** configuration directives below. 

## easy_jwt - module operation mode
**Syntax**: `easy_jwt  [off|parse|hs256|rs256|hmac|pub|all`
**Default**: `off`
**Context**: location

    Turns on module functionality.
    parse - only parses JWT
    hs256 - check JWT only HS256 signature if found in JWT
    rs256 - check JWT only RS256 signature if found in JWT
    hmac  - check JWT HMAC only signature if found in JWT (based on 'alg' from JWT header)
    pub   - check JWT priv/pub key signature if found in JWT (based on 'alg' from JWT header)
    all   - check JWT with any supported algorithms (based on 'alg' from JWT header)

## easy_jwt_cookie 
**Syntax**: `easy_jwt_cookie  name`
**Default**: `NULL`
**Context**: `main`,`server`,`location`

    Cookie name for token lookup. Easy JWT looks for `Authorization: Bearer` value first, then look for a cookie if the `name` is set.

## easy_jwt_realm 
**Syntax**: `easy_jwt_realm  text`
**Default**: `NULL`
**Context**: `main`,`server`,`location`

    Responds with WWW-Authenticate header field if value is set.
    Module adds realm="text" if the text of non-zero length

## easy_jwt_key 
**Syntax**: `easy_jwt_key  ALGO KEY1 [KEY2]`
**Default**: `NULL`
**Context**: `main`,`server`,`location`

    `ALGO` is the signature algorithm. HS256, RS256 supported.
    `KEY1` first key to check signature with. Or file path to public PEM-encoded RSA key 
    `KEY2` seconds key to check signature if the check on `KEY1` fails. or file path to public PEM-encoded RSA key

## easy_jwt_auth
**Syntax**: `easy_jwt_auth  name  value`
**Default**: `NULL`
**Context**: `location`

    Sets authorization for a location
    The `name` payload field value compared with the configured `value`.
    Request rejected with the `403 HTTP response` if the payload does not meet `value`
    `value` is a complex string and accepts nginx variable

## easy_jwt_claim
**Syntax**: `easy_jwt_claim  name`
**Default**: `NULL`
**Context**: `main`,`server`,`location`

    `ejwt_claim` variable initialized with the value of the `name` claim (payload) field if set
    if the `name` is `*`, full claim is set as `ejwt_claim` variable value



## Author
Max Amzarakov `maxam18 at Google`

## RFC Notes
### RFC6750 
3. WWW-Authenticate reply MUST be set
### RFC7519
4. JWT claims
parse latest duplicate key value or reject
