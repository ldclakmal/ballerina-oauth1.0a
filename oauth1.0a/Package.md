# Ballerina OAuth1.0a

`Ballerina OAuth1.0a` is an <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc5849">RFC 5849</a> standards-compliant library for <a target="_blank" href="https://ballerina.io/">Ballerina</a>.

This module provides a method for clients to access server resources on behalf of a resource owner (such as a different client or an end-user) as specified in the <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc5849">RFC 5849</a>.  It also provides a process for end-users to authorize third-party access to their server resources without sharing their credentials (typically, a username and password pair), using user-agent redirections.

This module facilitates auth providers that are to be used by the clients and listeners of different protocol connectors.

## Compatibility
|                    | Version          |
|:------------------:|:----------------:|
| Ballerina Language | Swan Lake GA     |

## Examples

```ballerina
import ballerina/http;
import ballerina/io;
import ldclakmal/oauth1;

public function main() returns error? {
    oauth1:ClientOAuthHandler oauthHandler = new({
        signatureMethod: oauth1:HMAC_SHA1,
        consumerKey: "dpf43f3p2l4k3l03",
        consumerSecret: "kd94hf93k423kf44",
        accessToken: "hh5s93j4hdidpola",
        accessTokenSecret: "pfkkdhi9sl3r4s00",
        realm: "Photos",
        nonce: "7d8f3e4a"
    });
    map<string|string[]> securityHeaders = check oauthHandler.getSecurityHeaders("GET", 
        "https://photos.example.net/request?type=jpg&maxsize=10mb");
    final http:Client clientEP = check new("https://photos.example.net");
    json payload = check clientEP->get("/request?type=jpg&maxsize=10mb", securityHeaders);
    io:println(payload);
}
```
