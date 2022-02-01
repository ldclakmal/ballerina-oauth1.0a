# Represents OAuth1.0a configurations.
#
# + signatureMethod - The cryptographic algorithm used for the signature
# + consumerKey - The consumer key
# + consumerSecret - The consumer secret
# + accessToken - The access token
# + accessTokenSecret - The access token secret
# + realm - The realm value
# + nonce - The nonce value
public type OAuthConfig record {|
    SigningAlgorithm signatureMethod;
    string consumerKey;
    string consumerSecret;
    string accessToken;
    string accessTokenSecret;
    string realm?;
    string nonce?;
|};

# Represents the cryptographic algorithm used for the signature.
public type SigningAlgorithm HMAC_SHA1|HMAC_SHA256|HMAC_SHA512;

# The `HMAC-SHA1` algorithm.
public const HMAC_SHA1 = "HMAC-SHA1";

# The `HMAC-SHA256` algorithm.
public const HMAC_SHA256 = "HMAC-SHA256";

# The `HMAC-SHA512` algorithm.
public const HMAC_SHA512 = "HMAC-SHA512";

isolated class ClientOAuthProvider {

    private final OAuthConfig & readonly config;

    isolated function init(OAuthConfig config) {
        self.config = config.cloneReadOnly();
    }

    isolated function generateToken(string httpMethod, string url) returns string|error {
        string|error authToken = buildOAuthValue(self.config, httpMethod, url);
        if authToken is string {
            return authToken;
        } else {
            return error("Failed to generate OAuth1.0a token.", authToken);
        }
    }
}
