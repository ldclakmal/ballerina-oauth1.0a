# Represents OAuth1.0a configurations.
#
# + consumerKey - The consumer key
# + consumerSecret - The consumer secret
# + accessToken - The access token
# + accessTokenSecret - The access token secret
# + realm - The realm value
# + nonce - The nonce value
public type OAuthConfig record {|
    string consumerKey;
    string consumerSecret;
    string accessToken;
    string accessTokenSecret;
    string realm?;
    string nonce?;
|};

isolated class ClientOAuthProvider {

    private final OAuthConfig & readonly config;

    isolated function init(OAuthConfig config) {
        self.config = config.cloneReadOnly();
    }

    isolated function generateToken(string httpMethod, string url) returns string|error {
        string|error authToken = buildOAuthValue(self.config, httpMethod, url);
        if (authToken is string) {
            return authToken;
        } else {
            return error("Failed to generate OAuth1.0a token.", authToken);
        }
    }
}
