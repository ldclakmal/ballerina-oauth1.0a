# Defines the OAuth1.0a handler for client authentication.
public isolated client class ClientOAuthHandler {

    private final ClientOAuthProvider provider;

    public isolated function init(OAuthConfig config) {
        self.provider = new(config);
    }

    # Returns the headers map with the relevant authentication requirements.
    # 
    # + httpMethod - The HTTP request method in uppercase ('HEAD', 'GET', 'POST', etc.)
    # + url - The complete URL with query parameters if present
    # + return - The updated headers map or else an error
    public isolated function getSecurityHeaders(string httpMethod, string url) returns map<string|string[]>|error {
        string|error result = self.provider.generateToken(httpMethod, url);
        if (result is string) {
            map<string|string[]> headers = {};
            headers["Authorization"] = result;
            return headers;
        } else {
            return error("Failed to enrich headers with OAuth1.0a token.", result);
        }
    }
}
