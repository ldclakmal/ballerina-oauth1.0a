import ballerina/crypto;
import ballerina/regex;
import ballerina/time;
import ballerina/url;
import ballerina/uuid;

const string UTF_8 = "UTF-8";

isolated function buildOAuthValue(OAuthConfig config, string httpMethod, string url) returns string|error {
    map<string> params = check buildProtocolParams(config.consumerKey, config.accessToken);
    if url.includes("?") {
        map<string> queryParams = buildQueryParams(url);
        params = <map<string>> check queryParams.mergeJson(params);
    }
    string normalizedParams = normalizeParams(params);
    string baseString = check buildBaseString(httpMethod, url, normalizedParams);
    string signature = check generateSignature(baseString, config.consumerSecret, config.accessTokenSecret);
    string encodedSignature = check url:encode(signature, UTF_8);
    string encodedaccessToken = check url:encode(config.accessToken, UTF_8);
    string nonce = uuid:createType4AsString();
    if config?.nonce is string {
        nonce = <string>config?.nonce;
    }
    int timeInSeconds = time:utcNow()[0];
    string timestamp = timeInSeconds.toString();
    string value = "OAuth ";
    if config?.realm is string {
        value += "realm=" + <string>config?.realm;
    }
    value += ",oauth_consumer_key=\"" + config.consumerKey + "\"," + 
            "oauth_signature_method=\"HMAC-SHA1\"," + 
            "oauth_timestamp=\"" + timestamp + "\"," + 
            "oauth_nonce=\"" + nonce + "\"," + 
            "oauth_version=\"1.0\"," + 
            "oauth_signature=\"" + encodedSignature + "\"," + 
            "oauth_token=\"" + encodedaccessToken + "\"";
    return value;
}

isolated function buildProtocolParams(string consumerKey, string accessToken) returns map<string>|error {
    string nonce = uuid:createType4AsString();
    int timeInSeconds = time:utcNow()[0];
    string timestamp = timeInSeconds.toString();
    map<string> protocolParams = {
        "oauth_consumer_key": consumerKey, 
        "oauth_token": accessToken, 
        "oauth_timestamp": timestamp, 
        "oauth_nonce": nonce, 
        "oauth_signature_method": "HMAC-SHA1", 
        "oauth_version": "1.0"
    };
    return protocolParams;
}

isolated function buildQueryParams(string url) returns map<string> {
    map<string> queryParams = {};
    string[] flatQueryParams = regex:split(regex:split(url, "\\?")[1], "\\&");
    foreach string param in flatQueryParams {
        string[] splittedParam = regex:split(param, "=");
        queryParams[splittedParam[0]] = splittedParam[1];
    }
    return queryParams;
}

isolated function normalizeParams(map<string> params) returns string {
    string normalizedParams = "";
    string[] sortedKeys = params.keys().sort();
    foreach string 'key in sortedKeys {
        normalizedParams += "&" + 'key + "=" + params.get('key);
    }
    return normalizedParams.substring(1, normalizedParams.length());
}

isolated function buildBaseString(string httpMethod, string url, string normalizedParams) returns string|error {
    string encodedParams = check url:encode(normalizedParams, UTF_8);
    string encodedUrl = check url:encode(url, UTF_8);
    return httpMethod + "&" + encodedUrl + "&" + encodedParams;
}

isolated function generateSignature(string baseString, string consumerSecret, string accessTokenSecret) returns string|error {
    string encodedConsumerSecret = check url:encode(consumerSecret, UTF_8);
    string encodedAccessTokenSecret = check url:encode(accessTokenSecret, UTF_8);
    string key = encodedConsumerSecret + "&" + encodedAccessTokenSecret;
    byte[] hmac = check crypto:hmacSha1(baseString.toBytes(), key.toBytes());
    return hmac.toBase64();
}
