import ballerina/crypto;
import ballerina/regex;
import ballerina/time;
import ballerina/url;
import ballerina/uuid;

const string UTF_8 = "UTF-8";

isolated function buildOAuthValue(OAuthConfig config, string httpMethod, string url) returns string|error {
    string nonce = uuid:createType4AsString();
    if config?.nonce is string {
        nonce = <string>config?.nonce;
    }
    int timeInSeconds = time:utcNow()[0];
    string timestamp = timeInSeconds.toString();
    map<string> params = check buildProtocolParams(config.signatureMethod, config.consumerKey, config.accessToken, nonce, timestamp);
    string requestUrl = url;
    if url.includes("?") {
        string[] urlParts = regex:split(url, "\\?");
        requestUrl = urlParts[0];
        map<string> queryParams = buildQueryParams(urlParts[1]);
        params = <map<string>> check queryParams.mergeJson(params);
    }
    string normalizedParams = normalizeParams(params);
    string baseString = check buildBaseString(httpMethod, requestUrl, normalizedParams);
    string signature = check generateSignature(config.signatureMethod, baseString, config.consumerSecret, config.accessTokenSecret);
    string encodedSignature = check url:encode(signature, UTF_8);
    string encodedaccessToken = check url:encode(config.accessToken, UTF_8);

    string value = "OAuth ";
    if config?.realm is string {
        value += "realm=\"" + <string>config?.realm + "\",";
    }
    value += "oauth_consumer_key=\"" + config.consumerKey + "\"," + 
            "oauth_token=\"" + encodedaccessToken + "\"," + 
            "oauth_signature=\"" + encodedSignature + "\"," + 
            "oauth_timestamp=\"" + timestamp + "\"," + 
            "oauth_nonce=\"" + nonce + "\"," + 
            "oauth_signature_method=\"" + config.signatureMethod + "\"," + 
            "oauth_version=\"1.0\"";
    return value;
}

isolated function buildProtocolParams(string signatureMethod, string consumerKey, string accessToken, string nonce, string timestamp) returns map<string>|error {
    map<string> protocolParams = {
        "oauth_consumer_key": consumerKey, 
        "oauth_token": accessToken, 
        "oauth_timestamp": timestamp, 
        "oauth_nonce": nonce, 
        "oauth_signature_method": signatureMethod, 
        "oauth_version": "1.0"
    };
    return protocolParams;
}

isolated function buildQueryParams(string urlQueryParams) returns map<string> {
    map<string> queryParams = {};
    string[] queryParamParts = regex:split(urlQueryParams, "\\&");
    foreach string param in queryParamParts {
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

isolated function generateSignature(string signatureMethod, string baseString, string consumerSecret, string accessTokenSecret) returns string|error {
    string encodedConsumerSecret = check url:encode(consumerSecret, UTF_8);
    string encodedAccessTokenSecret = check url:encode(accessTokenSecret, UTF_8);
    string 'key = encodedConsumerSecret + "&" + encodedAccessTokenSecret;
    if signatureMethod is HMAC_SHA1 {
        byte[] hmac = check crypto:hmacSha1(baseString.toBytes(), 'key.toBytes());
        return hmac.toBase64();
    } else if signatureMethod is HMAC_SHA256 {
        byte[] hmac = check crypto:hmacSha256(baseString.toBytes(), 'key.toBytes());
        return hmac.toBase64();
    } else {
        byte[] hmac = check crypto:hmacSha512(baseString.toBytes(), 'key.toBytes());
        return hmac.toBase64();
    }
}
