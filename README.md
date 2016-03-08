# EDHmacClient

HMAC authentication for iOS applications.

This library makes it easy to add support for HMAC authentication in iOS applications.

It works by adding HTTP headers to an outbound NSMutableURLRequest to encode the request for HMAC authentication.

## Getting Started

In your code, import the `EDHmacClient` class:

```swift
import EDHmacClient

if let url = NSURL(string: "http://example.com/api/testMethod") {
	let request = NSMutableURLRequest(URL: url)
	request.HTTPMethod = "DELETE"

	let requestEncoder = EDRequestEncoder(apiKey: 'your_api_key', secretKey: 'your_secret_key', useModifiedBase64ForURL: true)
	requestEncoder.encodeRequest(request)
	
	//...Send out request
}

```

Before calling encodeRequest, ensure that the NSURL contains any necessary query parameters. However, you should not add the API key as a query parameter because it is added for you in the internal implementation of encodeRequest.

The **useModifiedBase64ForURL** parameter in the initializer of EDRequestEncoder specifies whether to use modified Base64 for URL encoding in the generated signature. Setting this to true will replace '+' and '/' characters with '-' and '_' respectively in the signature.

If you need to change the names of the query parameter and headers used by HMAC, you can do so after initialization by setting:
* apiKeyQueryParameter
* signatureHTTPHeader
* timestampHTTPHeader
* versionHTTPHeader

Changes in the client must also be made at the server or authentication will not work.