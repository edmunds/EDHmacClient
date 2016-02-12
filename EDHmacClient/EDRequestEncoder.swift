//
//  EDRequestEncoder.swift
//  EDHmacClient
//
//  Created by Tischuk, Christopher on 2/10/16.
//  Copyright © 2016 Edmunds.com, Inc. All rights reserved.
/**
    Encodes an outbound NSMutableURLRequest with security credentials
    so that it can be authenticated on the receiving server.
*/

import Foundation
import CommonCrypto

class EDRequestEncoder {
    
    let apiKey: String
    let secretKey: String
    let apiKeyQueryParameter = "apiKey"
    let signatureHTTPHeader = "X-Auth-Signature"
    let timestampHTTPHeader = "X-Auth-Timestamp"
    let versionHTTPHeader = "X-Auth-Version"
    let version = "1"
    let useModifiedBase64ForURL: Bool
    
    /**
     @param apiKey The API key to be used.
     @param secretKey The secret key to be used.
     @param useModifiedBase64ForURL A boolean indicating whether to use modified Base64
                                    for URL encoding in the generated signature. Setting
                                    this to true will replace '+' and '/' characters 
                                    with '-' and '_' respectively in the signature.
     
     */
    init(apiKey: String, secretKey: String, useModifiedBase64ForURL: Bool) {
        self.apiKey = apiKey
        self.secretKey = secretKey
        self.useModifiedBase64ForURL = useModifiedBase64ForURL
    }
    
    // MARK: - Main Method
    
    /**
     Encodes an outbound NSMutableURLRequest. 
     Any query parameter string should be added to the URL before calling this method,
     and it should NOT contain the API key as it is added here.
     
     @param request The outbound NSMutableURLRequest.
     */
    func encodeRequest(request: NSMutableURLRequest) {
        let timestamp = getCurrentTimeStamp()
        self.addAPIKey(request)
        self.addTimeStamp(request, timestamp: timestamp)
        self.addSignature(request, timestamp: timestamp)
        self.addVersion(request)
    }
    
    // MARK: - Utility Methods
    
    func getCurrentTimeStamp() -> String {
        let dateFormatter = NSDateFormatter()
        
        dateFormatter.locale = NSLocale(localeIdentifier: "en_US_POSIX")
        dateFormatter.timeZone = NSTimeZone(name: "UTC")
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        
        return dateFormatter.stringFromDate(NSDate())
    }
    
    /**
     Adds the API Key as a query parameter to the outbound HTTP request.
     
     @param request The outbound NSMutableURLRequest.
     */
    func addAPIKey(request: NSMutableURLRequest) {
        if let urlString = request.URL?.absoluteString, urlComponents = NSURLComponents(string: urlString) {
            if urlComponents.queryItems == nil {
                urlComponents.queryItems = [NSURLQueryItem(name: apiKeyQueryParameter, value: apiKey)]
            }
            else {
                urlComponents.queryItems?.append(NSURLQueryItem(name: apiKeyQueryParameter, value: apiKey))
            }
            request.URL = urlComponents.URL
        }
    }
    
    func addTimeStamp(request: NSMutableURLRequest, timestamp: String) {
        request.addValue(timestamp, forHTTPHeaderField: timestampHTTPHeader)
    }
    
    func addVersion(request: NSMutableURLRequest) {
        request.addValue(version, forHTTPHeaderField: versionHTTPHeader)
    }
    
    /**
     Adds a signature to the authorization header of the outbound request.
     
     @param request The outbound NSMutableURLRequest.
     @param timestamp The timestamp used to generate the signature.
     
     */
    func addSignature(request: NSMutableURLRequest, timestamp: String) {
        if let signature = generateSignature(request, timestamp: timestamp) {
            request.addValue(signature, forHTTPHeaderField: signatureHTTPHeader)
        }
    }
    
    /**
     Generates an authentication code using HMAC-SHA256.
     
     @param request The NSMutableURLRequest used to generate the signature.
     @param timestamp The timestamp used to generate the signature.
     
     @return the encoded signature.
     */
    func generateSignature(request: NSMutableURLRequest, timestamp: String) -> String? {
        if let path = request.URL?.path?.stringByRemovingPercentEncoding, query = request.URL?.query?.stringByRemovingPercentEncoding {
            let delimiter = "\n"
            let message = "\(request.HTTPMethod)\(delimiter)\(timestamp)\(delimiter)\(path)?\(query)"
            
            if let messageData = message.dataUsingEncoding(NSUTF8StringEncoding),
                    secretData = secretKey.dataUsingEncoding(NSUTF8StringEncoding) {
                    
                let digest = UnsafeMutablePointer<CUnsignedChar>.alloc(Int(CC_SHA256_DIGEST_LENGTH))
                
                let hmacContext = UnsafeMutablePointer<CCHmacContext>.alloc(1)
                CCHmacInit(hmacContext, UInt32(kCCHmacAlgSHA256), secretData.bytes, secretData.length)
                CCHmacUpdate(hmacContext, messageData.bytes, messageData.length)
                CCHmacFinal(hmacContext, digest)
                
                let digestData = NSData(bytes: digest, length: Int(CC_SHA256_DIGEST_LENGTH))
                var signature = digestData.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
                
                if useModifiedBase64ForURL {
                    signature = signature.stringByReplacingOccurrencesOfString("/", withString: "_")
                    signature = signature.stringByReplacingOccurrencesOfString("+", withString: "-")
                }
                return signature
            }
        }
        return nil
    }
}