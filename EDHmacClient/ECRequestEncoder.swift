//
//  ECRequestEncoder.swift
//  EDHmacClient
//
//  Created by Tischuk, Christopher on 2/10/16.
//  Copyright © 2016 Edmunds.com, Inc. All rights reserved.
//

import Foundation
import CommonCrypto

class ECRequestEncoder {
    
    let apiKey: String
    let secretKey: String
    let apiKeyQueryParameter = "apiKey"
    let signatureHTTPHeader = "X-Auth-Signature"
    let timestampHTTPHeader = "X-Auth-Timestamp"
    let versionHTTPHeader = "X-Auth-Version"
    let version = "1"
    let useModifiedBase64ForURL: Bool
    
    init(apiKey: String, secretKey: String, useModifiedBase64ForURL: Bool) {
        self.apiKey = apiKey
        self.secretKey = secretKey
        self.useModifiedBase64ForURL = useModifiedBase64ForURL
    }
    
    // MARK: - Public Method
    
    func encodeRequest(request: NSMutableURLRequest) {
        let timestamp = getCurrentTimeStamp()
        self.addAPIKey(request)
        self.addTimeStamp(request, timestamp: timestamp)
        self.addSignature(request, timestamp: timestamp)
        self.addVersion(request)
    }
    
    // MARK: - Private Methods
    
    private func getCurrentTimeStamp() -> String {
        let dateFormatter = NSDateFormatter()
        
        dateFormatter.locale = NSLocale(localeIdentifier: "en_US_POSIX")
        dateFormatter.timeZone = NSTimeZone(name: "UTC")
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        
        return dateFormatter.stringFromDate(NSDate())
    }
    
    private func addAPIKey(request: NSMutableURLRequest) {
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
    
    private func addTimeStamp(request: NSMutableURLRequest, timestamp: String) {
        request.addValue(timestamp, forHTTPHeaderField: timestampHTTPHeader)
    }
    
    private func addVersion(request: NSMutableURLRequest) {
        request.addValue(version, forHTTPHeaderField: versionHTTPHeader)
    }
    
    private func addSignature(request: NSMutableURLRequest, timestamp: String) {
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
                    
                    request.addValue(signature, forHTTPHeaderField: signatureHTTPHeader)
            }
        }
    }
}