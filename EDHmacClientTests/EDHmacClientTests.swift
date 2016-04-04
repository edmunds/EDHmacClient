//
//  EDHmacClientTests.swift
//  EDHmacClientTests
//
//  Created by Tischuk, Christopher on 2/10/16.
//  Copyright © 2016 Edmunds.com, Inc. All rights reserved.
//

import XCTest
import Foundation
@testable import EDHmacClient

class EDHmacClientTests: XCTestCase {
    
    var apiKey: String!
    var secretKey: String!
    var request: NSMutableURLRequest!
    
    override func setUp() {
        super.setUp()
        
        apiKey = "MCAwDQYJKoZIhvcNAQEBBQADDwAwDAIFAMbwciUCAwEAAQ=="
        secretKey = "MC0CAQACBQDG8HIlAgMBAAECBBiRlekCAwDiuwIDAOCfAgMAlJcCAk3pAgMAkbI="
        request = NSMutableURLRequest(URL: NSURL(string: "http://default-environment.hbfutpqmpn.us-east-1.elasticbeanstalk.com/api/entries?")!)
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    /**
     Tests signature generation using a GET request with modified Base64
     for URL encoding.
     */
    func testSignatureValidationWithoutContentUsingModifiedBase64() {
        request.HTTPMethod = "GET"
        
        let requestEncoder = EDRequestEncoder(apiKey: apiKey, secretKey: secretKey, useModifiedBase64ForURL: true)
        requestEncoder.addAPIKey(request)
        
        let timestamp = "2016-04-02T22:02:59Z"
        
        if let signature = requestEncoder.generateSignature(request, timestamp: timestamp) {
            XCTAssert(signature == "ROgcxiAWI83CZjhAxu0_AWw6ad3EuKh35QXfSa-giT0=", "Unexpected signature.")
        }
        else {
            XCTFail("Signature cannot be nil.")
        }
    }
    
    /**
     Tests signature generation using a GET request without modified Base64
     for URL encoding.
     */
    func testSignatureGenerationWithoutContentNotUsingModifiedBase64() {
        request.HTTPMethod = "GET"
        
        let requestEncoder = EDRequestEncoder(apiKey: apiKey, secretKey: secretKey, useModifiedBase64ForURL: false)
        requestEncoder.addAPIKey(request)
        
        let timestamp = "2016-04-02T22:02:59Z"
        
        if let signature = requestEncoder.generateSignature(request, timestamp: timestamp) {
            XCTAssert(signature == "ROgcxiAWI83CZjhAxu0/AWw6ad3EuKh35QXfSa+giT0=", "Unexpected signature.")
        }
        else {
            XCTFail("Signature cannot be nil.")
        }
    }
    
    /**
     Tests signature generation using a POST request with modified Base64
     for URL encoding.
     */
    func testSignatureGenerationWithContentUsingModifiedBase64() {
        request.HTTPMethod = "POST"
        
        let HTTPBody = ["title": "new entry", "description": "new description"]
        request.HTTPBody = try? NSJSONSerialization.dataWithJSONObject(HTTPBody, options: NSJSONWritingOptions(rawValue: 0))
        
        let requestEncoder = EDRequestEncoder(apiKey: apiKey, secretKey: secretKey, useModifiedBase64ForURL: true)
        requestEncoder.addAPIKey(request)
        
        let timestamp = "2016-04-02T22:03:00Z"
        
        if let signature = requestEncoder.generateSignature(request, timestamp: timestamp) {
            XCTAssert(signature == "61fB-c_w52t8AGQtbRknDYyBmacCyb5keH4G2_e8hR0=", "Unexpected signature.")
        }
        else {
            XCTFail("Signature cannot be nil.")
        }
    }
    
    /**
     Tests signature generation using a POST request without modified Base64
     for URL encoding.
     */
    func testSignatureGenerationWithContentNotUsingModifiedBase64() {
        request.HTTPMethod = "POST"
        
        let HTTPBody = ["title": "new entry", "description": "new description"]
        request.HTTPBody = try? NSJSONSerialization.dataWithJSONObject(HTTPBody, options: NSJSONWritingOptions(rawValue: 0))
        
        let requestEncoder = EDRequestEncoder(apiKey: apiKey, secretKey: secretKey, useModifiedBase64ForURL: false)
        requestEncoder.addAPIKey(request)
        
        let timestamp = "2016-04-02T22:03:00Z"
        
        if let signature = requestEncoder.generateSignature(request, timestamp: timestamp) {
            XCTAssert(signature == "61fB+c/w52t8AGQtbRknDYyBmacCyb5keH4G2/e8hR0=", "Unexpected signature.")
        }
        else {
            XCTFail("Signature cannot be nil.")
        }
    }
}
