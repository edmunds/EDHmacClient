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
    var timestamp: String!
    
    override func setUp() {
        super.setUp()
        
        apiKey = "4424pfbGmD4PMSkE4MN8c3lM0UeSAXVe894E7462AEF624B732DDBAFB5AC78pQlEIS1s8H9q5IpKegKE051x7vEMZ9Ht+H15jE3ae4fM2Ma33TFqO52BeHY1fDiZY5zmO74ycX8"
        secretKey = "A53G5Qswm1CnF23Jf2JM0aG98323nB0AgrNlGBI3vW2hNKTR6Pnn5G5Ww3vRXw=="
        request = NSMutableURLRequest(URL: NSURL(string: "http://www.edmunds.com/api/testMethod")!)
        timestamp = "2016-02-02T00:09:22Z"
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testSignatureValidationWithoutContentUsingModifiedBase64() {
        request.HTTPMethod = "DELETE"
        let requestEncoder = EDRequestEncoder(apiKey: apiKey, secretKey: secretKey, useModifiedBase64ForURL: true)
        requestEncoder.addAPIKey(request)
        
        if let signature = requestEncoder.generateSignature(request, timestamp: timestamp) {
            XCTAssert(signature == "FuhJ1-z2ADybhLWiqf_uV0yylMa1MPIZg4aPtSfebQ8=", "Unexpected signature.")
        }
        else {
            XCTFail("Signature cannot be nil.")
        }
    }
    
    func testSignatureValidationWithContentUsingModifiedBase64() {
        request.HTTPMethod = "PUT"
        request.HTTPBody = try? NSJSONSerialization.dataWithJSONObject(["action": "read"], options: .PrettyPrinted)
        
        let requestEncoder = EDRequestEncoder(apiKey: apiKey, secretKey: secretKey, useModifiedBase64ForURL: true)
        requestEncoder.addAPIKey(request)
        
        if let signature = requestEncoder.generateSignature(request, timestamp: timestamp) {
            XCTAssert(signature == "ZZJr1SburNfavQj0QDvvqkbKksZFhrJ7xSbKH5peIbg=", "Unexpected signature.")
        }
        else {
            XCTFail("Signature cannot be nil.")
        }
    }
}
