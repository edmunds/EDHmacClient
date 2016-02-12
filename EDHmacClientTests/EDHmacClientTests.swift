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
    
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testSignatureValidationWithoutContentUsingModifiedBase64() {
        let apiKey = "4424pfbGmD4PMSkE4MN8c3lM0UeSAXVe894E7462AEF624B732DDBAFB5AC78pQlEIS1s8H9q5IpKegKE051x7vEMZ9Ht+H15jE3ae4fM2Ma33TFqO52BeHY1fDiZY5zmO74ycX8"
        let secretKey = "A53G5Qswm1CnF23Jf2JM0aG98323nB0AgrNlGBI3vW2hNKTR6Pnn5G5Ww3vRXw=="
        let request = NSMutableURLRequest(URL: NSURL(string: "http://www.edmunds.com/api/testMethod")!)
        request.HTTPMethod = "DELETE"
        let timestamp = "2016-02-02T00:09:22Z"
        let requestEncoder = EDRequestEncoder(apiKey: apiKey, secretKey: secretKey, useModifiedBase64ForURL: true)
        requestEncoder.addAPIKey(request)
        
        if let signature = requestEncoder.generateSignature(request, timestamp: timestamp) {
            XCTAssert(signature == "FuhJ1-z2ADybhLWiqf_uV0yylMa1MPIZg4aPtSfebQ8=", "Unexpected signature.")
        }
        else {
            XCTFail("Signature cannot be nil.")
        }
    }
}
