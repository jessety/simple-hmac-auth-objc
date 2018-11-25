//
//  ViewController.swift
//  SimpleHMACAuthExample-Swift
//
//  Created by Jesse T Youngblood on 11/25/18.
//  Copyright © 2018 Jesse T Youngblood. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let client = SimpleAuthClient(apiKey: "API_KEY", secret: "SECRET")
        
        client.settings.setValue(true, forKey: "verbose")
        client.settings.setValue("localhost", forKey: "host")
        client.settings.setValue(8000, forKey: "port");
        
        client.call("GET", path: "/items/", query: nil, body: nil) { (response, error) in
            
            guard error == nil else {
                
                print("Error:", error!)
                
                return
            }
            
            print("Request succeeded")
            print("\(response!)")
        }
    }
}
