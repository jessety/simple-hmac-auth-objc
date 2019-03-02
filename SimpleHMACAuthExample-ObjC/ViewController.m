//
//  ViewController.m
//  SimpleHMACAuthExample
//
//  Created by Jesse T Youngblood on 11/25/18.
//  Copyright © 2018 Jesse T Youngblood. All rights reserved.
//

#import "ViewController.h"

#include <SimpleHMACAuth/SimpleAuthClient.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    NSLog(@"Hello, world!");
    
    SimpleAuthClient *client = [[SimpleAuthClient alloc] initWithAPIKey:@"API_KEY" secret:@"SECRET"];
    
    [client.settings setValue:@true forKey: @"verbose"];
    [client.settings setValue:@"localhost" forKey: @"host"];
    [client.settings setValue:@8000 forKey: @"port"];
    
    [client call:@"GET" path:@"/items/" query:nil body:nil completion:^(id  _Nullable response, NSError * _Nullable error) {
        
        if (error) {
            
            NSLog(@"Error: %@", error);
            return;
        }
        
        NSLog(@"Request Succeeded");
        NSLog(@"Response: %@", response);
    }];
    
}


@end
