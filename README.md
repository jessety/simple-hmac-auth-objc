# simple-hmac-auth-ios
iOS framework for interfacing with APIs that implement HMAC signatures. Designed for use with a JSON API that implements [simple-hmac-auth](https://github.com/jessety/simple-hmac-auth).

## Usage

### Swift

```swift
let client = SimpleAuthClient(apiKey: "API_KEY", secret: "SECRET")

client.settings.setValue("localhost", forKey: "host")
client.settings.setValue(8000, forKey: "port");
client.settings.setValue(false, forKey: "ssl");
client.settings.setValue(true, forKey: "verbose")
        
client.call("GET", path: "/items/", query: nil, body: nil) { (response, error) in

  guard error == nil else {
    print("Error:", error!)
    return
  }
  
  print("Request succeeded")
  print("\(response!)")
}
```

### Objective-C

```obj-c
#include <SimpleHMACAuth/SimpleAuthClient.h>

SimpleAuthClient *client = [[SimpleAuthClient alloc] initWithAPIKey:@"API_KEY" secret:@"SECRET"];
    
[client.settings setValue:@"localhost" forKey: @"host"];
[client.settings setValue:@8000 forKey: @"port"];
[client.settings setValue:@false forKey: @"ssl"];
[client.settings setValue:@true forKey: @"verbose"];

[client call:@"GET" path:@"/items/" query:nil body:nil completion:^(id  _Nullable response, NSError * _Nullable error) {

  if (error) {
    NSLog(@"Error:", error);
    return;
  }
  
  NSLog(@"Request Succeeded");
  NSLog(@"%@", response);
}];
```
