//
//  SimpleAuthClient.m
//  Simple HMAC Auth
//
//  Created by Jesse T Youngblood on 6/26/15.
//

#import "SimpleAuthClient.h"
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>

@implementation SimpleAuthClient

static NSString *staticAPIKey = nil;
static NSString *staticSecret = nil;
static SimpleAuthClient *sharedInstance = nil;

NSDateFormatter *_dateFormatter;

@synthesize apiKey = _apiKey, secret = _secret, settings = _settings;

+ (void)setAPIKey:(nonnull NSString*)apiKey {
    
    staticAPIKey = apiKey;
    
    @synchronized(self) {
        
        if (sharedInstance) {
            sharedInstance.apiKey = staticAPIKey;
        }
    }
}

+ (void)setSecret:(nonnull NSString *)secret {
    
    staticSecret = secret;
    
    @synchronized(self) {
        
        if (sharedInstance) {
            sharedInstance.secret = secret;
        }
    }
}

+ (void)setAPIKey:(nonnull NSString*)apiKey secret:(nonnull NSString *)secret {
    
    staticAPIKey = apiKey;
    staticSecret = secret;
    
    @synchronized(self) {
        
        if (sharedInstance) {
            sharedInstance.apiKey = apiKey;
            sharedInstance.secret = secret;
        }
    }
}

+ (nonnull SimpleAuthClient*)sharedInstance {
    
    @synchronized(self) {
        
        if (sharedInstance == nil) {
            sharedInstance = [[SimpleAuthClient alloc] init];
        }
        
        if (staticAPIKey) {
            sharedInstance.apiKey = staticAPIKey;
        }
        
        if (staticSecret) {
            sharedInstance.secret = staticSecret;
        }
    }
    
    return sharedInstance;
}

- (id)init {
    
    self = [super init];
    
    if (self) {
        
        // Initialization code here.
        
        self.settings = [[NSMutableDictionary alloc] init];
        
        self.settings[@"host"] = @"localhost";
        self.settings[@"port"] = @443;
        self.settings[@"ssl"] = @true;
        self.settings[@"timeout"] = @45;
        self.settings[@"verbose"] = @false;
        
        // Create a date formatter to create RFC 1123 timestamps for the 'date' header
        _dateFormatter = [[NSDateFormatter alloc] init];
        _dateFormatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"GMT"];
        _dateFormatter.dateFormat = @"EEE',' dd MMM yyyy HH':'mm':'ss 'GMT'";
        _dateFormatter.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US"];
    }
    
    return self;
}

- (nonnull SimpleAuthClient*)initWithAPIKey:(nonnull NSString*)apiKey {
    
    self = [self init];
    
    self.apiKey = apiKey;
    
    return self;
}

- (nonnull SimpleAuthClient*)initWithAPIKey:(nonnull NSString*)apiKey secret:(nonnull NSString*)secret {
    
    self = [self init];
    
    self.apiKey = apiKey;
    self.secret = secret;
    
    return self;
}

- (void)call:(nonnull NSString*)method path:(nonnull NSString*)path query:(nullable NSDictionary*)query body:(nullable NSDictionary*)body completion:(nonnull void (^)(id _Nullable response, NSError *  _Nullable error))completion {
    
    NSDate *now = [NSDate date];
    
    NSString *queryString = @"";
    NSData *bodyData = nil;
    NSMutableDictionary *headers = [[NSMutableDictionary alloc] init];
    
    headers[@"authorization"] = [NSString stringWithFormat:@"api-key %@", self.apiKey];
    headers[@"date"] = [_dateFormatter stringFromDate:now];
    
    // Construct a string from the query dictionary
    
    if (query != nil) {
        
        NSMutableArray *parameterArray = [[NSMutableArray alloc] init];
        
        [query enumerateKeysAndObjectsUsingBlock:^(NSString *key, id object, BOOL *stop) {
            
            NSString *encodedKey = [key stringByAddingPercentEncodingWithAllowedCharacters: [NSCharacterSet URLQueryAllowedCharacterSet]];
            NSString *encodedValue;
            
            
            if ([object isKindOfClass:[NSString class]]) {
                
                encodedValue = [NSString stringWithFormat:@"\"%@\"", encodedValue];
                encodedValue = [(NSString*)object stringByAddingPercentEncodingWithAllowedCharacters: [NSCharacterSet URLQueryAllowedCharacterSet]];
                
            } else if ([object isKindOfClass:[NSNumber class]]) {
                
                encodedValue = [(NSNumber*)object stringValue];
                
            } else {
                
                NSError *jsonWriteError;
                NSData *jsonData;
                
                @try {
                    
                    jsonData = [NSJSONSerialization dataWithJSONObject:object options:kNilOptions error:&jsonWriteError];
                    
                } @catch (NSException *exception) {
                    completion(nil, [NSError errorWithDomain:@"AuthError" code:400 userInfo:@{
                                                                                              @"message": @"Error serializing request JSON", @"exception": exception}
                                     ]);
                    *stop = true;
                    return;
                }
                
                
                if (jsonWriteError) {
                    completion(nil, jsonWriteError);
                    return;
                }
                
                NSString *jsonString = [[NSString alloc] initWithBytes:[jsonData bytes] length:[jsonData length] encoding:NSUTF8StringEncoding];
                encodedValue = [jsonString stringByAddingPercentEncodingWithAllowedCharacters: [NSCharacterSet URLQueryAllowedCharacterSet]];
                
            }
            
            [parameterArray addObject:[NSString stringWithFormat:@"%@=%@", encodedKey, encodedValue]];
        }];
        
        queryString = [parameterArray componentsJoinedByString:@"&"];
    }
    
    // Serialize the body data
    if (body != nil) {
        
        NSError *jsonWriteError;
        
        //Serialize data as JSON
        bodyData = [NSJSONSerialization dataWithJSONObject:body options:kNilOptions error:&jsonWriteError];
        
        if (jsonWriteError) {
            completion(nil, jsonWriteError);
            return;
        }
        
        headers[@"content-type"] = @"application/json";
        headers[@"content-length"] = [NSString stringWithFormat:@"%lu", (unsigned long)[bodyData length]];
    }
    
    // If the user supplied a secret, sign the request
    if (self.secret) {
        
        NSString *signature = [self sign:headers method:method path:path queryString:queryString body:bodyData];
        
        headers[@"signature"] = [NSString stringWithFormat:@"simple-hmac-auth sha256 %@", signature];
    }
    
    [self _send:headers method:method path:path queryString:queryString body:bodyData completion:completion];
}

- (NSString*)sign:(NSDictionary*)headers method:(NSString*)method path:(NSString*)path queryString:(NSString*)queryString body:(NSData*)bodyData {
    
    NSString *canonicalizedRequest = [self _stringForRequest:headers method:method path:path queryString:queryString body:bodyData];
    NSString *signature = [self _hmac:canonicalizedRequest key:self.secret];
    
    return signature;
}

- (NSString*)_stringForRequest:(NSDictionary*)headers method:(NSString*)method path:(NSString*)path queryString:(NSString*)queryString body:(NSData*)bodyData {
    
    method = [method uppercaseString];
    
    if (!queryString) {
        queryString = @"";
    }
    
    
    // Only sign these headers
    NSArray *allowedHeaders = @[
                                @"authorization",
                                @"date",
                                @"content-length",
                                @"content-type"
                                ];
    
    
    NSMutableDictionary *newHeaders = [[NSMutableDictionary alloc] init];
    
    [headers enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        
        key = [key lowercaseString];
        
        if ([allowedHeaders containsObject:key]) {
            newHeaders[key] = value;
        }
    }];
    
    NSMutableString *headerString = [NSMutableString stringWithString:@""];
    
    // Sort the remaining keys
    NSArray *sortedKeys = [[newHeaders allKeys] sortedArrayUsingSelector: @selector(compare:)];
    
    for (NSString *key in sortedKeys) {
        
        NSString *value = [newHeaders[key] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        
        [headerString appendFormat:@"%@:%@\n", key, value];
    }
    
    NSString *dataString = @"";
    
    if (bodyData) {
        dataString = [[NSString alloc] initWithData:bodyData encoding:NSUTF8StringEncoding];
    }
    
    NSString *bodyHash = [self _sha256:dataString];
    
    NSMutableString *string = [NSMutableString stringWithString:@""];
    
    [string appendFormat:@"%@\n", method];
    [string appendFormat:@"%@\n", path];
    [string appendFormat:@"%@\n", queryString];
    [string appendString:headerString];
    [string appendString:bodyHash];
    
    return string;
}

- (NSString*)_sha256:(NSString*)input {
    
    const char* inputChar = [input UTF8String];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    
    CC_SHA256(inputChar, (CC_LONG)strlen(inputChar), result);
    
    NSMutableString *string = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        
        [string appendFormat:@"%02x",result[i]];
    }
    
    return string;
}

- (NSString*)_hmac:(NSString*)data key:(NSString*)key {
    
    const char *cKey  = [key cStringUsingEncoding:NSUTF8StringEncoding];
    const char *cData = [data cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    
    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
    
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", cHMAC[i]];
    }
    
    return output;
}

- (void)_send:(NSDictionary*)headers method:(NSString*)method path:(NSString*)path queryString:(NSString*)queryString body:(NSData*)bodyData completion:(void (^)(id response, NSError *error))completion {
    
    NSString *protocol = @"https";
    
    if ([self.settings[@"host"] boolValue] == NO) {
        protocol = @"http";
    }
    
    NSString *url = [NSString stringWithFormat:@"%@://%@:%@%@", protocol, self.settings[@"host"], self.settings[@"port"], path];
    
    if (queryString && ![queryString isEqualToString:@""]) {
        url = [url stringByAppendingFormat:@"?%@", queryString];
    }
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    
    [request setTimeoutInterval:(NSTimeInterval)[self.settings[@"timeout"] doubleValue]];
    
    [headers enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        
        [request setValue:value forHTTPHeaderField:key];
    }];
    
    [request setHTTPMethod:method];
    
    if (bodyData) {
        [request setHTTPBody:bodyData];
    }
    
    if ([self.settings[@"verbose"] boolValue] == true) {
        
        NSMutableString *log = [NSMutableString stringWithFormat:@"%@ %@", method, url];
        
        if (bodyData) {
            NSString *dataString = [[NSString alloc] initWithData:bodyData encoding:NSUTF8StringEncoding];
            [log appendFormat:@" %@", dataString];
        }
        
        /*
         [log appendString:@" [ "];
         
         [headers enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
         
         [log appendFormat:@"%@: '%@'", key, value];
         
         [log appendString:@" "];
         }];
         
         [log appendString:@"] "];
         */
        
        NSLog(@"AuthClient: %@", log);
    }
    
    
    NSURLSession *session = [NSURLSession sharedSession];
    
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        
        
        if (error) {
            completion(nil, error);
            return;
        }
        
        // Get HTTP status code
        
        NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
        NSInteger statusCode = httpResponse.statusCode;
        
        if (statusCode == 404) {
            NSError *error = [NSError errorWithDomain:@"AuthError" code:404 userInfo:@{}];
            completion(nil, error);
            return;
        }
        
        
        NSError *jsonError = nil;
        id responseObject = [NSJSONSerialization JSONObjectWithData:data options:kNilOptions error:&jsonError];
        
        
        // The status code is either 200, or something that returned an error
        
        if (statusCode != 200) {
            
            if (!jsonError) {
                NSDictionary *responseDictionary = (NSDictionary*)responseObject;
                
                if (responseDictionary[@"error"]) {
                    completion(nil, [NSError errorWithDomain:@"AuthError" code:statusCode userInfo:responseDictionary[@"error"]]);
                } else {
                    completion(nil, [NSError errorWithDomain:@"AuthError" code:statusCode userInfo:responseDictionary]);
                }
            } else {
                completion(nil, jsonError);
            }
            
            return;
        }
        
        completion(responseObject, nil);
        
    }];
    
    [task resume];
}

@end
