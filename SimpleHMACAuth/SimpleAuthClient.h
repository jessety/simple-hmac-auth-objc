//
//  SimpleAuthClient.h
//  Simple HMAC Auth
//
//  Created by Jesse T Youngblood on 6/26/15.
//

#import <Foundation/Foundation.h>

@interface SimpleAuthClient : NSObject

@property NSString * _Nonnull apiKey;
@property NSString * _Nullable secret;
@property NSMutableDictionary * _Nonnull settings;

- (void)call:(nonnull NSString*)method path:(nonnull NSString*)path query:(nullable NSDictionary*)query body:(nullable NSDictionary*)body completion:(nonnull void (^)(id _Nullable response, NSError *  _Nullable error))completion;

// Returns a client object. Requests are sent unsigned if a secret is not specified.
- (nonnull SimpleAuthClient*)initWithAPIKey:(nonnull NSString*)apiKey;
- (nonnull SimpleAuthClient*)initWithAPIKey:(nonnull NSString*)apiKey secret:(nonnull NSString*)secret;

// If using as a singleton, setting these will ensure the interface method is pre-populated with credentaials.
+ (void)setAPIKey:(nonnull NSString*)apiKey;
+ (void)setAPIKey:(nonnull NSString*)apiKey secret:(nonnull NSString*)secret;

+ (nonnull SimpleAuthClient*)sharedInstance;

@end
