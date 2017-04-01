//
//  ZRCryptographyOC
//  A set of cryptographic methods which provides an easily way to call. It includes RSA,AES,DES,MD5,SHA1,SHA224,SHA384,SHA512 algorithms.
//
//  https://github.com/VictorZhang2014/ZRCryptographyOC
//
//  Created by VictorZhang on 31/03/2017.
//  Copyright © 2017 Victor Studio. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ZRCryptographyOC : NSObject

/***** RSA Cryptography *****/
- (void)loadPublicKeyFromFile:(NSString *)derFilePath;
- (void)loadPublicKeyFromData:(NSData *)derData;

- (void)loadPrivateKeyFromFile:(NSString *)p12FilePath password:(NSString*)p12Password;
- (void)loadPrivateKeyFromData:(NSData *)p12Data password:(NSString *)p12Password;


- (NSString *)rsaEncryptString:(NSString *)string;
- (NSData *)rsaEncryptData:(NSData *)data ;

- (NSString *) rsaDecryptString:(NSString *)string;
- (NSData *)rsaDecryptData:(NSData *)data;

- (BOOL)rsaSHA1VerifyData:(NSData *)plainData
            withSignature:(NSData *)signature;



/***** AES Cryptography *****/
- (NSString *)AES256Encrypt:(NSString *)key unencryptedStr:(NSString *)unencryptedStr;
- (NSString *)AES256Decrypt:(NSString *)key undecryptedStr:(NSString *)undecryptedStr;



/***** DES Cryptography *****/
- (NSString *)DESEncrypt:(NSString *)key unencryptedStr:(NSString *)unencryptedStr;
- (NSString *)DESDecrypt:(NSString *)key undecryptedStr:(NSString *)undecryptedStr;



/***** MD5 Cryptography *****/
- (NSString *)MD5:(NSString *)plainText;



/***** SHA serials Cryptography *****/
- (NSString *)SHA1:(NSString *)plainText;
- (NSString *)SHA224:(NSString *)plainText;
- (NSString *)SHA256:(NSString *)plainText;
- (NSString *)SHA384:(NSString *)plainText;
- (NSString *)SHA512:(NSString *)plainText;


@end
