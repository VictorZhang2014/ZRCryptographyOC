//
//  main.m
//  ZRCryptographyOC
//
//  Created by VictorZhang on 31/03/2017.
//  Copyright © 2017 Victor Studio. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ZRCryptographyOC.h"

//RSA Cryptography
void TestRSACryptography();

//AES
void TestAESCryptography();

//DES
void TestDESCryptography();

//MD5
void TestMD5();

//SHA1,SHA224,SHA256,SHA384,SHA512
void TestSHAAlgorithm();


int main(int argc, const char * argv[]) {
    
//    void TestRSACryptography();
    
//    TestAESCryptography();
    
//    TestDESCryptography();
    
//    TestMD5();
    
    TestSHAAlgorithm();
    
    return 0;
}




/**************** START    ----      RSA Cryptography  ****************/
NSString * EncryptoString(NSString *inputStr)
{
    ZRCryptographyOC *rsa = [[ZRCryptographyOC alloc] init];
    
    //Load your public Key file
    [rsa loadPublicKeyFromFile:@"/Users/VictorZhang/Desktop/RSA/public_key.der"];
    
    //encrypt
    return [rsa rsaEncryptString:inputStr];
}

NSString *DecryptoString(NSString *secureText)
{
    ZRCryptographyOC *rsa = [[ZRCryptographyOC alloc] init];
    
    //Load your private key file
    [rsa loadPrivateKeyFromFile:@"/Users/VictorZhang/Desktop/RSA/private_key.p12" password:@"123456"];
    
    //decrypt
    return [rsa rsaDecryptString:secureText];
}

void TestRSACryptography()
{
    NSLog(@"\n\n\n\n\n");
    
    //1.Encrypt String
    NSString *hello = @"RSA is an algorithm used by modern computers to encrypt and decrypt messages. It is an asymmetric cryptographic algorithm. Asymmetric means that there are two different keys. This is also called public key cryptography, because one of them can be given to everyone. The other key must be kept private. It is based on the fact that finding the factors of an integer is hard (the factoring problem). RSA stands for Ron Rivest, Adi Shamir and Leonard Adleman, who first publicly described it in 1978. A user of RSA creates and then publishes the product of two large prime numbers, along with an auxiliary value, as their public key. The prime factors must be kept secret. Anyone can use the public key to encrypt a message, but with currently published methods, if the public key is large enough, only someone with knowledge of the prime factors can feasibly decode the message.";
    
    NSString *secureHello = EncryptoString(hello);
    NSLog(@"Cipher Data : %@ \n", secureHello);
    
    //2.Decrypt String
    NSString *decryptStr = DecryptoString(secureHello);
    NSLog(@"Decrypted Data: %@", decryptStr);
}
/**************** END    ----      RSA Cryptography  ****************/






/**************** START    ----      AES Cryptography  ****************/
void TestAESCryptography()
{
    NSLog(@"\n\n\n\n\n");
    
    NSString * key = @"This is key!";
    
    NSString * unencryptedStr = @"Hello, world! I am an AES Cryptography, if you wanna use it to your project, it's very easy !";
    
    ZRCryptographyOC *aes = [[ZRCryptographyOC alloc] init];
    NSString *encryptedData = [aes AES256Encrypt:key unencryptedStr:unencryptedStr];
    NSLog(@"encryptedData = %@", encryptedData);
    
    
    NSString *plainText = [aes AES256Decrypt:key undecryptedStr:encryptedData];
    NSLog(@"plainText = %@", plainText);
}
/**************** END    ----      AES Cryptography  ****************/






/**************** START    ----    DES Cryptography  ****************/
void TestDESCryptography()
{
    NSLog(@"\n\n\n\n\n");
    
    NSString * key = @"This is DES key!";
    
    NSString * unencryptedStr = @"Hello, world! I am an DES Cryptography, if you wanna use it to your project, it's very easy !";
    
    ZRCryptographyOC *des = [[ZRCryptographyOC alloc] init];
    NSString *encryptedData = [des DESEncrypt:key unencryptedStr:unencryptedStr];
    NSLog(@"encryptedData = %@", encryptedData);
    
    
    NSString *plainText = [des DESDecrypt:key undecryptedStr:encryptedData];
    NSLog(@"plainText = %@", plainText);
}
/**************** END    ----      DES Cryptography  ****************/






/**************** START    ----    MD5 Cryptography  ****************/
void TestMD5()
{
    NSLog(@"\n\n\n\n\n");
    
    NSString * unencryptedStr = @"Hello, world! I am an MD5 Cryptography, if you wanna use it to your project, it's very easy !";
    
    ZRCryptographyOC *md5 = [[ZRCryptographyOC alloc] init];
    NSString *cipherStr = [md5 MD5:unencryptedStr];
    NSLog(@"md5 cipherstr = %@", cipherStr);
}
/**************** END    ----      MD5 Cryptography  ****************/






/**************** START    ----    SHA1,SHA224,SHA256,SHA384,SHA512 Cryptography  ****************/
void TestSHAAlgorithm()
{
    NSString * unencryptedStr = @"Hello, world! I am an SHA Serials Algorithms Cryptography, if you wanna use it to your project, it's very easy !";
    
    ZRCryptographyOC *crypto = [[ZRCryptographyOC alloc] init];
    NSString *SHA1 = [crypto SHA1:unencryptedStr];
    NSString *SHA224 = [crypto SHA224:unencryptedStr];
    NSString *SHA256 = [crypto SHA256:unencryptedStr];
    NSString *SHA384 = [crypto SHA384:unencryptedStr];
    NSString *SHA512 = [crypto SHA512:unencryptedStr];
    
    
    NSLog(@" \n SHA1=%@ \n SHA224=%@ \n SHA256=%@ \n SHA384=%@ \n SHA512=%@", SHA1, SHA224, SHA256, SHA384, SHA512);
    
}
/**************** END    ----      SHA1,SHA224,SHA256,SHA384,SHA512 Cryptography  ****************/
