# ZRCryptographyOC
ZRCryptographyOC, a set of cryptographic methods which provides an easily way to call. It includes RSA,AES,DES,MD5,SHA1,SHA224,SHA384,SHA512 algorithms.

[![Version](https://img.shields.io/cocoapods/v/ZRCryptographyOC.svg?style=flat)](http://cocoapods.org/pods/ZRCryptographyOC)
[![License](https://img.shields.io/cocoapods/l/ZRCryptographyOC.svg?style=flat)](http://cocoapods.org/pods/ZRCryptographyOC)
[![Platform](https://img.shields.io/cocoapods/p/ZRCryptographyOC.svg?style=flat)](http://cocoapods.org/pods/ZRCryptographyOC)

## How to get started?
-----------------------------------
- [Download ZRCryptographyOC](https://github.com/VictorZhang2014/ZRCryptographyOC) try the example app out

## Installation
-----------------------------------
[CocoaPods](http://cocoapods.org) is a dependency manager for Objective-C , which anutomates and simplifies the process of using 3rd-party libraries like ZRCryptographyOC in you projects.

```bash
$ gem install cocoapods
```

#### podfile
To integrate ZRCryptographyOC into your Xcode project using Cocoapods, specify it in your `Podfile`:

```ruby
platform :ios, '7.0'

target 'Your project Name' do
  pod 'ZRCryptographyOC' , '~>1.1.2'

end
```
Then, run the following command:

```bash
$ pod install
```


## Usage
----------------------------------
First of all, your must import the header file of `#import <ZRCryptographyOC/ZRCryptographyOC.h>`

#### RSA encrypt and decrypt
```
NSString * EncryptoString(NSString *inputStr)
{
    ZRCryptographyOC *rsa = [[ZRCryptographyOC alloc] init];
    
    //Load your public Key file
    [rsa loadPublicKeyFromFile:@"/Your bundle path/public_key.der"];
    
    //encrypt
    return [rsa rsaEncryptString:inputStr];
}

NSString *DecryptoString(NSString *secureText)
{
    ZRCryptographyOC *rsa = [[ZRCryptographyOC alloc] init];
    
    //Load your private key file
    [rsa loadPrivateKeyFromFile:@"/Your bundle path/private_key.p12" password:@"123456"];
    
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
```


#### AES encrypt and decrypt
```
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
```


#### DES encrypt and decrypt
```
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
```


#### MD5 encrypt and decrypt
```
void TestMD5()
{
    NSLog(@"\n\n\n\n\n");
    
    NSString * unencryptedStr = @"Hello, world! I am an MD5 Cryptography, if you wanna use it to your project, it's very easy !";
    
    ZRCryptographyOC *md5 = [[ZRCryptographyOC alloc] init];
    NSString *cipherStr = [md5 MD5:unencryptedStr];
    NSLog(@"md5 cipherstr = %@", cipherStr);
}
```


#### SHA serials algorithms encrypt and decrypt
```
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
```

## Licenses
ZRCryptographyOC is licensed under the [MIT License](https://github.com/VictorZhang2014/ZRCryptographyOC/blob/master/LICENSE).
