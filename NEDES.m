//
//  NEDES.m
//
//  Created by Zhongxi on 2018/8/29.
//  Copyright © 2018 Zhongxi. All rights reserved.
//

#import "NEDES.h"
#import <CommonCrypto/CommonCrypto.h>
#define DESKEY @"NEDESENCRYPTKEY"
@implementation NEDES
+(NSString *)encryptWithPlainText:(NSString *)plainText{
    return [self encryptWithPlainText:plainText key:DESKEY];
}

+(NSString *)decryptWithCipherText:(NSString *)cipherText{
    return [self decryptWithCipherText:cipherText key:DESKEY];
}

+(NSString *)encryptWithPlainText:(NSString *)plainText key:(NSString *)key{
    NSData *data = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    Byte iv[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF};
    size_t numBytesEncrypted = 0;
    NSString *DESkey = key;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding,
                                          [DESkey UTF8String], kCCBlockSizeDES,
                                          iv,
                                          [data bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        return [[NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted] base64EncodedStringWithOptions:0];
    }
    
    free(buffer);
    return nil;
}

+(NSString *)decryptWithCipherText:(NSString *)cipherText key:(NSString *)key{
    NSData *cipherData = [[NSData alloc]initWithBase64EncodedString:cipherText options:0];
    NSUInteger dataLength = [cipherData length];
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    Byte iv[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF};
    size_t numBytesDecrypted = 0;
    NSString *DESkey = key;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding,
                                          [DESkey UTF8String], kCCBlockSizeDES,
                                          iv,
                                          [cipherData bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        return [[NSString alloc] initWithData:[NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted] encoding:NSUTF8StringEncoding];
    }
    
    free(buffer);
    return nil;
}
@end
