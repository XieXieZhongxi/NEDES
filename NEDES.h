//
//  NEDES.h
//
//  Created by Zhongxi on 2018/8/29.
//  Copyright © 2018 Zhongxi. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NEDES : NSObject

/**
 encrypt,default key
 */
+ (NSString *)encryptWithPlainText:(NSString *)plainText;
/**
 decrypt,default key
 */
+ (NSString *)decryptWithCipherText:(NSString *)cipherText;

/**
 encrypt,custom key
 */
+ (NSString *)encryptWithPlainText:(NSString *)plainText key:(NSString *)key;
/**
 decrypt,custom key
 */
+ (NSString *)decryptWithCipherText:(NSString *)cipherText key:(NSString *)key;
@end
