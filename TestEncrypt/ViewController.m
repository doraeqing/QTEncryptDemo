//
//  ViewController.m
//  TestEncrypt
//
//  Created by lu9869 on 2017/10/30.
//  Copyright © 2017年 com.bilibili. All rights reserved.
//

#import "ViewController.h"
#import "NSString+YYAdd.h"
#import "NSData+YYAdd.h"

#define TestSalt @"fdsfsfdsfsdfdsfdsf64654123"
#define TestAESKey @"32BytesLengthKey32BytesLengthKey"
#define kRSA_KEY_SIZE 1024

@interface ViewController ()

@end

@implementation ViewController {
    SecKeyRef _RASPublicKeyRef;     //RSA公钥
    SecKeyRef _RSAPrivateKeyRef;    //RSA私钥
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [self generateRSAKeyPair:kRSA_KEY_SIZE];
    [self RSA];
    [self MD5];
    [self AES];
    NSString *srrrrr = [NSString stringWithFormat:@"%@",@"http:\\\\\\/\\\\\\/upos-hz-mirrorks3.acgvideo.com\\\\\\/dspxcode\\\\\\/g17112311792l66fj0nh2eur5egziggd-1-56.mp4?um_deadline=1511430755&rate=500000&oi=2886868239&um_sign=550a5c1b19f32572b4a84cb570a25df3&gen=dsp&wsTime=1511430755&platform=html5&uuid=5a1670331afd0"];
    srrrrr =  [srrrrr stringByURLDecode];
    NSString *ssssssss = [@"http://upos-hz-mirrorks3.acgvideo.com/dspxcode/g17112311792l66fj0nh2eur5egziggd-1-56.mp4?um_deadline=1511430755&rate=500000&oi=2886868239&um_sign=550a5c1b19f32572b4a84cb570a25df3&gen=dsp&wsTime=1511430755&platform=html5&uuid=5a1670331afd0" stringByURLDecode];
}

#pragma mark -
- (void)RSA {
    
    /** 三种填充方式区别
     kSecPaddingNone      = 0,   要加密的数据块大小<＝SecKeyGetBlockSize的大小，如这里128
     kSecPaddingPKCS1     = 1,   要加密的数据块大小<=128-11
     kSecPaddingOAEP      = 2,   要加密的数据块大小<=128-42
     */
    NSData *originData = [@"123456789" dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"RSA加密前的数据dec==%@", originData);
    
    // 公钥加密
    uint8_t encData[kRSA_KEY_SIZE/8] = {0};
    size_t blockSize = kRSA_KEY_SIZE / 8 ;
    OSStatus ret = SecKeyEncrypt(_RASPublicKeyRef, kSecPaddingNone, originData.bytes, originData.length, encData, &blockSize);
    NSAssert(ret==errSecSuccess, @"RSA加密失败");
    
    //私钥解密
    uint8_t decData[kRSA_KEY_SIZE/8] = {0};
    ret = SecKeyDecrypt(_RSAPrivateKeyRef, kSecPaddingNone, encData, blockSize, decData, &blockSize);
    NSAssert(ret==errSecSuccess, @"解密失败");
    
    NSData *decEndData = [NSData dataWithBytes:decData length:blockSize];
    NSString *decStr = [[NSString alloc] initWithData:decEndData encoding:NSUTF8StringEncoding];
    NSLog(@"RSA解密后的Data, dec==%@", decEndData);
    NSLog(@"RSA解密后的Str, dec==%@", decStr);
    
    if (memcmp(originData.bytes, decEndData.bytes, originData.length)==0) {
        NSLog(@"PASS");
    }
}

- (void)AES {
    NSData *contentData = [@"123" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [TestAESKey dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"==============开始AES加密==================");
    NSData *encryptedData = [contentData aes256EncryptWithKey:keyData iv:nil];
    NSString *encryptStr = [encryptedData base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
    NSLog(@"AES加密后的数据：%@",encryptStr);
    NSLog(@"==============AES加密结束==================\n");
    
    NSLog(@"==============开始AES解密==================");
    NSData *decryptedData = [encryptedData aes256DecryptWithkey:keyData iv:nil];
    NSString *decryptStr = [decryptedData utf8String];
    NSLog(@"AES解密后的数据：%@",decryptStr);
    NSLog(@"==============AES解密结束==================");
}

#pragma mark - MD5
- (void)MD5 {
    NSLog(@"================MD5================");
    [self digest:@"123"];
    [self digest2:@"123"];
    [self digest3:@"123"];
    [self digest4:@"123"];
    NSLog(@"================MD5================\n");
}

// 直接加密，去MD5解密网站即可破解
- (NSString *)digest:(NSString *)str {
    NSString *anwen = [str md5String];
    NSLog(@"直接加密\n%@ - %@", str, anwen);
    return anwen;
}

// 先加盐，后加密，通过MD5解密之后，很容易发现规律
- (NSString *)digest2:(NSString *)str {
    str = [str stringByAppendingString:TestSalt];
    NSString *anwen = [str md5String];
    NSLog(@"加盐\n%@ - %@", str, anwen);
    return anwen;
}

// 多次MD5，使用MD5解密之后，发现还是密文，那就接着MD5解密
- (NSString *)digest3:(NSString *)str {
    NSString *anwen = [str md5String];
    anwen = [anwen md5String];
    NSLog(@"多次MD5\n%@ - %@", str, anwen);
    return anwen;
}

// 先加密，后乱序，破解难度增加（推荐）
- (NSString *)digest4:(NSString *)str {
    NSString *anwen = [str md5String];
    
    // 注册: 123 ---- 2CB962AC59075B964B07152D234B7020
    // 登录: 123 --- 202CB962AC59075B964B07152D234B70
    
    NSString *header = [anwen substringToIndex:2];
    NSString *footer = [anwen substringFromIndex:2];
    anwen = [footer stringByAppendingString:header];
    NSLog(@"先加密，后乱序\n%@ - %@", str, anwen);
    return anwen;
}

#pragma mark - 动态密码
- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    [super touchesBegan:touches withEvent:event];
    NSString *password = [self md5hmacWithPassword:@"123"];
    NSString *URLStr = [NSString stringWithFormat:@"http://localhost/login/loginhmac.php?username=%@&password=%@",@"123",password];
    [[NSURLSession sharedSession] dataTaskWithURL:[NSURL URLWithString:URLStr] completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        NSLog(@"%@",[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
    }];
}

- (NSString *)md5hmacWithPassword:(NSString *)password {
    // 1、私钥
    static NSString *hmacKey = @"dhfhkl54564f5d4sasf4a5d4a";
    
    // 2、对密码和私钥进行第一次加密
    password =  [password hmacMD5StringWithKey:hmacKey];
    
    // 3、取出当前的时间,将当前时间拼接在第一次机密的密码后面
    NSDate *date = [NSDate date];
    
    // 对当前时间做格式化处理.
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"yyyy-MM-dd HH:mm"];
    NSString *timer = [formatter stringFromDate:date];
    
    //4、 第一次加密之后的密码拼接当前时间
    password = [password stringByAppendingString:timer];
    
    //5、 对增加了时间戳的字符串进行 hmac 运算.
    password = [password hmacMD5StringWithKey:hmacKey];
    return password;
}

#pragma mark - tool

// 加密长度是指理论上最大允许”被加密的信息“长度的限制，也就是明文的长度限制。随着这个参数的增大（比方说2048），允许的明文长度也会增加，但同时也会造成计算复杂度的极速增长。一般推荐的长度就是1024位（128字节）。
/// 生成RSA密钥对 支持的SIZE有 sizes for RSA keys are: 512, 768, 1024, 2048
- (void)generateRSAKeyPair:(int)size {
    _RASPublicKeyRef = NULL;
    _RSAPrivateKeyRef = NULL;
    CFDictionaryRef dicRef = (CFDictionaryRef)CFBridgingRetain(@{
                                                                 (id)kSecAttrKeyType : (id)kSecAttrKeyTypeRSA,
                                                                 (id)kSecAttrKeySizeInBits : @(size),
                                                                 (id)kSecAttrIsPermanent : @(YES) //持久化属性(是否存储到keychain)
                                                                 });
    OSStatus ret = SecKeyGeneratePair(dicRef, &_RASPublicKeyRef, &_RSAPrivateKeyRef);
    NSAssert(ret == errSecSuccess, @"密钥对生成失败:%d", ret);

    NSLog(@"publicKeyRef-------%@", _RASPublicKeyRef);
    NSLog(@"privateKeyRef-------%@", _RSAPrivateKeyRef);
    NSLog(@"max size:%lu", SecKeyGetBlockSize(_RSAPrivateKeyRef));
}

@end
