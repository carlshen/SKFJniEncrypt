
#ifndef SKF_APDU_H
#define SKF_APDU_H

#include "SKF_TypeDef.h"

//CA环境FID
BYTE APDU_CA_FID[2];
BYTE APDU_MF_FID[2];
BYTE APDU_EF01_FID[2];
BYTE APDU_EF02_FID[2];
//设备管理


//访问控制
//验证PIN码，0x05，包括管理员PIN和用户PIN
BYTE apdu_verifyPIN[0x05];
//解锁PIN，0x05，在管理员验证后对用户PIN进行解锁
BYTE apdu_unblockPIN[0x05];
//修改PIN码，0x05，包括管理员PIN和用户PIN
BYTE apdu_changePIN[0x05];
//重装PIN，0x05，包括管理员PIN和用户PIN
BYTE apdu_reloadPIN[0x05];
//重装PIN时计算MAC的初始值，x08
BYTE reload_initV[0x08];
//重装PIN时计算MAC的密钥，0x08
BYTE reload_key[0x10];

//应用管理
//设备， 0x10
BYTE apdu_deviceKey[0x10];
//验证TK，0x0D
BYTE apdu_verifyTK[0x40];
//传输密钥，0x10，创建MF时使用
BYTE apdu_TK[0x10];
//选择MF，0x07
BYTE apdu_selectMF[0x07];
//选择DF，0x07
BYTE apdu_selectDF[0x07];
//创建MF，0x21
BYTE apdu_createMF[0x21];
//创建DF，0x21
BYTE apdu_createDF[0x21];
//随机数，0x05
BYTE apdu_random[0x05];
//外部认证，0x0D
BYTE apdu_externalAuth[0x05] ;
//删除MF，0x07
BYTE apdu_deleteMF[0x07];
//外部认证密钥，0x10，删除MF时使用
BYTE apdu_TK2[0x10];

//创建KEY文件，0x19
BYTE apdu_createKey[0x19];
//KEYMK密钥，0x10
BYTE apdu_KEYMK[0x10];
//DAMK密钥，0x10
BYTE apdu_DAMK[0x10];
//DCCK密钥，0x10
BYTE apdu_DCCK[0x10];
//DUPK密钥，0x10
BYTE apdu_DUPK[0x10];
//更新KEY文件，0x1C
BYTE apdu_writeKey[0x1C];
//KEYMK密钥，0x10
BYTE apdu_KEY_KEYMK[0x17];
//DAMK密钥，0x10
BYTE apdu_KEY_DAMK[0x17];
//DCCK密钥，0x10
BYTE apdu_KEY_DCCK[0x17];
//创建MF结束
BYTE apdu_createDFEnd[0x05];
//删除DF
BYTE apdu_deleteDF[0x05];

//文件管理
//创建二进制，0x19
BYTE apdu_createBinary[0x19];
//更新二进制文件
BYTE apdu_updateBinary[0x05];
//读二进制文件
BYTE apdu_readBinary[0x05];

//容器管理

//密码服务
//随机数，0x05
BYTE apdu_random2[5];
//获取响应，0x05
BYTE apdu_getResponse[5];

//ECC签名密钥对
BYTE apdu_eccGenKeyPair[0x05];
BYTE apdu_eccSignData[0x05];
BYTE apdu_eccSignVerify[0x05];
BYTE apdu_eccEncrypt[0x05];
BYTE apdu_eccDecrypt[0x05];
//
BYTE apdu_personalization[0x05];

//SM1，加密，ECB模式，0x05
BYTE apdu_encrypt_sm1_ecb[0x05];
//SM1，解密，ECB模式，0x05
BYTE apdu_decrypt_sm1_ecb[0x05];
//SM1，加密，CBC模式，0x05
BYTE apdu_encrypt_sm1_cbc[0x05];
//SM1，解密，CBC模式，0x05
BYTE apdu_decrypt_sm1_cbc[0x05];
//SM1，加密，CFB模式，0x05
BYTE apdu_encrypt_sm1_cfb[0x05];
//SM1，解密，CFB模式，0x05
BYTE apdu_decrypt_sm1_cfb[0x05];
//SM1，加密，OFB模式，0x05
BYTE apdu_encrypt_sm1_ofb[0x05];
//SM1，解密，OFB模式，0x05
BYTE apdu_decrypt_sm1_ofb[0x05];

//SSF33，加密，ECB模式，0x05
BYTE apdu_encrypt_ssf33_ecb[0x05];
//SSF33，解密，ECB模式，0x05
BYTE apdu_decrypt_ssf33_ecb[0x05];
//SSF33，加密，CBC模式，0x05
BYTE apdu_encrypt_ssf33_cbc[0x05];
//SSF33，解密，CBC模式，0x05
BYTE apdu_decrypt_ssf33_cbc[0x05];
//SSF33，加密，CFB模式，0x05
BYTE apdu_encrypt_ssf33_cfb[0x05];
//SSF33，解密，CFB模式，0x05
BYTE apdu_decrypt_ssf33_cfb[0x05];
//SSF33，加密，OFB模式，0x05
BYTE apdu_encrypt_ssf33_ofb[0x05];
//SSF33，解密，OFB模式，0x05
BYTE apdu_decrypt_ssf33_ofb[0x05];

//SM4，加密，ECB模式，0x05
BYTE apdu_encrypt_sm4_ecb[0x05];
//SM4，解密，ECB模式，0x05
BYTE apdu_decrypt_sm4_ecb[0x05];
//SM4，加密，CBC模式，0x05
BYTE apdu_encrypt_sm4_cbc[0x05];
//SM4，解密，CBC模式，0x05
BYTE apdu_decrypt_sm4_cbc[0x05];
//SM4，加密，CFB模式，0x05
BYTE apdu_encrypt_sm4_cfb[0x05];
//SM4，解密，CFB模式，0x05
BYTE apdu_decrypt_sm4_cfb[0x05];
//SM4，加密，OFB模式，0x05
BYTE apdu_encrypt_sm4_ofb[0x05];
//SM4，解密，OFB模式，0x05
BYTE apdu_decrypt_sm4_ofb[0x05];

//分组算法SM1，SSF33和SM4等CBC模式使用，0x05
BYTE apdu_cbc_sendIV[0x05];
//SM3杂凑
BYTE apdu_sm3_digest[0x05];

//导入SM2签名密钥对
BYTE apdu_import_sm2_keypair[0x05];
//点乘加运算
BYTE apdu_point_multadd[0x05];
//模乘加运算
BYTE apdu_mod_multadd[0x05];

#endif //SKF_APDU_H
