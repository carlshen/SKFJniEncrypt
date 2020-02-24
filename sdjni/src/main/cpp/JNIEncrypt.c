#include <jni.h>
#include "logger.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "base64.h"
#include <sys/ptrace.h>
#include <SDSCErr.h>
#include <SDSCDev.h>
#include "SKF_TypeDef.h"
#include "transmit.h"
#include "Global_Def.h"
#include "SKF_ContainerManager.h"
#include "SKF_DeviceManager.h"
#include "SKF_CryptoService.h"

// 获取数组的大小
# define NELEM(x) ((int) (sizeof(x) / sizeof((x)[0])))
// 指定要注册的类，对应完整的java类名
#define JNIREG_CLASS "com/tongxin/sdjni/AESEncrypt"

jstring charToJstring(JNIEnv *envPtr, char *src) {
    JNIEnv env = *envPtr;

    jsize len = strlen(src);
    jclass clsstring = env->FindClass(envPtr, "java/lang/String");
    jstring strencode = env->NewStringUTF(envPtr, "UTF-8");
    jmethodID mid = env->GetMethodID(envPtr, clsstring, "<init>", "([BLjava/lang/String;)V");
    jbyteArray barr = env->NewByteArray(envPtr, len);
    env->SetByteArrayRegion(envPtr, barr, 0, len, (jbyte *) src);

    return (jstring) env->NewObject(envPtr, clsstring, mid, barr, strencode);
}

JNIEXPORT jlong JNICALL set_package(JNIEnv *env, jobject instance, jstring str_) {
    // set package name
    char *pkgname = (char *) (*env)->GetStringUTFChars(env, str_, JNI_FALSE);
    LOGI("set_package package name: %s\n", pkgname);
    // set log path
    memset(SV_PSZLOGPATH, 0x00, SIZE_BUFFER_128);
    memcpy(SV_PSZLOGPATH, pkgname, strlen(pkgname));
    strcat(SV_PSZLOGPATH, "/files/tmc_sdk.log");
    LOGI("set_package log_name: %s\n", SV_PSZLOGPATH);
    unsigned long pkgresult = SDSCSetPackageName(pkgname);
    LOGI("setpackage result: %ld", pkgresult);
    (*env)->ReleaseStringUTFChars(env, str_, pkgname);
    return pkgresult;
}

JNIEXPORT jstring JNICALL get_func_list(JNIEnv *env, jobject instance, jstring str_) {
    char *pkgname = (char *) (*env)->GetStringUTFChars(env, str_, JNI_FALSE);
    LOGI("get_func_list pkgname: %s\n", pkgname);
    memset(SV_PSZLOGPATH, 0x00, SIZE_BUFFER_128);
    memcpy(SV_PSZLOGPATH, pkgname, strlen(pkgname));
    strcat(SV_PSZLOGPATH, "/files/tmc_sdk.log");
    LOGI("set_package log_name: %s\n", SV_PSZLOGPATH);
    char *devInfo = (char *) malloc(SDSC_MAX_DEV_NAME_LEN * sizeof(char));
    if (devInfo == NULL) {
        LOGE("get_dev_info with null alloc.");
        return (*env)->NewStringUTF(env, '\0');
    }
    memset(devInfo, 0x00, SDSC_FIRMWARE_VER_LEN * sizeof(char));
    unsigned long baseResult = SKF_GetFuncList( sv_Device, devInfo );
    LOGI("get_dev_info baseResult: %ld", baseResult);
    jstring  result = charToJstring(env, devInfo);
    // need free the memory
    free(devInfo);
    return result;
}

JNIEXPORT jlong JNICALL import_cert(JNIEnv *env, jobject instance, jint handle) {
    LOGI("import_cert handle: %ld", handle);
    char *pszDrives = (char *) malloc(SDSC_MAX_DEV_NUM * SDSC_MAX_DEV_NAME_LEN * sizeof(char));
    if (pszDrives == NULL) {
        LOGE("import_cert with null alloc.");
        return (*env)->NewStringUTF(env, '\0');
    }
    memset(pszDrives, 0x00, SDSC_MAX_DEV_NUM * SDSC_MAX_DEV_NAME_LEN * sizeof(char));
    unsigned long pulDrivesLen = SDSC_MAX_DEV_NUM * SDSC_MAX_DEV_NAME_LEN * sizeof(char);
    unsigned long baseResult = SKF_ImportCertificate(handle, 1, pszDrives, &pulDrivesLen);
    LOGI("import_cert result: %ld", baseResult);
    return handle;
}

JNIEXPORT jlong JNICALL export_cert(JNIEnv *env, jobject instance, jint handle) {
    LOGI("export_cert handle: %ld", handle);
    char *pszDrives = (char *) malloc(SDSC_MAX_DEV_NUM * SDSC_MAX_DEV_NAME_LEN * sizeof(char));
    if (pszDrives == NULL) {
        LOGE("export_cert with null alloc.");
        return (*env)->NewStringUTF(env, '\0');
    }
    memset(pszDrives, 0x00, SDSC_MAX_DEV_NUM * SDSC_MAX_DEV_NAME_LEN * sizeof(char));
    unsigned long pulDrivesLen = SDSC_MAX_DEV_NUM * SDSC_MAX_DEV_NAME_LEN * sizeof(char);
    unsigned long baseResult = SKF_ExportCertificate(handle, 1, pszDrives, &pulDrivesLen);
    LOGI("export_cert result: %ld", baseResult);
    return handle;
}

JNIEXPORT jstring JNICALL enum_dev(JNIEnv *env, jobject instance) {
    LOGI("enum_dev function.");
    char *pszDrives = (char *) malloc(SDSC_MAX_DEV_NUM * SDSC_MAX_DEV_NAME_LEN * sizeof(char));
    if (pszDrives == NULL) {
        LOGE("EnumDev with null alloc.");
        return (*env)->NewStringUTF(env, '\0');
    }
    memset(pszDrives, 0x00, SDSC_MAX_DEV_NUM * SDSC_MAX_DEV_NAME_LEN * sizeof(char));
    unsigned long pulDrivesLen = SDSC_MAX_DEV_NUM * SDSC_MAX_DEV_NAME_LEN * sizeof(char);
    unsigned long pulDriveNum = 0;
    unsigned long baseResult = SKF_EnumDev(pszDrives, &pulDrivesLen, &pulDriveNum);
    LOGI("EnumDev result: %ld", baseResult);
    LOGI("EnumDev pulDriveNum: %ld", pulDriveNum);
    LOGI("EnumDev pszDrives: %s\n", pszDrives);
    jstring  result = charToJstring(env, pszDrives);
    // need free the memory
    free(pszDrives);
    return result;
}

JNIEXPORT jint JNICALL connect_dev(JNIEnv *env, jobject instance, jstring str_) {
    char *szDrive = (char *) (*env)->GetStringUTFChars(env, str_, JNI_FALSE);
    if (szDrive == NULL) {
        LOGE("connect_dev with null string.");
        return -1;
    }
    LOGI("connect_dev szDrive: %s\n", szDrive);
    int pulDriveNum = 0;
    unsigned long baseResult = SKF_ConnectDev(szDrive, &pulDriveNum);
    LOGI("connect_dev baseResult: %ld", baseResult);
    LOGI("connect_dev pulDriveNum: %d", pulDriveNum);
    sv_Device = pulDriveNum;
    (*env)->ReleaseStringUTFChars(env, str_, szDrive);
    if (baseResult == 0) {
        return pulDriveNum;
    } else {
        return 0;
    }
}

JNIEXPORT jlong JNICALL disconnect_dev(JNIEnv *env, jobject instance, jint handle) {
    LOGI("disconnect_dev handle: %ld", handle);
    unsigned long baseResult = SKF_DisConnectDev(sv_Device);
    LOGI("disconnect_dev baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL gen_random(JNIEnv *env, jobject instance, jint handle) {
    LOGI("gen_random handle: %ld", handle);
    char *pszDrives = (char *) malloc(SDSC_MAX_DEV_NUM * SDSC_MAX_DEV_NAME_LEN * sizeof(char));
    if (pszDrives == NULL) {
        LOGE("gen_random with null alloc.");
        return (*env)->NewStringUTF(env, '\0');
    }
    memset(pszDrives, 0x00, SDSC_MAX_DEV_NUM * SDSC_MAX_DEV_NAME_LEN * sizeof(char));
    unsigned long pulDrivesLen = SDSC_MAX_DEV_NUM * SDSC_MAX_DEV_NAME_LEN * sizeof(char);
    unsigned long baseResult = SKF_GenRandom(handle, pszDrives, &pulDrivesLen);
    LOGI("gen_random baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL gen_ecc_key(JNIEnv *env, jobject instance, jint handle) {
    LOGI("gen_ecc_key handle: %ld", handle);
    ECCPUBLICKEYBLOB pBlob;
    unsigned long baseResult = SKF_GenECCKeyPair( handle, SGD_SM2_1, &pBlob );
    LOGI("gen_ecc_key baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL import_ecc_key(JNIEnv *env, jobject instance, jint handle) {
    LOGI("import_ecc_key handle: %ld", handle);
    PENVELOPEDKEYBLOB pEnvelopedKeyBlob;
    unsigned long baseResult = SKF_ImportECCKeyPair( handle, pEnvelopedKeyBlob );
    LOGI("import_ecc_key baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL ecc_sign_data(JNIEnv *env, jobject instance, jint handle) {
    LOGI("ecc_sign_data handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    PECCSIGNATUREBLOB pSignature;
    unsigned long baseResult = SKF_ECCSignData( handle, pbData, ulDataLen, pSignature );
    LOGI("ecc_sign_data baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL ecc_verify(JNIEnv *env, jobject instance, jint handle) {
    LOGI("ecc_verify handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    ECCPUBLICKEYBLOB pECCPubKeyBlob;
    PECCSIGNATUREBLOB pSignature;
    unsigned long baseResult = SKF_ECCVerify( handle, &pECCPubKeyBlob, pbData, ulDataLen, pSignature );
    LOGI("ecc_verify baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL ext_ecc_verify(JNIEnv *env, jobject instance, jint handle) {
    LOGI("ext_ecc_verify handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    ECCPUBLICKEYBLOB pECCPubKeyBlob;
    PECCSIGNATUREBLOB pSignature;
    unsigned long baseResult = SKF_ExtECCVerify( handle, &pECCPubKeyBlob, pbData, ulDataLen, pSignature );
    LOGI("ext_ecc_verify baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL gen_data_ecc(JNIEnv *env, jobject instance, jint handle) {
    LOGI("gen_data_ecc handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    ECCPUBLICKEYBLOB pECCPubKeyBlob;
    HANDLE* phAgreementHandle;
    unsigned long baseResult = SKF_GenerateAgreementDataWithECC( handle, SGD_SM2_1, &pECCPubKeyBlob,
            pbData, ulDataLen, phAgreementHandle );
    LOGI("gen_data_ecc baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL gen_key_ecc(JNIEnv *env, jobject instance, jint handle) {
    LOGI("gen_key_ecc handle: %ld", handle);
    ULONG ulAlgId;
    ECCPUBLICKEYBLOB pSponsorECCPubKeyBlob;
    ECCPUBLICKEYBLOB pTempECCPubKeyBlob;
    BYTE pbID;
    ULONG ulIDLen;
    HANDLE phKeyHandle;
    unsigned long baseResult = SKF_GenerateKeyWithECC( handle, &pSponsorECCPubKeyBlob,
            &pTempECCPubKeyBlob, &pbID, ulIDLen, &phKeyHandle );
    LOGI("gen_key_ecc baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL gen_data_key_ecc(JNIEnv *env, jobject instance, jint handle) {
    LOGI("gen_data_key_ecc handle: %ld", handle);
    ULONG ulAlgId;
    ECCPUBLICKEYBLOB pSponsorECCPubKeyBlob;
    ECCPUBLICKEYBLOB pSponsorTempECCPubKeyBlob;
    ECCPUBLICKEYBLOB pTempECCPubKeyBlob;
    BYTE pbID;
    ULONG ulIDLen;
    BYTE pbSponsorID;
    ULONG ulSponsorIDLen;
    HANDLE phKeyHandle;
    unsigned long baseResult = SKF_GenerateAgreementDataAndKeyWithECC( handle, ulAlgId, &pSponsorECCPubKeyBlob,
            &pSponsorTempECCPubKeyBlob, &pTempECCPubKeyBlob, &pbID, ulIDLen, &pbSponsorID, ulSponsorIDLen, &phKeyHandle );
    LOGI("gen_data_key_ecc baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL export_public_key(JNIEnv *env, jobject instance, jint handle) {
    LOGI("export_public_key handle: %ld", handle);
    BYTE pbBlob;
    ULONG pulBlobLen;
    unsigned long baseResult = SKF_ExportPublicKey( handle, 1, &pbBlob, &pulBlobLen );
    LOGI("export_public_key baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL import_session_key(JNIEnv *env, jobject instance, jint handle) {
    LOGI("import_session_key handle: %ld", handle);
    BYTE* pbBlob;
    ULONG pulBlobLen;
    HANDLE phKey;
    unsigned long baseResult = SKF_ImportSessionKey( handle, SGD_SM2_1, pbBlob, pulBlobLen, &phKey );
    LOGI("import_session_key baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL set_sym_key(JNIEnv *env, jobject instance, jint handle) {
    LOGI("set_sym_key handle: %ld", handle);
    BYTE* pbBlob;
    HANDLE* phKey;
    unsigned long baseResult = SKF_SetSymmKey( handle, pbBlob, SGD_SM2_1, phKey );
    LOGI("set_sym_key baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL close_handle(JNIEnv *env, jobject instance, jint handle) {
    LOGI("close_handle handle: %ld", handle);
    unsigned long baseResult = SKF_CloseHandle( handle );
    LOGI("close_handle baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jstring JNICALL get_dev_info(JNIEnv *env, jobject instance, jint handle) {
    LOGI("get_dev_info handle: %ld", handle);
    char *devInfo = (char *) malloc(SDSC_MAX_DEV_NAME_LEN * sizeof(char));
    if (devInfo == NULL) {
        LOGE("get_dev_info with null alloc.");
        return (*env)->NewStringUTF(env, '\0');
    }
    memset(devInfo, 0x00, SDSC_FIRMWARE_VER_LEN * sizeof(char));
    unsigned long baseResult = SKF_GetDevInfo( handle, devInfo );
    LOGI("get_dev_info baseResult: %ld", baseResult);
    jstring  result = charToJstring(env, devInfo);
    // need free the memory
    free(devInfo);
    return result;
}

JNIEXPORT jlong JNICALL get_za(JNIEnv *env, jobject instance, jint handle) {
    LOGI("get_za handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    BYTE *pbZAData;
    ULONG pulZALen;
    unsigned long baseResult = SKF_GetZA( handle, pbData, ulDataLen, pbZAData, &pulZALen );
    LOGI("get_za baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL encrypt_init(JNIEnv *env, jobject instance, jint handle) {
    LOGI("encrypt_init handle: %ld", handle);
    BLOCKCIPHERPARAM encryptParam;
    unsigned long baseResult = SKF_EncryptInit( handle, encryptParam );
    LOGI("encrypt_init baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL encrypt(JNIEnv *env, jobject instance, jint handle) {
    LOGI("encrypt handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    BYTE *pbEncryptedData;
    ULONG *pulEncryptedLen;
    unsigned long baseResult = SKF_Encrypt( handle, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen );
    LOGI("encrypt baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL encrypt_update(JNIEnv *env, jobject instance, jint handle) {
    LOGI("encrypt_update handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    BYTE *pbEncryptedData;
    ULONG *pulEncryptedLen;
    unsigned long baseResult = SKF_EncryptUpdate( handle, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen );
    LOGI("encrypt_update baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL encrypt_final(JNIEnv *env, jobject instance, jint handle) {
    LOGI("encrypt_final handle: %ld", handle);
    BYTE *pbEncryptedData;
    ULONG *pulEncryptedLen;
    unsigned long baseResult = SKF_EncryptFinal( handle, pbEncryptedData, pulEncryptedLen );
    LOGI("encrypt_final baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL decrypt_init(JNIEnv *env, jobject instance, jint handle) {
    LOGI("decrypt_init handle: %ld", handle);
    BLOCKCIPHERPARAM encryptParam;
    unsigned long baseResult = SKF_DecryptInit( handle, encryptParam );
    LOGI("decrypt_init baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL decrypt(JNIEnv *env, jobject instance, jint handle) {
    LOGI("decrypt handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    BYTE *pbEncryptedData;
    ULONG *pulEncryptedLen;
    unsigned long baseResult = SKF_Decrypt( handle, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen );
    LOGI("decrypt baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL decrypt_update(JNIEnv *env, jobject instance, jint handle) {
    LOGI("decrypt_update handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    BYTE *pbEncryptedData;
    ULONG *pulEncryptedLen;
    unsigned long baseResult = SKF_DecryptUpdate( handle, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen );
    LOGI("decrypt_update baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL decrypt_final(JNIEnv *env, jobject instance, jint handle) {
    LOGI("decrypt_final handle: %ld", handle);
    BYTE *pbEncryptedData;
    ULONG *pulEncryptedLen;
    unsigned long baseResult = SKF_DecryptFinal( handle, pbEncryptedData, pulEncryptedLen );
    LOGI("decrypt_final baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL digest_init(JNIEnv *env, jobject instance, jint handle) {
    LOGI("digest_init handle: %ld", handle);
    ECCPUBLICKEYBLOB* pPubKey;
    BYTE* pucID;
    ULONG ulIDLen;
    HANDLE *phHash;
    unsigned long baseResult = SKF_DigestInit( handle, SGD_SM2_1, pPubKey, pucID, ulIDLen, phHash );
    LOGI("digest_init baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL digest(JNIEnv *env, jobject instance, jint handle) {
    LOGI("digest handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    BYTE *pbEncryptedData;
    ULONG *pulEncryptedLen;
    unsigned long baseResult = SKF_Digest( handle, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen );
    LOGI("digest baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL digest_update(JNIEnv *env, jobject instance, jint handle) {
    LOGI("digest_update handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    unsigned long baseResult = SKF_DigestUpdate( handle, pbData, ulDataLen );
    LOGI("digest_update baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL digest_final(JNIEnv *env, jobject instance, jint handle) {
    LOGI("digest_final handle: %ld", handle);
    BYTE *pbHashData;
    ULONG *pulHashLen;
    unsigned long baseResult = SKF_DigestFinal( handle, pbHashData, pulHashLen );
    LOGI("digest_final baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL mac_init(JNIEnv *env, jobject instance, jint handle) {
    LOGI("mac_init handle: %ld", handle);
    BLOCKCIPHERPARAM* pMacParam;
    HANDLE *phMac;
    unsigned long baseResult = SKF_MacInit( handle, pMacParam, phMac );
    LOGI("mac_init baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL mac(JNIEnv *env, jobject instance, jint handle) {
    LOGI("mac handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    BYTE *pbEncryptedData;
    ULONG *pulEncryptedLen;
    unsigned long baseResult = SKF_Mac( handle, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen );
    LOGI("mac baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL mac_update(JNIEnv *env, jobject instance, jint handle) {
    LOGI("mac_update handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    unsigned long baseResult = SKF_MacUpdate( handle, pbData, ulDataLen );
    LOGI("mac_update baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL mac_final(JNIEnv *env, jobject instance, jint handle) {
    LOGI("mac_final handle: %ld", handle);
    BYTE *pbHashData;
    ULONG *pulHashLen;
    unsigned long baseResult = SKF_MacFinal( handle, pbHashData, pulHashLen );
    LOGI("mac_final baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL gen_key(JNIEnv *env, jobject instance, jint handle) {
    LOGI("generate_key handle: %ld", handle);
    // need update GenerateKey
    ULONG ulBitsLen;
    RSAPRIVATEKEYBLOB *pBlob;
    unsigned long baseResult = SKF_GenExtRSAKey( handle, ulBitsLen, pBlob );
    LOGI("generate_key baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL ecc_export_session_key(JNIEnv *env, jobject instance, jint handle) {
    LOGI("ecc_export_session_key handle: %ld", handle);
    ECCPUBLICKEYBLOB* pPubKey;
    PECCCIPHERBLOB pData;
    HANDLE* phSessionKey;
    unsigned long baseResult = SKF_ECCExportSessionKey( handle, SGD_SM2_1, pPubKey, pData, phSessionKey );
    LOGI("ecc_export_session_key baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL ecc_prv_key_decrypt(JNIEnv *env, jobject instance, jint handle) {
    LOGI("ecc_prv_key_decrypt handle: %ld", handle);
    // need update ECCPrvKeyDecrypt
    PECCCIPHERBLOB pCipherText;
    BYTE* pbPlainText;
    ULONG* pulPlainTextLen;
    unsigned long baseResult = SKF_ECCPrvKeyDecrypt( handle, pCipherText, pbPlainText, pulPlainTextLen );
    LOGI("ecc_prv_key_decrypt baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL import_key_pair(JNIEnv *env, jobject instance, jint handle) {
    LOGI("import_key_pair handle: %ld", handle);
    PENVELOPEDKEYBLOB pEnvelopedKeyBlob;
    unsigned long baseResult = SKF_ImportECCKeyPair2( handle, pEnvelopedKeyBlob );
    LOGI("import_key_pair baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL cipher(JNIEnv *env, jobject instance, jint handle) {
    LOGI("cipher handle: %ld", handle);
    // need update Cipher
    BYTE *pbData;
    ULONG ulDataLen;
    BYTE *pbSignature;
    ULONG *pulSignLen;
    unsigned long baseResult = SKF_Cipher( handle, pbData, ulDataLen, pbSignature, pulSignLen );
    LOGI("ecc_sign_data baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL begin_transaction(JNIEnv *env, jobject instance, jint handle) {
    unsigned long baseResult = SDSCBeginTransaction(handle);
    LOGI("begin_transaction baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL end_transaction(JNIEnv *env, jobject instance, jint handle) {
    unsigned long baseResult = SDSCEndTransaction(handle);
    LOGI("end_transaction baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jstring JNICALL get_firm_ver(JNIEnv *env, jobject instance, jint handle) {
    char *firmVer = (char *) malloc(SDSC_FIRMWARE_VER_LEN * sizeof(char));
    if (firmVer == NULL) {
        LOGE("get_firm_ver with null alloc.");
        return (*env)->NewStringUTF(env, '\0');
    }
    memset(firmVer, 0x00, SDSC_FIRMWARE_VER_LEN * sizeof(char));
    unsigned long firmLen = SDSC_FIRMWARE_VER_LEN * sizeof(char);
    unsigned long baseResult = SDSCGetFirmwareVer(handle, firmVer, &firmLen);
    LOGI("get_firm_ver baseResult: %ld", baseResult);
    LOGI("get_firm_ver firmLen: %ld", firmLen);
    jstring  result = charToJstring(env, firmVer);
    // need free the memory
    free(firmVer);
    return result;
}

JNIEXPORT jstring JNICALL get_flash_id(JNIEnv *env, jobject instance, jint handle) {
    char *flashId = (char *) malloc(SDSC_FLASH_ID_LEN * sizeof(char));
    if (flashId == NULL) {
        LOGE("get_flash_id with null alloc.");
        return (*env)->NewStringUTF(env, '\0');
    }
    memset(flashId, 0x00, SDSC_FLASH_ID_LEN * sizeof(char));
    unsigned long flashLen = SDSC_FLASH_ID_LEN * sizeof(char);
    unsigned long baseResult = SDSCGetFlashID(handle, flashId, &flashLen);
    LOGI("get_flash_id baseResult: %ld", baseResult);
    LOGI("get_flash_id flashLen: %ld", flashLen);
    jstring  result = charToJstring(env, flashId);
    // need free the memory
    free(flashId);
    return result;
}

// If the calling application needn't get the ATR, the parameters pbAtr and pulAtrLen can be NULL.
JNIEXPORT jstring JNICALL reset_card(JNIEnv *env, jobject instance, jint handle) {
    char *pbAtr = (char *) malloc(SDSC_MAX_DEV_NAME_LEN * sizeof(char));
    if (pbAtr == NULL) {
        LOGE("reset_card with null alloc.");
        return (*env)->NewStringUTF(env, '\0');
    }
    memset(pbAtr, 0x00, SDSC_MAX_DEV_NAME_LEN * sizeof(char));
    unsigned long pulAtrLen = SDSC_MAX_DEV_NAME_LEN * sizeof(char);
    unsigned long baseResult = SDSCResetCard(handle, pbAtr, &pulAtrLen);
    LOGI("reset_card baseResult: %ld", baseResult);
    LOGI("reset_card pulAtrLen: %ld", pulAtrLen);
    jstring  result = charToJstring(env, pbAtr);
    // need free the memory
    free(pbAtr);
    return result;
}

JNIEXPORT jlong JNICALL reset_control(JNIEnv *env, jobject instance, jint handle, jlong control) {
    unsigned long baseResult = SDSCResetController(handle, control);
    LOGI("reset_control baseResult: %ld", baseResult);
    return baseResult;
}

#if 1 //temporary replaced with other debugging interface,
JNIEXPORT jbyteArray JNICALL transmit(JNIEnv *env, jobject instance, jint handle, jbyteArray str_, jlong length, jlong mode) {
    unsigned long result;

    if(length == 2){
    }else if(length == 4) {
    }else if(length == 5) {
        result = TransmitData_WriteKeyTest(handle);
        LOGI("TransmitData WriteKeyTest ret:%d", result);
    }else if(length == 6) {
        result = TransmitData_ClearKeyTest(handle);
        LOGI("TransmitData ClearKeyTest ret:%d", result);
    } else {
        result = TransmitData_EncryptTest(handle);
        LOGI("TransmitData EncryptTest ret:%d", result);
    }

    return NULL;
}
#else
JNIEXPORT jbyteArray JNICALL transmit(JNIEnv *env, jobject instance, jint handle, jbyteArray str_, jlong length, jlong mode) {
    jbyte* bBuffer = (*env)->GetByteArrayElements(env, str_, 0);
    unsigned char* pbCommand = (unsigned char*) bBuffer;
    if (pbCommand == NULL) {
        LOGE("transmit with null string.");
        return NULL;
    }
    unsigned char *pbOutData = (char *) malloc(SDSC_MAX_DEV_NAME_LEN * sizeof(char));
    if (pbOutData == NULL) {
        LOGE("transmit with null alloc.");
        return NULL;
    }
    memset(pbOutData, 0x00, SDSC_MAX_DEV_NAME_LEN * sizeof(char));
    unsigned long pulOutDataLen = SDSC_MAX_DEV_NAME_LEN * sizeof(char);
    unsigned long pulCosState = 0;

    //    LOGI("transmit pbCommand: %s\n", pbCommand);
    unsigned long baseResult = SDSCTransmit(handle, pbCommand, length, mode, pbOutData, &pulOutDataLen, &pulCosState);
    LOGI("transmit baseResult: %ld", baseResult);
    if (baseResult != 0) {
        free(pbOutData);
        return NULL;
    }
//    LOGI("transmit pulCosState: %ld", pulCosState);
//    LOGI("transmit pbOutData: %s\n", pbOutData);
    jbyte *by = (jbyte*)pbOutData;
    jbyteArray jarray = (*env)->NewByteArray(env, pulOutDataLen);
    (*env)->SetByteArrayRegion(env, jarray, 0, pulOutDataLen, by);

    // need free the memory
    free(pbOutData);
    return jarray;
}
#endif

JNIEXPORT jbyteArray JNICALL transmit_ex(JNIEnv *env, jobject instance, jint handle, jbyteArray str_, jlong mode) {
    jbyte* bBuffer = (*env)->GetByteArrayElements(env, str_, 0);
    unsigned char* pbCommand = (unsigned char*) bBuffer;
    if (pbCommand == NULL) {
        LOGE("transmit_ex with null string.");
        return NULL;
    }
    unsigned char *pbOutData = (char *) malloc(SDSC_MAX_DEV_NAME_LEN * sizeof(char));
    if (pbOutData == NULL) {
        LOGE("transmit_ex with null alloc.");
        return NULL;
    }
    memset(pbOutData, 0x00, SDSC_MAX_DEV_NAME_LEN * sizeof(char));
    unsigned long pulOutDataLen = SDSC_MAX_DEV_NAME_LEN * sizeof(char);
    unsigned long ulCommandLen = (*env)->GetArrayLength(env, str_);
    LOGI("transmit ulCommandLen: %ld", ulCommandLen);
    unsigned long baseResult = SDSCTransmitEx(handle, pbCommand, ulCommandLen, mode, pbOutData, &pulOutDataLen);
    LOGI("transmit_ex baseResult: %ld", baseResult);
    if (baseResult != 0) {
        free(pbOutData);
        return NULL;
    }
    jbyte *by = (jbyte*) pbOutData;
    jbyteArray jarray = (*env)->NewByteArray(env, pulOutDataLen);
    (*env)->SetByteArrayRegion(env, jarray, 0, pulOutDataLen, by);
    // need free the memory
    free(pbOutData);
    return jarray;
}

JNIEXPORT jstring JNICALL get_sdk_ver(JNIEnv *env, jobject instance) {
    char *pszVersion = (char *) malloc(SDSC_MAX_VERSION_LEN * sizeof(char));
    if (pszVersion == NULL) {
        LOGE("get_sdk_ver with null alloc.");
        return (*env)->NewStringUTF(env, '\0');
    }
    memset(pszVersion, 0x00, SDSC_MAX_VERSION_LEN * sizeof(char));
    unsigned long pulVersionLen = SDSC_MAX_VERSION_LEN * sizeof(char);
    unsigned long baseResult = SDSCGetSDKVersion(pszVersion, &pulVersionLen);
    LOGI("get_sdk_ver pszVersion: %s\n", pszVersion);
    LOGI("get_sdk_ver baseResult: %ld", baseResult);
    jstring  result = charToJstring(env, pszVersion);
    // need free the memory
    free(pszVersion);
    return result;
}

JNIEXPORT jlong JNICALL get_scio_type(JNIEnv *env, jobject instance, jint handle) {
    unsigned long pulSCIOType = 0;
    unsigned long baseResult = SDSCGetSCIOType(handle, &pulSCIOType);
    LOGI("get_scio_type baseResult: %ld", baseResult);
    return baseResult;
}

// Java和JNI函数的绑定表
static JNINativeMethod method_table[] = {
        {"setPackageName",  "(Ljava/lang/String;)J",                                   (void *) set_package},
        {"GetFuncList",     "(Ljava/lang/String;)Ljava/lang/String;",                   (void *) get_func_list},
        {"ImportCert",      "(I)J",                                                     (void *) import_cert},
        {"ExportCert",      "(I)J",                                                     (void *) export_cert},
        {"EnumDev",         "()Ljava/lang/String;",                                    (void *) enum_dev},
        {"ConnectDev",      "(Ljava/lang/String;)I",                                    (void *) connect_dev},
        {"DisconnectDev",   "(I)J",                                                    (void *) disconnect_dev},
        {"GenRandom",       "(I)J",                                                    (void *) gen_random},
        {"GenECCKeyPair",   "(I)J",                                                    (void *) gen_ecc_key},
        {"ImportECCKey",    "(I)J",                                                    (void *) import_ecc_key},
        {"ECCSignData",     "(I)J",                                                    (void *) ecc_sign_data},
        {"ECCVerify",       "(I)J",                                                    (void *) ecc_verify},
        {"ExtECCVerify",    "(I)J",                                                    (void *) ext_ecc_verify},
        {"GenDataWithECC",   "(I)J",                                                    (void *) gen_data_ecc},
        {"GenKeyWithECC",    "(I)J",                                                    (void *) gen_key_ecc},
        {"GenDataAndKeyWithECC", "(I)J",                                                (void *) gen_data_key_ecc},
        {"ExportPublicKey",   "(I)J",                                                   (void *) export_public_key},
        {"ImportSessionKey",  "(I)J",                                                   (void *) import_session_key},
        {"SetSymKey",         "(I)J",                                                   (void *) set_sym_key},
        {"CloseHandle",       "(I)J",                                                   (void *) close_handle},
        {"GetDevInfo",        "(I)Ljava/lang/String;",                                  (void *) get_dev_info},
        {"GetZA",             "(I)J",                                                   (void *) get_za},
        {"EncryptInit",       "(I)J",                                                   (void *) encrypt_init},
        {"Encrypt",           "(I)J",                                                   (void *) encrypt},
        {"EncryptUpdate",     "(I)J",                                                   (void *) encrypt_update},
        {"EncryptFinal",      "(I)J",                                                   (void *) encrypt_final},
        {"DecryptInit",       "(I)J",                                                   (void *) decrypt_init},
        {"Decrypt",           "(I)J",                                                   (void *) decrypt},
        {"DecryptUpdate",     "(I)J",                                                   (void *) decrypt_update},
        {"DecryptFinal",      "(I)J",                                                   (void *) decrypt_final},
        {"DigestInit",        "(I)J",                                                   (void *) digest_init},
        {"Digest",            "(I)J",                                                   (void *) digest},
        {"DigestUpdate",      "(I)J",                                                   (void *) digest_update},
        {"DigestFinal",       "(I)J",                                                   (void *) digest_final},
        {"MacInit",           "(I)J",                                                   (void *) mac_init},
        {"MacUpdate",         "(I)J",                                                   (void *) mac_update},
        {"MacFinal",          "(I)J",                                                   (void *) mac_final},
        {"GenerateKey",       "(I)J",                                                   (void *) gen_key},
        {"ECCExportSessionKey", "(I)J",                                                 (void *) ecc_export_session_key},
        {"ECCPrvKeyDecrypt",  "(I)J",                                                   (void *) ecc_prv_key_decrypt},
        {"ImportKeyPair",     "(I)J",                                                   (void *) import_key_pair},
        {"Cipher",            "(I)J",                                                   (void *) cipher},
        {"GetZA",             "(I)J",                                                   (void *) get_za},
        {"BeginTransaction", "(I)J",                                                   (void *) begin_transaction},
        {"EndTransaction",   "(I)J",                                                   (void *) end_transaction},
        {"GetFirmVer",        "(I)Ljava/lang/String;",                                 (void *) get_firm_ver},
        {"GetFlashID",        "(I)Ljava/lang/String;",                                 (void *) get_flash_id},
        {"ResetCard",         "(I)Ljava/lang/String;",                                   (void *) reset_card},
        {"ResetController",  "(IJ)J",                                                   (void *) reset_control},
        {"TransmitSd",        "(I[BJJ)[B",                                                    (void *) transmit},
        {"TransmitEx",        "(I[BJ)[B",                                                 (void *) transmit_ex},
        {"GetSDKVer",         "()Ljava/lang/String;",                                    (void *) get_sdk_ver},
        {"GetSCIOType",      "(I)J",                                                     (void *) get_scio_type},
};

// 注册native方法到java中
static int registerNativeMethods(JNIEnv *env, const char *className,
                                 JNINativeMethod *gMethods, int numMethods) {
    jclass clazz;
    clazz = (*env)->FindClass(env, className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if ((*env)->RegisterNatives(env, clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {

//    ptrace(PTRACE_TRACEME, 0, 0, 0);

    JNIEnv *env = NULL;
    jint result = -1;

    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_4) != JNI_OK) {
        return result;
    }

    // call register method
    if (registerNativeMethods(env, JNIREG_CLASS, method_table, NELEM(method_table)) <= 0) {
        return result;
    }

    // return jni version
    return JNI_VERSION_1_4;
}

