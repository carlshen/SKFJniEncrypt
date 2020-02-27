#ifndef SKF_CRYPTO_SERVICE_H
#define SKF_CRYPTO_SERVICE_H

#include "SKF_TypeDef.h"

void GetDevHandleFromContainer( HANDLE hContainer, HANDLE* phDev );
ULONG SKF_GenRandom( HANDLE hDev, BYTE *pbRandom, ULONG *ulRandomLen );
ULONG SKF_GenExtRSAKey( HANDLE hDev, ULONG ulBitsLen, RSAPRIVATEKEYBLOB *pBlob );
ULONG SKF_GenRSAKeyPair( HANDLE hContainer, ULONG ulBitsLen, RSAPUBLICKEYBLOB* pBlob );
ULONG SKF_ImportRSAKeyPair( HANDLE hContainer, ULONG ulSymAlgId, BYTE *pbWrappedKey, ULONG ulWrappedKeyLen,
                            BYTE *pbEncryptedData, ULONG ulEncryptedDataLen);
ULONG SKF_RSASignData( HANDLE hContainer, BYTE *pbData, ULONG  ulDataLen, BYTE *pbSignature, ULONG *pulSignLen );
ULONG SKF_RSAVerify( HANDLE hDev, RSAPUBLICKEYBLOB* pRSAPubKeyBlob, BYTE *pbData, ULONG ulDataLen,
                     BYTE* pbSignature, ULONG ulSignLen );
ULONG SKF_RSAExportSessionKey( HANDLE hContainer, ULONG ulAlgId, RSAPUBLICKEYBLOB *pPubKey,
                               BYTE *pbData, ULONG  *pulDataLen, HANDLE *phSessionKey );
ULONG SKF_ExtRSAPubKeyOperation( HANDLE hDev, RSAPUBLICKEYBLOB* pRSAPubKeyBlob,BYTE* pbInput,
                                 ULONG ulInputLen, BYTE* pbOutput, ULONG* pulOutputLen );
ULONG SKF_ExtRSAPriKeyOperation( HANDLE hDev, RSAPRIVATEKEYBLOB* pRSAPriKeyBlob,BYTE* pbInput,
                                 ULONG ulInputLen, BYTE* pbOutput, ULONG* pulOutputLen );
ULONG SKF_GenECCKeyPair( HANDLE hContainer, BYTE* pBlob );
ULONG SKF_ImportECCKeyPair( HANDLE hContainer, BYTE* pubKey, BYTE* privKey );
ULONG SKF_ECCSignData( HANDLE hContainer, BYTE *pbData, ULONG ulDataLen,
                       PECCSIGNATUREBLOB pSignature );
ULONG SKF_ECCVerify( HANDLE hDev, ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE* pbData,
                     ULONG ulDataLen, PECCSIGNATUREBLOB pSignature );
ULONG SKF_ECCExportSessionKey( HANDLE hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB* pPubKey,
                               PECCCIPHERBLOB pData, HANDLE* phSessionKey );
ULONG SKF_ExtECCEncrypt( HANDLE hDev, ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE* pbPlainText,
                         ULONG ulPlainTextLen, PECCCIPHERBLOB pCipherText );
ULONG SKF_ExtECCVerify( HANDLE hDev, ECCPUBLICKEYBLOB*  pECCPubKeyBlob,BYTE* pbData, ULONG ulDataLen,
                        PECCSIGNATUREBLOB pSignature );
ULONG SKF_GenECCKeyPairEx( HANDLE hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB* pPubKeyBlob,
                           ECCPRIVATEKEYBLOB *pPrivKeyBlob );
ULONG SKF_ImportECCKeyPair2( HANDLE hContainer, PENVELOPEDKEYBLOB pEnvelopedKeyBlob );
ULONG SKF_ECCDecrypt( HANDLE hContainer, PECCCIPHERBLOB pCipherText, BYTE* pbPlainText, ULONG* pulPlainTextLen );
ULONG SKF_ECCMultAdd(HANDLE hContainer, unsigned int k, ECCPRIVATEKEYBLOB *e,
                     ECCPUBLICKEYBLOB *A, ECCPUBLICKEYBLOB * B, ECCPUBLICKEYBLOB * C);
ULONG SKF_ECCModMultAdd(HANDLE hContainer, ECCPRIVATEKEYBLOB *k, ECCPRIVATEKEYBLOB * a,
                        ECCPRIVATEKEYBLOB * b, ECCPRIVATEKEYBLOB * c);
ULONG SKF_GenerateAgreementDataWithECC( HANDLE hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
                                        BYTE* pbID, ULONG ulIDLen, HANDLE* phAgreementHandle );
ULONG SKF_GenerateAgreementDataAndKeyWithECC( HANDLE hContainer, ULONG ulAlgId,
                                              ECCPUBLICKEYBLOB* pSponsorECCPubKeyBlob, ECCPUBLICKEYBLOB* pSponsorTempECCPubKeyBlob,
                                              ECCPUBLICKEYBLOB* pTempECCPubKeyBlob, BYTE* pbID, ULONG ulIDLen, BYTE* pbSponsorID,
                                              ULONG ulSponsorIDLen, HANDLE* phKeyHandle );
ULONG SKF_GenerateKeyWithECC( HANDLE hAgreementHandle, ECCPUBLICKEYBLOB* pECCPubKeyBlob,
                              ECCPUBLICKEYBLOB* pTempECCPubKeyBlob, BYTE* pbID,
                              ULONG ulIDLen, HANDLE* phKeyHandle );
ULONG SKF_ExportPublicKey( HANDLE hContainer, BYTE* pbBlob, ULONG* pulBlobLen );
ULONG SKF_ImportSessionKey( HANDLE hContainer, ULONG ulAlgId, BYTE* pbWrapedData,
                            ULONG ulWrapedLen, HANDLE* phKey );
ULONG SKF_SetSymmKey( HANDLE hDev,  BYTE *pbKey, ULONG ulAlgID, HANDLE *phKey );
ULONG SKF_EncryptInit( HANDLE hKey, BLOCKCIPHERPARAM encryptParam );
ULONG SKF_Encrypt( HANDLE hKey, BYTE *pbData, ULONG ulDataLen,
                   BYTE *pbEncryptedData, ULONG * pulEncryptedLen );
ULONG SKF_EncryptUpdate( HANDLE hKey, BYTE * pbData, ULONG ulDataLen, BYTE *pbEncryptedData,
                         ULONG *pulEncryptedLen );
ULONG SKF_EncryptFinal (HANDLE hKey, BYTE *pbEncryptedData, ULONG *pulEncryptedLen );
ULONG SKF_DecryptInit( HANDLE hKey, BLOCKCIPHERPARAM encryptParam );
ULONG SKF_Decrypt( HANDLE hKey, BYTE *pbEncryptedData, ULONG ulEncryptedLen,
                   BYTE *pbData, ULONG *pulDataLen );
ULONG SKF_DecryptUpdate( HANDLE hKey, BYTE * pbEncryptedData, ULONG ulEncryptedLen, BYTE * pbData,
                         ULONG * pulDataLen );
ULONG SKF_DecryptFinal (HANDLE hKey, BYTE *pbDecryptedData, ULONG *pulDecryptedLen);
ULONG SKF_DigestInit( HANDLE hDev, ULONG ulAlgID, ECCPUBLICKEYBLOB* pPubKey, BYTE* pucID,
                      ULONG ulIDLen, HANDLE *phHash );
ULONG SKF_Digest( HANDLE hHash, BYTE* pbData, ULONG ulDataLen, BYTE* pbHashData, ULONG* pulHashLen );
ULONG SKF_DigestUpdate( HANDLE hHash, BYTE* pbData, ULONG ulDataLen );
ULONG SKF_DigestFinal( HANDLE hHash, BYTE* pbHashData, ULONG* pulHashLen );
ULONG SKF_MacInit( HANDLE hKey, BLOCKCIPHERPARAM* pMacParam, HANDLE* phMac );
ULONG SKF_Mac( HANDLE hMac, BYTE* pbData, ULONG ulDataLen, BYTE* pbMacData, ULONG* pulMacLen );
ULONG SKF_MacUpdate( HANDLE hMac, BYTE* pbData, ULONG ulDataLen );
ULONG SKF_MacFinal( HANDLE hMac, BYTE* pbMacData, ULONG* pulMacDataLen );
ULONG SKF_CloseHandle( HANDLE hHandle );
ULONG V_ECCPrvKeyDecrypt( HANDLE hContainer, BYTE *bKeyFlag, BYTE *pData, BYTE *pbOutData, ULONG *uOutLen );
ULONG V_Cipher(HANDLE hContainer, BYTE *pbData, ULONG ulDataLen, BYTE *pbSignature,
               ULONG *pulSignLen);
ULONG V_GetZA( HANDLE hContainer, BYTE *pData, BYTE *pZA, ULONG  *ulZALen );
ULONG V_GenerateKey( HANDLE hContainer, ULONG ulAlgId, BYTE *bKeyFlag, BYTE* pKeyData, ULONG *uKeyLen );
ULONG V_ECCExportSessionKeyByHandle( HANDLE hContainer, BYTE *bKeyFlag, BYTE* pKeyData, ULONG uKeyLen, BYTE *pbOutData, ULONG *uOutLen );

#endif //SKF_CRYPTO_SERVICE_H
