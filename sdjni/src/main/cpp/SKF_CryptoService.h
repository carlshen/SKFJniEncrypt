#ifndef SKF_CRYPTOSERVICE_H
#define SKF_CRYPTOSERVICE_H

#include "SKF_TypeDef.h"

void GetDevHandleFromContainer( HCONTAINER hContainer, DEVHANDLE* phDev );
ULONG SKF_GenRandom( DEVHANDLE hDev, BYTE *pbRandom, ULONG ulRandomLen );
ULONG SKF_GenExtRSAKey( DEVHANDLE hDev, ULONG ulBitsLen, RSAPRIVATEKEYBLOB *pBlob );
ULONG SKF_GenRSAKeyPair( HCONTAINER hContainer, ULONG ulBitsLen, RSAPUBLICKEYBLOB* pBlob );
ULONG SKF_ImportRSAKeyPair( HCONTAINER hContainer, ULONG ulSymAlgId, BYTE *pbWrappedKey, ULONG ulWrappedKeyLen,
                            BYTE *pbEncryptedData, ULONG ulEncryptedDataLen);
ULONG SKF_RSASignData( HCONTAINER hContainer, BYTE *pbData, ULONG  ulDataLen, BYTE *pbSignature, ULONG *pulSignLen );
ULONG SKF_RSAVerify( DEVHANDLE hDev, RSAPUBLICKEYBLOB* pRSAPubKeyBlob, BYTE *pbData, ULONG ulDataLen,
                     BYTE* pbSignature, ULONG ulSignLen );
ULONG SKF_RSAExportSessionKey( HCONTAINER hContainer, ULONG ulAlgId, RSAPUBLICKEYBLOB *pPubKey,
                               BYTE *pbData, ULONG  *pulDataLen, HANDLE *phSessionKey );
ULONG SKF_ExtRSAPubKeyOperation( DEVHANDLE hDev, RSAPUBLICKEYBLOB* pRSAPubKeyBlob,BYTE* pbInput,
                                 ULONG ulInputLen, BYTE* pbOutput, ULONG* pulOutputLen );
ULONG SKF_ExtRSAPriKeyOperation( DEVHANDLE hDev, RSAPRIVATEKEYBLOB* pRSAPriKeyBlob,BYTE* pbInput,
                                 ULONG ulInputLen, BYTE* pbOutput, ULONG* pulOutputLen );
ULONG SKF_GenECCKeyPair( HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB* pBlob );
ULONG SKF_ImportECCKeyPair( HCONTAINER hContainer, PENVELOPEDKEYBLOB pEnvelopedKeyBlob );
ULONG SKF_ECCSignData( HCONTAINER hContainer, BYTE *pbData, ULONG ulDataLen,
                       PECCSIGNATUREBLOB pSignature );
ULONG SKF_ECCVerify( DEVHANDLE hDev, ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE* pbData,
                     ULONG ulDataLen, PECCSIGNATUREBLOB pSignature );
ULONG SKF_ECCExportSessionKey( HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB* pPubKey,
                               PECCCIPHERBLOB pData, HANDLE* phSessionKey );
ULONG SKF_ExtECCEncrypt( DEVHANDLE hDev, ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE* pbPlainText,
                         ULONG ulPlainTextLen, PECCCIPHERBLOB pCipherText );
ULONG SKF_ExtECCVerify( DEVHANDLE hDev, ECCPUBLICKEYBLOB*  pECCPubKeyBlob,BYTE* pbData, ULONG ulDataLen,
                        PECCSIGNATUREBLOB pSignature );
ULONG SKF_GenECCKeyPairEx( HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB* pPubKeyBlob,
                           ECCPRIVATEKEYBLOB *pPrivKeyBlob );
ULONG SKF_ImportECCKeyPair2( HCONTAINER hContainer, PENVELOPEDKEYBLOB pEnvelopedKeyBlob );
ULONG SKF_ECCDecrypt( HCONTAINER hContainer, PECCCIPHERBLOB pCipherText, BYTE* pbPlainText, ULONG* pulPlainTextLen );
ULONG SKF_ECCMultAdd(HCONTAINER hContainer, unsigned int k, ECCPRIVATEKEYBLOB *e,
                     ECCPUBLICKEYBLOB *A, ECCPUBLICKEYBLOB * B, ECCPUBLICKEYBLOB * C);
ULONG SKF_ECCModMultAdd(HCONTAINER hContainer, ECCPRIVATEKEYBLOB *k, ECCPRIVATEKEYBLOB * a,
                        ECCPRIVATEKEYBLOB * b, ECCPRIVATEKEYBLOB * c);
ULONG SKF_GenerateAgreementDataWithECC( HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
                                        BYTE* pbID, ULONG ulIDLen, HANDLE* phAgreementHandle );
ULONG SKF_GenerateAgreementDataAndKeyWithECC( HANDLE hContainer, ULONG ulAlgId,
                                              ECCPUBLICKEYBLOB* pSponsorECCPubKeyBlob, ECCPUBLICKEYBLOB* pSponsorTempECCPubKeyBlob,
                                              ECCPUBLICKEYBLOB* pTempECCPubKeyBlob, BYTE* pbID, ULONG ulIDLen, BYTE* pbSponsorID,
                                              ULONG ulSponsorIDLen, HANDLE* phKeyHandle );
ULONG SKF_GenerateKeyWithECC( HANDLE hAgreementHandle, ECCPUBLICKEYBLOB* pECCPubKeyBlob,
                              ECCPUBLICKEYBLOB* pTempECCPubKeyBlob, BYTE* pbID,
                              ULONG ulIDLen, HANDLE* phKeyHandle );
ULONG SKF_ExportPublicKey( HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbBlob, ULONG* pulBlobLen );
ULONG SKF_SetSymmKey( DEVHANDLE hDev,  BYTE *pbKey, ULONG ulAlgID, HANDLE *phKey );
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
ULONG SKF_DigestInit( DEVHANDLE hDev, ULONG ulAlgID, ECCPUBLICKEYBLOB* pPubKey, BYTE* pucID,
                      ULONG ulIDLen, HANDLE *phHash );
ULONG SKF_DigestInit1( DEVHANDLE hDev, ULONG ulAlgID, ECCPUBLICKEYBLOB* pPubKey, BYTE* pucID,
                       ULONG ulIDLen, HANDLE *phHash );
ULONG SKF_Digest( HANDLE hHash, BYTE* pbData, ULONG ulDataLen, BYTE* pbHashData, ULONG* pulHashLen );
ULONG SKF_DigestUpdate( HANDLE hHash, BYTE* pbData, ULONG ulDataLen );
ULONG SKF_DigestFinal( HANDLE hHash, BYTE* pbHashData, ULONG* pulHashLen );
ULONG SKF_MacInit( HANDLE hKey, BLOCKCIPHERPARAM* pMacParam, HANDLE* phMac );
ULONG SKF_Mac( HANDLE hMac, BYTE* pbData, ULONG ulDataLen, BYTE* pbMacData, ULONG* pulMacLen );
ULONG SKF_MacUpdate( HANDLE hMac, BYTE* pbData, ULONG ulDataLen );
ULONG SKF_MacFinal( HANDLE hMac, BYTE* pbMacData, ULONG* pulMacDataLen );
ULONG SKF_CloseHandle( HANDLE hHandle );

#endif //SKF_CRYPTOSERVICE_H