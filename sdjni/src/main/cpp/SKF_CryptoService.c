// SKF_CryptoService.cpp: implementation of the SKF_CryptoService class.
//
//////////////////////////////////////////////////////////////////////
#include <string.h>
#include <zconf.h>
#include "SKF_TypeDef.h"
#include "Global_Def.h"
#include "Algorithms.h"
#include "transmit.h"
#include "SKF_CryptoService.h"
#include "APDUs.h"
#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif  /*__cplusplus*/

//1
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_GenRandom
* �������ܣ������
* �����б�hDev:        [IN], �豸���
*           pbRandom:    [OUT], ���������
*           ulRandomLen: [IN], ���������
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_GenRandom( HANDLE hDev, BYTE *pbRandom, ULONG *ulRandomLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_GenRandom ********** \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	sv_fEnd = FALSE;
	memset( szLog, 0x0, sizeof(szLog) );

    WriteLogToFile( pszLog );

	if( hDev < 0 ) {
		return SAR_INVALIDHANDLEERR;
	}
	if (pbRandom == NULL) {
		LOGE("SKF_GenRandom param is null.");
		return -1;
	}

	unsigned long send_len = strlen(apdu_84_00);
	unsigned char check_sum = 0;
	int ret;
	unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	//copy the raw data
	memcpy(tmpBuffer_wr, (unsigned char *)apdu_84_00, send_len);

	unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	unsigned long recv_len = 0;

	//fill the checksum byte
	check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

	//fill the data ...........................................
	*(tmpBuffer_wr+send_len) = check_sum;
	send_len = send_len + 1;

	int repeat_times = 10;
	for (int i = 0; i < repeat_times; i++) {
		if (repeat_times > 1)
			usleep(500 * 1000);  //gap between each cycle

		memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
		recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
		ret = TransmitData(trans_dev_id, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
		if (ret < 0) {
			sprintf( szLog, "SKF_GenRandom failed, error code: %d \n", ret );
			WriteLogToFile( szLog );
			LOGE("SKF_GenRandom return failed, ret %d.", ret);
			ret = -1;
			continue;
		}
		if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
			// get data if need
            *ulRandomLen = recv_len-2;
            memcpy(pbRandom, tmpBuffer_rd, *ulRandomLen);
			break;
		} else {
			sprintf( szLog, "SKF_GenRandom failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
			WriteLogToFile( szLog );
			LOGE("SKF_GenRandom failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
		}
	}

    free(tmpBuffer_wr);
    free(tmpBuffer_rd);
    if (ret < 0) {
        return SAR_FAIL;
    }
	return SAR_OK;
}


//2--------------------NO
ULONG SKF_GenExtRSAKey( HANDLE hDev, ULONG ulBitsLen, RSAPRIVATEKEYBLOB *pBlob )
{
	CHAR* pszLog = ( "**********Start to execute SKF_GenExtRSAKey ********** \n" );
   
	WriteLogToFile( pszLog );

	return SAR_OK;
}

//3
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_GenRSAKeyPair
* �������ܣ�����RSAǩ����Կ��
* �����б�hContainer:	        [IN], �������
*	        ulBitsLen:	        [IN], ��Կģ��
*	        pBlob: 	            [OUT, ���ص�RSA��Կ���ݽṹ

* �� �� ֵ:	SAR_OK���ɹ�
            ����ֵ��������
*/
ULONG SKF_GenRSAKeyPair( HANDLE hContainer, ULONG ulBitsLen, RSAPUBLICKEYBLOB* pBlob )
{
	CHAR* pszLog = ( "**********Start to execute SKF_GenRSAKeyPair ********** \n" );
    
	WriteLogToFile( pszLog );

	return SAR_OK;
}

//4
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_ImportRSAKeyPair
* �������ܣ�����RSA������Կ��
* �����б�hContainer:	        [IN], ���������
*	        ulSymAlgId:	        [IN], �Գ��㷨��Կ��ʶ��
*	        pbWrappedKey: 	    [IN], ʹ�ø�������ǩ����Կ�����ĶԳ��㷨��Կ��
*	        ulWrappedKeyLen:	[IN], �����ĶԳ��㷨��Կ���ȡ�
*	        pbEncryptedData:	[IN], �Գ��㷨��Կ������RSA����˽Կ��˽Կ�ĸ�ʽ��ѭPKCS #1 v2.1: RSA Cryptography Standard�е�˽Կ��ʽ���塣
*	        ulEncryptedDataLen:	[IN], �Գ��㷨��Կ������RSA���ܹ�˽Կ�Գ��ȡ�
* �� �� ֵ:	SAR_OK���ɹ�
            ����ֵ��������
*/

ULONG SKF_ImportRSAKeyPair( HANDLE hContainer, ULONG ulSymAlgId, BYTE *pbWrappedKey, ULONG ulWrappedKeyLen,
                                   BYTE *pbEncryptedData, ULONG ulEncryptedDataLen)
{
	CHAR* pszLog = ( "**********Start to execute SKF_ImportRSAKeyPair ********** \n" );

    WriteLogToFile( pszLog );

	return SAR_OK;
}

//5
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_RSASignData
* �������ܣ�RSAǩ��
* �����б�hContainer:  [IN], �������
*           pbData:      [IN], ��ǩ��������
*           ulDataLen:   [IN], ǩ�����ݳ��ȣ�Ӧ������RSA��Կģ��-11
*           pbSignature: [OUT], ���ǩ������Ļ�����ָ�룻���ֵΪNULL������ȡ��ǩ���������
*           pulSignLen:  [IN/OUT], ����ʱ��ʾǩ�������������С�����ʱ��ʾǩ���������

* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_RSASignData( HANDLE hContainer, BYTE *pbData, ULONG  ulDataLen, BYTE *pbSignature, ULONG *pulSignLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_RSASignData ********** \n" );
    
	WriteLogToFile( pszLog );

	return SAR_OK;
}
 

//6--------------------NO   
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_RSAVerify
* �������ܣ�RSA��ǩ
* �����б�hDev:           [IN], �豸���
*           pRSAPubKeyBlob: [IN], RSA��Կ���ݽṹ
*           pbData:         [IN], ����֤ǩ��������
*           ulDataLen:      [IN], ���ݳ��ȣ�Ӧ�����ڹ�Կģ��-11
*           pbSignature:    [IN], ����֤��ǩ��ֵ
*           ulSignLen:      [IN], ǩ��ֵ���ȣ�����Ϊ��Կģ��

* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
                                   
ULONG SKF_RSAVerify( HANDLE hDev, RSAPUBLICKEYBLOB* pRSAPubKeyBlob, BYTE *pbData, ULONG ulDataLen,
						   BYTE* pbSignature, ULONG ulSignLen )
{
	CHAR* pszLog = ("**********Start to execute SKF_RSAVerify ********** \n");
    
	WriteLogToFile( pszLog );

	return SAR_OK;
}


//7--------------------NO
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_RSAExportSessionKey
* �������ܣ�RSA���ɲ������Ự��Կ
* �����б�hContainer:  [IN], �������
*           ulAlgId:     [IN], �Ự��Կ�㷨��ʶ
*           pPubKey:     [IN], ���ܻỰ��Կ��RSA��Կ���ݽṹ
*           pbData:      [OUT], �����ļ��ܻỰ��Կ���ģ�����RKCS#1v1.5Ҫ���װ
*           pulDataLen:  [IN/OUT], ����ʱ��ʾ�Ự��Կ�������ݻ��������ȣ����ʱ��ʾ�Ự��Կ���ĵ�ʵ�ʳ���
*           phSessionKey: [OUT], ��������Կ���
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_RSAExportSessionKey( HANDLE hContainer, ULONG ulAlgId, RSAPUBLICKEYBLOB *pPubKey,
									 BYTE *pbData, ULONG  *pulDataLen, HANDLE *phSessionKey )
{
	CHAR* pszLog = ("**********Start to execute SKF_RSAExportSessionKey ********** \n");
    
	WriteLogToFile( pszLog );

	return SAR_OK;
}

//8--------------------NO
ULONG SKF_ExtRSAPubKeyOperation( HANDLE hDev, RSAPUBLICKEYBLOB* pRSAPubKeyBlob,BYTE* pbInput,
										ULONG ulInputLen, BYTE* pbOutput, ULONG* pulOutputLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_ExtRSAPubKeyOperation ********** \n" );

    WriteLogToFile( pszLog );

	return SAR_OK;
}

//9--------------------NO
ULONG SKF_ExtRSAPriKeyOperation( HANDLE hDev, RSAPRIVATEKEYBLOB* pRSAPriKeyBlob,BYTE* pbInput,
									   ULONG ulInputLen, BYTE* pbOutput, ULONG* pulOutputLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_ExtRSAPriKeyOperation ********** \n" );

    WriteLogToFile( pszLog );
	return SAR_OK;
}

//10
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_GenECCKeyPair
* �������ܣ�����ECCǩ����Կ�Բ����ǩ����Կ
* �����б�hContainer:  [IN], �������
*           ulAlgId:     [IN], �㷨��ʶ��ֻ֧��SGD_SM2_1�㷨
*           pBlob:       [OUT], ����ECC��Կ���ݽṹ
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_GenECCKeyPair( HANDLE hDev, BYTE * pBlob )
{
	CHAR* pszLog = ( "**********Start to execute SKF_GenECCKeyPair ********** \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE apdu[0x0D];
	sv_fEnd = FALSE;
	
    memset( szLog, 0x0, strlen(szLog) );
	memset( apdu, 0x00, sizeof(apdu) );

	WriteLogToFile( pszLog );

    if( hDev < 0 ) {
        return SAR_INVALIDHANDLEERR;
    }
    if (pBlob == NULL) {
        LOGE("SKF_GenECCKeyPair param is null.");
        return -1;
    }

    // 80C80000 08 0107+A001+A101+0100
    memcpy(apdu, (unsigned char *)apdu_C8_00, 0x05);
    memcpy(apdu + 0x05, apdu_GenEccKeyPair, 0x08);
    unsigned long send_len = strlen(apdu);
    unsigned char check_sum = 0;
    int ret;
    unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    //copy the raw data
    memcpy(tmpBuffer_wr, (unsigned char *)apdu, send_len);

    unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    unsigned long recv_len = 0;

    //fill the checksum byte
    check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

    //fill the data ...........................................
    *(tmpBuffer_wr+send_len) = check_sum;
    send_len = send_len + 1;

    int repeat_times = 10;
    for (int i = 0; i < repeat_times; i++) {
        if (repeat_times > 1)
            usleep(500 * 1000);  //gap between each cycle

        memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
        recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
        ret = TransmitData(trans_dev_id, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
        if (ret < 0) {
            sprintf( szLog, "SKF_GenECCKeyPair failed, error code: %d \n", ret );
            WriteLogToFile( szLog );
            LOGE("SKF_GenECCKeyPair return failed, ret %d.", ret);
            ret = -1;
            continue;
        }
        if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
            // get data if need
            break;
        } else {
            sprintf( szLog, "SKF_GenECCKeyPair failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
            WriteLogToFile( szLog );
            LOGE("SKF_GenECCKeyPair failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
        }
    }
	if (ret < 0) {
		free(tmpBuffer_wr);
		free(tmpBuffer_rd);
		return SAR_FAIL;
	}

	// command ecc key pair
	unsigned char DataTobeSend[0x07];
	send_len = 0x07;
	memcpy(DataTobeSend, (unsigned char *)apdu_CE_01, 0x05);
	memcpy(DataTobeSend + 0x05, apdu_A001, 0x02);
	//copy the raw data
	memcpy(tmpBuffer_wr, (unsigned char *)DataTobeSend, send_len);

	//fill the checksum byte
	check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

	//fill the data ...........................................
	*(tmpBuffer_wr+send_len) = check_sum;
	send_len = send_len + 1;

	repeat_times = 10;
	for (int i = 0; i < repeat_times; i++) {
		if (repeat_times > 1)
			usleep(500 * 1000);  //gap between each cycle

		memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
		recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
		ret = TransmitData(trans_dev_id, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
		if (ret < 0) {
            sprintf( szLog, "SKF_GenECCKeyPair failed, error code: %d \n", ret );
            WriteLogToFile( szLog );
            LOGE("SKF_GenECCKeyPair return failed, ret %d.", ret);
			ret = -1;
			continue;
		}
		if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
			// get data if need
			memcpy(pBlob, tmpBuffer_rd, recv_len-2);
			break;
        } else {
            sprintf( szLog, "SKF_GenECCKeyPair failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
            WriteLogToFile( szLog );
            LOGE("SKF_GenECCKeyPair failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
        }
	}

    free(tmpBuffer_wr);
    free(tmpBuffer_rd);
    if (ret < 0) {
        return SAR_FAIL;
    }
    return SAR_OK;
}


//11
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_ImportECCKeyPair
* �������ܣ�����ECC������Կ��
* �����б�hContainer:            [IN], �������
*           pEnvelopedKeyBlob:     [IN], �ܱ����ļ�����Կ��
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_ImportECCKeyPair( HANDLE hDev, BYTE* pubKey, BYTE* privKey )
{
	CHAR* pszLog = ( "**********Start to execute SKF_ImportECCKeyPair ********** \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE apdu[0x4B];
	if( hDev < 0 ) {
		return SAR_INVALIDHANDLEERR;
	}
	if (pubKey == NULL || (strlen(pubKey) != SIZE_BUFFER_64)) {
		LOGE("SKF_ImportECCKeyPair param pubKey is null.");
		return -1;
	}
	if (privKey == NULL || (strlen(privKey) != SIZE_BUFFER_32)) {
		LOGE("SKF_ImportECCKeyPair param privKey is null.");
		return -1;
	}

	WriteLogToFile( pszLog );
	sv_fEnd = FALSE;
	memset( apdu, 0x00, sizeof(apdu) );
	memset( szLog, 0x0, strlen(szLog) );

	//  80CC0000 46 0107+A002+0040+64�ֽ�SM2��Կ
	memcpy(apdu, (unsigned char *)apdu_CC_00, 0x04);
	memcpy(apdu + 0x04, apdu_importEcc46, 0x07);
	memcpy(apdu + 0x04 + 0x07, pubKey, 0x40);
	unsigned long send_len = strlen(apdu);
	unsigned char check_sum = 0;
	int ret;
	unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	//copy the raw data
	memcpy(tmpBuffer_wr, (unsigned char *)apdu, send_len);

	unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	unsigned long recv_len = 0;

	//fill the checksum byte
	check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

	//fill the data ...........................................
	*(tmpBuffer_wr+send_len) = check_sum;
	send_len = send_len + 1;

	int repeat_times = 10;
	for (int i = 0; i < repeat_times; i++) {
		if (repeat_times > 1)
			usleep(500 * 1000);  //gap between each cycle

		memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
		recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
		ret = TransmitData(trans_dev_id, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
		if (ret < 0) {
			sprintf( szLog, "SKF_ImportECCKeyPair failed, error code: %d \n", ret );
			WriteLogToFile( szLog );
			LOGE("SKF_ImportECCKeyPair return failed, ret %d.", ret);
			ret = -1;
			continue;
		}
		if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
			// get data if need
			break;
		} else {
			sprintf( szLog, "SKF_ImportECCKeyPair failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
			WriteLogToFile( szLog );
			LOGE("SKF_ImportECCKeyPair failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
		}
	}
	if (ret < 0) {
		free(tmpBuffer_wr);
		free(tmpBuffer_rd);
		return SAR_FAIL;
	}

	// import ecc key pair
	unsigned char DataTobeSend[0x2B];
	send_len = strlen(DataTobeSend);;
    memcpy(DataTobeSend, (unsigned char *)apdu_CC_00, 0x04);
    memcpy(DataTobeSend + 0x04, apdu_importEcc26, 0x07);
    memcpy(DataTobeSend + 0x04 + 0x07, privKey, 0x20);
	//copy the raw data
	memcpy(tmpBuffer_wr, (unsigned char *)DataTobeSend, send_len);

	//fill the checksum byte
	check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

	//fill the data ...........................................
	*(tmpBuffer_wr+send_len) = check_sum;
	send_len = send_len + 1;

	repeat_times = 10;
	for (int i = 0; i < repeat_times; i++) {
		if (repeat_times > 1)
			usleep(500 * 1000);  //gap between each cycle

		memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
		recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
		ret = TransmitData(trans_dev_id, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
		if (ret < 0) {
            sprintf( szLog, "SKF_ImportECCKeyPair failed, error code: %d \n", ret );
            WriteLogToFile( szLog );
            LOGE("SKF_ImportECCKeyPair return failed, ret %d.", ret);
			ret = -1;
			continue;
		}
		if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
			// get data if need
			break;
        } else {
            sprintf( szLog, "SKF_ImportECCKeyPair failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
            WriteLogToFile( szLog );
            LOGE("SKF_ImportECCKeyPair failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
        }
	}

	free(tmpBuffer_wr);
	free(tmpBuffer_rd);
	if (ret < 0) {
		return SAR_FAIL;
	}

	return SAR_OK;
}
//12
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_ECCSignData
* �������ܣ�ECCǩ��
* �����б�hContainer: [IN], �������
*           pbData:     [IN], ��ǩ������
*           ulDataLen:  [IN], ��ǩ�����ݳ��ȣ�����С����Կģ��
*           pSignature: [OUT], ǩ��ֵ
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
BYTE sign_ef_fid[2] = { 0x00, 0x00 };
ULONG SKF_ECCSignData( HANDLE hContainer, BYTE *pbData, ULONG ulDataLen,
							 PECCSIGNATUREBLOB pSignature )
{
	CHAR* pszLog = ("**********Start to execute SKF_ECCSignData ********** \n");
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE appFID[2] = { 0xDF, 0x00 };
	BYTE response[SIZE_BUFFER_1024];
	BYTE fileSFI[0x06] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	BYTE apdu[SIZE_BUFFER_1024];
	HANDLE hDev;
	DWORD nResponseLen = 0;
	LONG nRet = 0;
	sv_fEnd = FALSE;
    memset( szLog, 0x0, strlen(szLog) );
	memset( apdu, 0x00, sizeof(apdu) );
	memset( response, 0x00, sizeof(response) );

	WriteLogToFile( pszLog );

	//--------�����������Ϊ��
	if( hContainer == NULL )
	{
		return SAR_INVALIDHANDLEERR;
	}

	//--------ѡ��ADF��ͨ��FIDѡ��
	if( SV_SelectDFByFID(hDev, appFID, "ѡ��ADF") != SAR_OK )
		return SAR_FAIL;


	//--------��֯APDU
	memcpy( apdu, apdu_eccSignData, 0x05 );
	apdu[2] = 0xEB;
	apdu[3] = fileSFI[4];
	sign_ef_fid[0] = 0xEB;
	sign_ef_fid[1] = fileSFI[4];
	apdu[4] = (BYTE)ulDataLen; 

	memcpy( apdu+0x05, pbData, ulDataLen );

//	PrintApduToFile( 0, apdu, (BYTE)(0x05+ulDataLen) );

    nResponseLen = sizeof( response );
    nRet = TransmitData( hDev, apdu, 0x05+ulDataLen, response, &nResponseLen );
    if( nRet != SAR_OK )
	{
        sprintf( szLog, "ECCǩ��ʧ�ܣ�������: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}
	
//	PrintApduToFile( 1, response, nResponseLen );

	if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
	{
		memcpy( sv_eccSignBlob.r, response, SIZE_BUFFER_32 );
		memcpy( sv_eccSignBlob.s, response+SIZE_BUFFER_32, SIZE_BUFFER_32 );
		memcpy( (pSignature->r)+SIZE_BUFFER_32, response, SIZE_BUFFER_32 );
		memcpy( (pSignature->s)+SIZE_BUFFER_32, response+SIZE_BUFFER_32, SIZE_BUFFER_32 );
        //pSignature = &sv_eccSignBlob;
#ifdef _DEBUG
		BYTE m = 0;
		WriteLogToFile( TEXT("Signature: \n") );
		for( m=0; m<nResponseLen-2; m++ )
		{
			sprintf( szLog, "%02X", response[m] );
			WriteLogToFile( szLog );
		}
		WriteLogToFile( TEXT("\n") );
#endif
	}
	else
	{
		sprintf( szLog, "ECCǩ��ʧ�ܣ�״̬��: %02x%02x \n", response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;	
	}

	return SAR_OK;
}

//13--------------------NO
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_ECCVerify
* �������ܣ�ECC��ǩ
* �����б�hDev:     [IN], �豸���
*           pECCPubKeyBlob: [IN], ECC��Կ���ݽṹ
*           pbData:         [IN], ����֤ǩ��������
*           ulDataLen:      [IN], ����֤ǩ�������ݳ���
*           pSignature:     [IN], ����֤ǩ��ֵ
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_ECCVerify( HANDLE hDev, ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE* pbData,
						   ULONG ulDataLen, PECCSIGNATUREBLOB pSignature )
{
	CHAR* pszLog = ( "**********Start to execute SKF_ECCVerify ********** \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE response[SIZE_BUFFER_1024];
	BYTE apdu[SIZE_BUFFER_1024];
	DWORD nResponseLen = 0;
	LONG nRet = 0;
	sv_fEnd = FALSE;
    memset( szLog, 0x0, strlen(szLog) );
	memset( apdu, 0x00, sizeof(apdu) );
	memset( response, 0x00, sizeof(response) );

	WriteLogToFile( pszLog );

	//--------�豸�������Ϊ��
	if( hDev == NULL )
	{
		return SAR_INVALIDHANDLEERR;
	}

	if( OpenApplication( hDev, sv_stApplication.ApplicationName) != SAR_OK )
		return SAR_FAIL;

	//--------��֯APDU����ǩ
	memcpy( apdu, apdu_eccSignVerify, 0x05 );
	apdu[4] = SIZE_BUFFER_128+(BYTE)ulDataLen;

	memcpy( apdu+0x05, (pECCPubKeyBlob->XCoordinate)+SIZE_BUFFER_32, SIZE_BUFFER_32 );
	memcpy( apdu+0x05+SIZE_BUFFER_32, (pECCPubKeyBlob->YCoordinate)+SIZE_BUFFER_32, SIZE_BUFFER_32 );
	
	memcpy( apdu+0x05+SIZE_BUFFER_64, (pSignature->r)+SIZE_BUFFER_32, SIZE_BUFFER_32 );
	memcpy( apdu+0x05+SIZE_BUFFER_96, (pSignature->s)+SIZE_BUFFER_32, SIZE_BUFFER_32 );
	
	memcpy( apdu+0x05+SIZE_BUFFER_128, pbData, ulDataLen );

//	PrintApduToFile( 0, apdu, (BYTE)(0x05+SIZE_BUFFER_128+ulDataLen) );

	nResponseLen = sizeof( response );
    nRet = TransmitData( hDev, apdu, 0x05+SIZE_BUFFER_128+ulDataLen, response, &nResponseLen );
    if( nRet != SAR_OK )
	{
        sprintf( szLog, "ECC��ǩʧ�ܣ�������: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}
	
//	PrintApduToFile( 1, response, nResponseLen );
//
	if( (response[nResponseLen-2] != 0x90) || (response[nResponseLen-1] != 0x00) )
	{
        sprintf( szLog, "ECC��ǩʧ�ܣ�״̬��: %02x%02x \n", response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

	return SAR_OK;
}

//14--------------------NO
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_ECCExportSessionKey
* �������ܣ�ECC���ɲ������Ự��Կ
* �����б�hContainer:   [IN], �������
*           ulAlgId:      [IN], �Ự��Կ�㷨��ʶ
*           pPubKey:      [IN], �ⲿ����Ĺ�Կ�ṹ
*           pData:        [OUT], �Ự��Կ����
*           phSessionKey: [OUT], �Ự��Կ���
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_ECCExportSessionKey( HANDLE hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB* pPubKey,
									 PECCCIPHERBLOB pData, HANDLE* phSessionKey )
{
	CHAR* pszLog = ( "**********Start to execute SKF_ECCExportSessionKey ********** \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE apdu[SIZE_BUFFER_1024];
	BYTE response[SIZE_BUFFER_1024];
	BYTE sessionBuf[0x10];
	BYTE fileSFI[0x06] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE appFID[0x02] = { 0xDF, 0x00 };
    SESSIONKEY sessionKey;
	HANDLE hDev;
	DWORD nResponseLen = 0;
	LONG nRet = 0;
	sv_fEnd = FALSE;
	memset( sessionBuf, 0x00, sizeof(sessionBuf) );
	memset( apdu, 0x00, sizeof(apdu) );
	memset( response, 0x00, sizeof(response) );
	memset( szLog, 0x0, strlen(szLog) );

	WriteLogToFile( pszLog );

	//--------�����������Ϊ��
	if( hContainer == NULL )
	{
		return SAR_INVALIDHANDLEERR;
	}

	//--------ȡ16�ֽ������
	memcpy( apdu, apdu_random, 0x05 );
	apdu[4] = 0x10;  //�����ֽ�
    nResponseLen = sizeof( response );
    nRet = TransmitData( hDev, apdu, 0x05, response, &nResponseLen );
    if( nRet != SAR_OK )
	{
        sprintf( szLog, "ȡ�����ʧ�ܣ�������: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}
	
	if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
	{
		memcpy( sessionBuf, response, 0x10 );
	}
	else
	{
        sprintf( szLog, "ȡ�����ʧ�ܣ�״̬��: %02x%02x \n", response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

	//--------����SKF_ExtECCEncrypt�������
	//if( SKF_ExtECCEncrypt( hDev, pPubKey, sessionBuf, 0x10, pData) != SAR_OK )
	//	return SAR_FAIL;

	//--------���ػỰ���
	sessionKey.AlgID = ulAlgId;
 	sessionKey.KeyLen=16;
// 	sessionKey.hContainer=hContainer;
    sessionKey.hDev=hDev;
 	memcpy( sessionKey.KeyVal,sessionBuf,0x10 );	
 	//memcpy((*myKey).SessionID,(*(PCONTAINER)hContainer).SessionkeyID,2);
    *phSessionKey = &sessionKey;

	return SAR_OK;
}

//15--------------------NO
/*
* �������ƣ�SKF_ExtECCEncrypt
* �������ܣ�ECC������Կ����
* �����б�hDev:           [IN], �豸���
*           pECCPubKeyBlob: [IN], ECC��Կ���ݽṹ
*           pbPlainText:    [IN], �����ܵ���������
*           ulPlainTextLen: [OUT], �������������ݵĳ���
*           pCipherText:    [OUT], ��������
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ECCCIPHERBLOB eccCiperBlob;
ULONG SKF_ExtECCEncrypt( HANDLE hDev, ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE* pbPlainText,
							   ULONG ulPlainTextLen, PECCCIPHERBLOB pCipherText )
{
	CHAR* pszLog = ( "**********Start to execute SKF_ExtECCEncrypt ********** \n");
	CHAR szLog[SIZE_BUFFER_1024];
	//ECCCIPHERBLOB eccCiperBlob;
	BYTE apdu[SIZE_BUFFER_1024];
	BYTE response[SIZE_BUFFER_1024];
	DWORD nResponseLen = 0;
	LONG nRet = 0;
#ifdef _DEBUG
	ULONG m = 0;
#endif
	sv_fEnd = FALSE;
	memset( apdu, 0x00, sizeof(apdu) );
	memset( response, 0x00, sizeof(response) );
	memset( szLog, 0x0, strlen(szLog) );

	WriteLogToFile( pszLog );

#ifdef _DEBUG
	WriteLogToFile( TEXT("SKF_ExtECCEncrypt: \n") );
	for( m=0; m<ulPlainTextLen; m++ )
	{
		sprintf( szLog, "%02X", pbPlainText[m] );
		WriteLogToFile( szLog );
	}
	WriteLogToFile( TEXT("\n") );
#endif

#ifdef _DEBUG
	WriteLogToFile( TEXT("SKF_ExtECCEncrypt: \n") );
	for( m=0; m<64; m++ )
	{
		sprintf( szLog, "%02X", pECCPubKeyBlob->XCoordinate[m] );
		WriteLogToFile( szLog );
	}
	WriteLogToFile( TEXT("\n") );
#endif

#ifdef _DEBUG
	WriteLogToFile( TEXT("SKF_ExtECCEncrypt: \n") );
	for( m=0; m<64; m++ )
	{
		sprintf( szLog, "%02X", pECCPubKeyBlob->YCoordinate[m] );
		WriteLogToFile( szLog );
	}
	WriteLogToFile( TEXT("\n") );
#endif

	//--------��֯APDU
	memcpy( apdu, apdu_eccEncrypt, 0x05 );
	apdu[4] = (BYTE)(SIZE_BUFFER_64+(BYTE)ulPlainTextLen);  //�����ֽ�

	memcpy( apdu+0x05, (pECCPubKeyBlob->XCoordinate) +SIZE_BUFFER_32 , SIZE_BUFFER_32 );
	memcpy( apdu+0x05+SIZE_BUFFER_32, (pECCPubKeyBlob->YCoordinate) +SIZE_BUFFER_32 , SIZE_BUFFER_32 );
	memcpy( apdu+0x05+SIZE_BUFFER_64, pbPlainText, ulPlainTextLen );
    nResponseLen = sizeof( response );
    nRet = TransmitData( hDev, apdu, 0x05+SIZE_BUFFER_64+(BYTE)ulPlainTextLen, response, &nResponseLen );
    if( nRet != SAR_OK )
	{
        sprintf( szLog, "ECC������Կ����ʧ�ܣ�������: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}
	
	if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
	{
		memcpy( eccCiperBlob.XCoordinate+SIZE_BUFFER_32, response, SIZE_BUFFER_32 );
		memcpy( eccCiperBlob.YCoordinate+SIZE_BUFFER_32, response+SIZE_BUFFER_32, SIZE_BUFFER_32 );

		memcpy( eccCiperBlob.HASH, response+SIZE_BUFFER_64, SIZE_BUFFER_32 );
		
		eccCiperBlob.CipherLen = ulPlainTextLen;
		memcpy( eccCiperBlob.Cipher, response+SIZE_BUFFER_96, ulPlainTextLen );
	}
	else
	{
		sprintf( szLog, "ECC������Կ����ʧ�ܣ�״̬��: %02x%02x \n", response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;	
	}

	memcpy(pCipherText, &eccCiperBlob, sizeof(ECCCIPHERBLOB));
	return SAR_OK;
}

//16--------------------NO
ULONG SKF_ExtECCDecrypt( HANDLE hDev, ECCPRIVATEKEYBLOB*  pECCPriKeyBlob, PECCCIPHERBLOB pCipherText,
							   BYTE* pbPlainText, ULONG* pulPlainTextLen )
{
	CHAR* pszLog = ("**********Start to execute SKF_ExtECCDecrypt ********** \n");

	WriteLogToFile( pszLog );

	return SAR_OK;
}

//17--------------------NO
ULONG SKF_ExtECCSign( HANDLE hDev, ECCPRIVATEKEYBLOB*  pECCPriKeyBlob, BYTE* pbData, ULONG ulDataLen,
							 PECCSIGNATUREBLOB pSignature )
{
	CHAR* pszLog = ( "**********Start to execute SKF_ExtECCSign ********** \n");

	WriteLogToFile( pszLog );

	return SAR_OK;
}

//18--------------------NO
ULONG SKF_ExtECCVerify( HANDLE hDev, ECCPUBLICKEYBLOB*  pECCPubKeyBlob,BYTE* pbData, ULONG ulDataLen,
							  PECCSIGNATUREBLOB pSignature )
{
	CHAR* pszLog = ("**********Start to execute SKF_ExtECCVerify ********** \n");

	WriteLogToFile( pszLog );

	return SAR_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_GenECCKeyPairEx
* �������ܣ�����ECCǩ����Կ�Բ������Կ��˽Կ
* �����б�hContainer:  [IN], �������
*           ulAlgId:     [IN], �㷨��ʶ��ֻ֧��SGD_SM2_1�㷨
*           pPubKeyBlob:       [OUT], ����ECC��Կ���ݽṹ
*           pPrivKeyBlob:       [OUT], ����ECC˽Կ���ݽṹ
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_GenECCKeyPairEx( HANDLE hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB* pPubKeyBlob,
                                                 ECCPRIVATEKEYBLOB *pPrivKeyBlob )
{
	CHAR* pszLog = ( "**********Start to execute SKF_GenECCKeyPairEx ********** \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE response[SIZE_BUFFER_1024];
	BYTE fileSFI[0x06] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE apdu[SIZE_BUFFER_1024];
	ECCPUBLICKEYBLOB eccPubKeyBlob = {0};
	ECCPRIVATEKEYBLOB eccPriKeyBlob = {0};
	PCONTAINERINFO pContainer;
	HANDLE hDev;
	DWORD nResponseLen = 0;
	LONG nRet = 0;
	sv_fEnd = FALSE;
	
    memset( szLog, 0x0, strlen(szLog) );
	memset( apdu, 0x00, sizeof(apdu) );
	memset( response, 0x00, sizeof(response) );

	WriteLogToFile( pszLog );

	//--------�����������Ϊ��
	if( hContainer == NULL )
	{
		return SAR_INVALIDHANDLEERR;
	}

	//--------�㷨��ʶ��ֻ֧��SGD_SM2_1�㷨
	switch( ulAlgId )
	{
	    case SGD_SM2_1:
		    break;
	    default:
		    return SAR_NOTSUPPORTYETERR;
	}

	//--------��֯APDU
	memcpy( apdu, apdu_eccGenKeyPair, 0x05 );
	apdu[2] = 0xEB;
	apdu[3] = fileSFI[4];
	apdu[4] = 0x60;  //0x40��Կ�����ֽ�0x20 ˽Կ�����ֽ�

//	PrintApduToFile( 0, apdu, 0x05 );

	nResponseLen = sizeof( response );
    nRet = TransmitData( hDev, apdu, 0x05, response, &nResponseLen );
    if( nRet != SAR_OK )
	{
        sprintf( szLog, "����ECC��Կ��ʧ�ܣ�������: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}
	
//	PrintApduToFile( 1, response, nResponseLen );

	if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
	{
#ifdef _DEBUG
		BYTE m = 0;
		WriteLogToFile( TEXT("SKF_GenECCKeyPairEx: \n") );
		for( m=0; m<nResponseLen-2; m++ )
		{
			sprintf( szLog, "%02X", response[m] );
			WriteLogToFile( szLog );
		}
		WriteLogToFile( TEXT("\n") );
#endif
		eccPubKeyBlob.BitLen = 256;
		memset( eccPubKeyBlob.XCoordinate, 0x00, sizeof(eccPubKeyBlob.XCoordinate) );
		memset( eccPubKeyBlob.YCoordinate, 0x00, sizeof(eccPubKeyBlob.YCoordinate) );
		memcpy( eccPubKeyBlob.XCoordinate+SIZE_BUFFER_32, response, SIZE_BUFFER_32 );
		memcpy( eccPubKeyBlob.YCoordinate+SIZE_BUFFER_32, response+SIZE_BUFFER_32, SIZE_BUFFER_32 );

		eccPriKeyBlob.BitLen = 256;
		memcpy( eccPriKeyBlob.PrivateKey+SIZE_BUFFER_32, response+SIZE_BUFFER_64, SIZE_BUFFER_32 );
		
	
		*pPubKeyBlob = eccPubKeyBlob;
		*pPrivKeyBlob = eccPriKeyBlob;
	}
	else
	{
        sprintf( szLog, "����ECC��Կ��ʧ�ܣ�״̬��: %02x%02x \n", response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;	
	}
    
	return SAR_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_ImportECCKeyPair2
* �������ܣ�����ECC����ǩ����Կ�Բ��ϳ�ʵ��ǩ����Կ
* �����б�hContainer:            [IN], �������
*           pEnvelopedKeyBlob:     [IN], �ܱ����ļ�����Կ��
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_ImportECCKeyPair2( HANDLE hContainer, PENVELOPEDKEYBLOB pEnvelopedKeyBlob )
{
	CHAR* pszLog = ( "**********Start to execute SKF_ImportECCKeyPair ********** \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE appFID[2] = { 0xDF, 0x00 };
	BYTE fileSFI[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE bSFI = 0x00;
	BYTE apdu[SIZE_BUFFER_1024];
	BYTE response[SIZE_BUFFER_1024];
	BYTE tempbuf[SIZE_BUFFER_1024];
	ULONG length = 0;
	//ENVELOPEDKEYBLOB envelopedKeyBlob;
	INT nDivider = 0;
	INT nRemainder = 0;
	INT nIndex = 0;
	ULONG dwOffset = 0;
	HANDLE hDev;
	DWORD nResponseLen = 0;
	LONG nRet = 0;
	//--------�����������Ϊ��
	if( hContainer == NULL )
	{
		return SAR_INVALIDHANDLEERR;
	}

	WriteLogToFile( pszLog );
	sv_fEnd = FALSE;
	memset( apdu, 0x00, sizeof(apdu) );
	memset( response, 0x00, sizeof(response) );
	memset( szLog, 0x0, strlen(szLog) );

	//--------ѡ��ADF��ͨ��FIDѡ��
	if( SV_SelectDFByFID(hDev, appFID, "ѡ��ADF") != SAR_OK )
		return SAR_FAIL;

	//--------ʹ��ǩ����Կ�Խ��ܶԳ���Կ����
	memcpy( apdu, apdu_eccDecrypt, 0x05 );
	apdu[2] = 0xEB;
	apdu[3] = fileSFI[4];
	apdu[4] = (BYTE)(pEnvelopedKeyBlob->ECCCipherBlob.CipherLen + SIZE_BUFFER_96);  //�����ֽ�

	memcpy( apdu+0x05, (pEnvelopedKeyBlob->ECCCipherBlob.XCoordinate) + SIZE_BUFFER_32, SIZE_BUFFER_32 );
	memcpy( apdu+0x05+SIZE_BUFFER_32, (pEnvelopedKeyBlob->ECCCipherBlob.YCoordinate) + SIZE_BUFFER_32, SIZE_BUFFER_32 );
	memcpy( apdu+0x05+SIZE_BUFFER_64, (pEnvelopedKeyBlob->ECCCipherBlob.HASH), SIZE_BUFFER_32 );
	memcpy( apdu+0x05+SIZE_BUFFER_96, pEnvelopedKeyBlob->ECCCipherBlob.Cipher, pEnvelopedKeyBlob->ECCCipherBlob.CipherLen);

    nResponseLen = sizeof( response );
    nRet = TransmitData( hDev, apdu, (BYTE)(0x05+(BYTE)pEnvelopedKeyBlob->ECCCipherBlob.CipherLen + SIZE_BUFFER_96), response, &nResponseLen );
    if( nRet != SAR_OK )
	{
        sprintf( szLog, "ECC����ʧ�ܣ�������: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}
	
	if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
	{
		memcpy( tempbuf, response, nResponseLen-2 );
		length = nResponseLen-2;
	}
	else
	{
        sprintf( szLog, "ECC����ʧ�ܣ�״̬��: %02x%02x \n", response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

	if(length != 16)
	{
		return SAR_INDATALENERR;
	}

	//--------ʹ�öԳ���Կ����˽Կ����
	 //--------�����㷨���ͣ����üӽ��ܺ���
	switch( pEnvelopedKeyBlob->ulSymmAlgID)
	{
	    case SGD_SM1_ECB:  //SM1�㷨ECB����ģʽ
		    memcpy( apdu, apdu_decrypt_sm1_ecb, 0x05 );
			break;
	    case SGD_SSF33_ECB:  //SSF33�㷨ECB����ģʽ
		    memcpy( apdu, apdu_decrypt_ssf33_ecb, 0x05 );
			break;
	    case SGD_SM4_ECB:  //SMS4�㷨ECB����ģʽ
		    memcpy( apdu, apdu_decrypt_sm4_ecb, 0x05 );
			break;
	    default: 
		    return SAR_NOTSUPPORTYETERR;
	}
	apdu[4] = (BYTE)(0x10 + SIZE_BUFFER_32);

	memcpy( apdu+5, tempbuf, length );
	memcpy( apdu+21, pEnvelopedKeyBlob->cbEncryptedPriKey + SIZE_BUFFER_32, SIZE_BUFFER_32 );
	
//	PrintApduToFile( 0, apdu, 21+SIZE_BUFFER_32 );

    nResponseLen = sizeof( response );
    nRet = TransmitData( hDev, apdu, 21+SIZE_BUFFER_32, response, &nResponseLen );
    if( nRet != SAR_OK )
	{
        sprintf( szLog, "����˽Կʧ�ܣ�������: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}

	if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
	{
		memcpy( tempbuf, response, nResponseLen-2 );
	}
	else
	{
        sprintf( szLog, "����˽Կʧ�ܣ�״̬��: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

	//--------����ǩ����Կ��
	memcpy( apdu, apdu_import_sm2_keypair, 0x05 );
	apdu[2] = 0xEB;
	apdu[3] = fileSFI[4];

	memcpy( apdu+5, pEnvelopedKeyBlob->PubKey.XCoordinate + SIZE_BUFFER_32, SIZE_BUFFER_32 );
	memcpy( apdu+5+SIZE_BUFFER_32, pEnvelopedKeyBlob->PubKey.YCoordinate + SIZE_BUFFER_32, SIZE_BUFFER_32 );
	memcpy( apdu+5+SIZE_BUFFER_64, tempbuf, SIZE_BUFFER_32 );

//	PrintApduToFile( 0, apdu, 0x05+SIZE_BUFFER_96 );

    nResponseLen = sizeof( response );
    nRet = TransmitData( hDev, apdu, 0x05+SIZE_BUFFER_96, response, &nResponseLen );
    if( nRet != SAR_OK )
	{
        sprintf( szLog, "����SM2ǩ����Կ��ʧ�ܣ�������: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}

	if( (response[nResponseLen-2] != 0x90) && (response[nResponseLen-1] != 0x00) )
	{
        sprintf( szLog, "����SM2ǩ����Կ��ʧ�ܣ�״̬��: %02x%02x \n", response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

	return SAR_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_ECCDecrypt
* �������ܣ�ECC�ڲ�˽Կ����
* �����б�hContainer:            [IN], �������
*				pCipherText:		    [IN] �����ܵ��������ݡ�
*				pbPlainText:		    [OUT] ������������,����ò���ΪNULL������pulPlainTextLen �����������ݵ�ʵ�ʳ��ȡ�
*				pulPlainTextLen:	    [IN��OUT] ����ʱ��ʾpbPlainText �������ĳ��ȣ����ʱ��ʾ�������ݵ�ʵ�ʳ��ȡ�
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_ECCDecrypt( HANDLE hContainer, PECCCIPHERBLOB pCipherText, BYTE* pbPlainText, ULONG* pulPlainTextLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_ECCDecrypt ********** \n");
	CHAR szLog[SIZE_BUFFER_1024];
	//ECCCIPHERBLOB eccCiperBlob;
	BYTE fileSFI[0x06] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	PCONTAINERINFO pContainer;
	BYTE apdu[SIZE_BUFFER_1024];
	BYTE response[SIZE_BUFFER_1024];
	HANDLE hDev;
	DWORD nResponseLen = 0;
	LONG nRet = 0;
#ifdef _DEBUG
	ULONG m = 0;
#endif
	sv_fEnd = FALSE;
	memset( apdu, 0x00, sizeof(apdu) );
	memset( response, 0x00, sizeof(response) );
	memset( szLog, 0x0, strlen(szLog) );

	WriteLogToFile( pszLog );

	//--------�����������Ϊ��
	if( hContainer == NULL )
	{
		return SAR_INVALIDHANDLEERR;
	}

	if( pCipherText->CipherLen > SIZE_BUFFER_128 ) 
	{
		return SAR_INDATALENERR;
	}

	//--------��֯APDU
	memcpy( apdu, apdu_eccDecrypt, 0x05 );
	apdu[2] = 0xEA;
	apdu[3] = fileSFI[3];
	apdu[4] = (BYTE)((BYTE)pCipherText->CipherLen + SIZE_BUFFER_96);  //�����ֽ�

	memcpy( apdu+0x05, (pCipherText->XCoordinate) + SIZE_BUFFER_32, SIZE_BUFFER_32 );
	memcpy( apdu+0x05+SIZE_BUFFER_32, (pCipherText->YCoordinate) + SIZE_BUFFER_32, SIZE_BUFFER_32 );
	memcpy( apdu+0x05+SIZE_BUFFER_64, (pCipherText->HASH), SIZE_BUFFER_32 );
	memcpy( apdu+0x05+SIZE_BUFFER_96, pCipherText->Cipher, pCipherText->CipherLen);

    nResponseLen = sizeof( response );
    nRet = TransmitData( hDev, apdu, (BYTE)(0x05+(BYTE)pCipherText->CipherLen + SIZE_BUFFER_96), response, &nResponseLen );
    if( nRet != SAR_OK )
	{
        sprintf( szLog, "ECC����ʧ�ܣ�������: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}
	
	if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
	{
		if (pbPlainText != NULL)
		{
			memcpy( pbPlainText, response, nResponseLen-2 );
		}
		*pulPlainTextLen = nResponseLen-2;
	}
	else
	{
        sprintf( szLog, "ECC����ʧ�ܣ�״̬��: %02x%02x \n", response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

	return SAR_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_ECCMultAdd
* �������ܣ�ECC ��˼����㺯��
* �����б�hContainer:            [IN], �������
*					k:			    [IN] ˽Կ��ʶ��
*													1��ʹ���ڲ�����˽Կ���档
*													2��ʹ���ڲ�ǩ��˽Կ���档
*													0��k ��ʹ�á�
*					e:			    [IN] ����˽Կ����e =NULL ʱ��e ��ʹ�á�
*					A :			    [IN] SM2 ��Բ���ߵ㣬��A =NULL ʱ��ʹ���ڲ�SM2 ����G����A��
*					B:			    [IN] SM2 ��Բ���ߵ㣬��B =NULL ʱ������������㡣
*					C:			    [OUT] SM2 ��Բ���ߵ㣬 C = (dk + e)A + B
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_ECCMultAdd(HANDLE hContainer, unsigned int k, ECCPRIVATEKEYBLOB *e,
                                                 ECCPUBLICKEYBLOB *A, ECCPUBLICKEYBLOB * B, ECCPUBLICKEYBLOB * C)

{
	CHAR* pszLog = ( "**********Start to execute SKF_ECCMultAdd ********** \n");
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE fileSFI[0x06] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	PCONTAINERINFO pContainer;
	BYTE apdu[SIZE_BUFFER_1024];
	BYTE response[SIZE_BUFFER_1024];
	BYTE Param1 = 0;
	BYTE Param2 = 0;
	BYTE offset = 5;
	HANDLE hDev;
	DWORD nResponseLen = 0;
	LONG nRet = 0;
	sv_fEnd = FALSE;
	memset( apdu, 0x00, sizeof(apdu) );
	memset( response, 0x00, sizeof(response) );
	memset( szLog, 0x0, strlen(szLog) );

	WriteLogToFile( pszLog );

	//--------�����������Ϊ��
	if( hContainer == NULL )
	{
		return SAR_INVALIDHANDLEERR;
	}

	if(( k < 0) || (k > 2))
	{
		return SAR_INDATAERR;
	}

	if(k != 0)
	{
		Param1 = 0x80;
		if(k == 1)
		{
			Param1 |= fileSFI[3];  //������Կ��
		}
		else 
		{
			Param1 |= fileSFI[4];  //ǩ����Կ��
		}
	}
	if(e != NULL)
	{
		Param2 |= PARAM_E_EXIST;
		memcpy( apdu+offset, e->PrivateKey + SIZE_BUFFER_32, SIZE_BUFFER_32 );
		offset += SIZE_BUFFER_32;
	}
	if(A != NULL)
	{
		Param2 |= PARAM_A_EXIST;
		memcpy( apdu+offset, A->XCoordinate + SIZE_BUFFER_32, SIZE_BUFFER_32 );
		memcpy( apdu+offset+SIZE_BUFFER_32, A->YCoordinate + SIZE_BUFFER_32, SIZE_BUFFER_32 );
		offset += SIZE_BUFFER_64;
	}
	if(B != NULL)
	{
		Param2 |= PARAM_B_EXIST;
		memcpy( apdu+offset, B->XCoordinate + SIZE_BUFFER_32, SIZE_BUFFER_32 );
		memcpy( apdu+offset+SIZE_BUFFER_32, B->YCoordinate + SIZE_BUFFER_32, SIZE_BUFFER_32 );
		offset += SIZE_BUFFER_64;
	}


	//--------��֯APDU
	memcpy( apdu, apdu_point_multadd, 0x05 );
	apdu[2] = Param1;
	apdu[3] = Param2;
	apdu[4] = (BYTE)(offset-5);  //�����ֽ�

    nResponseLen = sizeof( response );
    nRet = TransmitData( hDev, apdu, (BYTE)offset, response, &nResponseLen );
    if( nRet != SAR_OK )
	{
        sprintf( szLog, "��˼�����ʧ�ܣ�������: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}
	
	if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
	{
		C->BitLen = 256;
		memcpy( (C->XCoordinate)+SIZE_BUFFER_32, response, SIZE_BUFFER_32 );
		memcpy( (C->YCoordinate)+SIZE_BUFFER_32, response+SIZE_BUFFER_32, SIZE_BUFFER_32 );
	}
	else
	{
        sprintf( szLog, "��˼�����ʧ�ܣ�״̬��: %02x%02x \n", response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

	return SAR_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_ECCModMultAdd
* �������ܣ�ECC ģ�˼����㺯��
* �����б�hContainer:            [IN], �������
*				k:				    [IN] ������
*				a:				    [IN] ������
*				b:				    [IN] ������
*				c:				    [OUT] ������ c = ka + b mod n
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_ECCModMultAdd(HANDLE hContainer, ECCPRIVATEKEYBLOB *k, ECCPRIVATEKEYBLOB * a,
                                                 ECCPRIVATEKEYBLOB * b, ECCPRIVATEKEYBLOB * c)

{
	CHAR* pszLog = ( "**********Start to execute SKF_ECCModMultAdd ********** \n");
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE fileSFI[0x06] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	PCONTAINERINFO pContainer;
	BYTE apdu[SIZE_BUFFER_1024];
	BYTE response[SIZE_BUFFER_1024];
	BYTE Param1 = 0;
	BYTE Param2 = 0;
	BYTE offset = 5;
	HANDLE hDev;
	DWORD nResponseLen = 0;
	LONG nRet = 0;
	sv_fEnd = FALSE;
	memset( apdu, 0x00, sizeof(apdu) );
	memset( response, 0x00, sizeof(response) );
	memset( szLog, 0x0, strlen(szLog) );

	WriteLogToFile( pszLog );

	//--------�����������Ϊ��
	if( hContainer == NULL )
	{
		return SAR_INVALIDHANDLEERR;
	}

	//--------��֯APDU
	memcpy( apdu, apdu_mod_multadd, 0x05 );

	if(k != NULL)
	{
		Param1 = 0x01;
		memcpy( apdu+offset, (k->PrivateKey)+SIZE_BUFFER_32, SIZE_BUFFER_32 );
		offset += SIZE_BUFFER_32;
	}
	
	memcpy( apdu+offset, (a->PrivateKey)+SIZE_BUFFER_32, SIZE_BUFFER_32 );
	offset += SIZE_BUFFER_32;
	
	if(b != NULL)
	{
		Param2 = 0x01;
		memcpy( apdu+offset, (b->PrivateKey)+SIZE_BUFFER_32, SIZE_BUFFER_32 );
		offset += SIZE_BUFFER_32;
	}

	apdu[2] = Param1;
	apdu[3] = Param2;
	apdu[4] = (BYTE)(offset-5);  //�����ֽ�

    nResponseLen = sizeof( response );
    nRet = TransmitData( hDev, apdu, (BYTE)offset, response, &nResponseLen );
    if( nRet != SAR_OK )
	{
        sprintf( szLog, "ģ�˼�����ʧ�ܣ�������: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}
	
	if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
	{
		c->BitLen = 256;
		memcpy( (c->PrivateKey)+SIZE_BUFFER_32, response, SIZE_BUFFER_32 );
	}
	else
	{
        sprintf( szLog, "ģ�˼�����ʧ�ܣ�״̬��: %02x%02x \n", response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

	return SAR_OK;
}



//19--------------------NO
ULONG SKF_GenerateAgreementDataWithECC( HANDLE hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB* pTempECCPubKeyBlob,
							BYTE* pbID, ULONG ulIDLen, HANDLE* phAgreementHandle )
{
	CHAR* pszLog = ( "**********Start to execute SKF_GenerateAgreementDataWithECC ********** \n");

	WriteLogToFile( pszLog );

	return SAR_OK;
}

//20--------------------NO
ULONG SKF_GenerateAgreementDataAndKeyWithECC( HANDLE hContainer, ULONG ulAlgId,
							ECCPUBLICKEYBLOB* pSponsorECCPubKeyBlob, ECCPUBLICKEYBLOB* pSponsorTempECCPubKeyBlob,
							ECCPUBLICKEYBLOB* pTempECCPubKeyBlob, BYTE* pbID, ULONG ulIDLen, BYTE* pbSponsorID,
							ULONG ulSponsorIDLen, HANDLE* phKeyHandle ) {
	CHAR* pszLog = ("**********Start to execute SKF_GenerateAgreementDataAndKeyWithECC ********** \n");

	WriteLogToFile( pszLog );

	// 1st command  80C80000 08 0107+B001+B101+0100
	unsigned char *DataTobeSend = apdu_genDataKeyEcc;
	unsigned long send_len = 0;
	unsigned char check_sum = 0;

	int ret;
	unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	send_len = sizeof(DataTobeSend);

	unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	unsigned long recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
	memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);

	//copy the raw data
	memcpy(tmpBuffer_wr, (unsigned char *)DataTobeSend, send_len);

    //fill the checksum byte
    check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

	//fill the data ...........................................
	*(tmpBuffer_wr+send_len) = check_sum;
	send_len = send_len + 1;

	int repeat_times = 10;
	for (int i = 0; i < repeat_times; i++) {
		if (repeat_times > 1)
			usleep(500 * 1000);  //gap between each cycle

		memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
		recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
		ret = TransmitData(hContainer, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
		if (ret < 0) {
			LOGE("TransmitData return failed, ret %d.", ret);
			ret = -1;
			continue;
		}
		if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
			break;
		}
	}
	// 2nd command 80CE0100 02 A001
	DataTobeSend = (unsigned char) malloc(0x07);
	memset(DataTobeSend, '\0', 0x07);
	memcpy(DataTobeSend, apdu_CE_01, 0x04);
	memcpy(DataTobeSend + 0x04, apdu_02, 0x01);
	memcpy(DataTobeSend + 0x05, apdu_A001, 0x02);
	memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	send_len = sizeof(DataTobeSend);
	//copy the raw data
	memcpy(tmpBuffer_wr, (unsigned char *)DataTobeSend, send_len);
	for (int i = 0; i < repeat_times; i++) {
		if (repeat_times > 1)
			usleep(500 * 1000);  //gap between each cycle

		memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
		recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
		ret = TransmitData(hContainer, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
		if (ret < 0) {
			LOGE("TransmitData return failed, ret %d.", ret);
			ret = -1;
			continue;
		}
		if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
			// get the public key
			break;
		}
	}

	free(DataTobeSend);
	free(tmpBuffer_wr);
	free(tmpBuffer_rd);

	return SAR_OK;
}

//21--------------------NO
ULONG SKF_GenerateKeyWithECC( HANDLE hAgreementHandle, ECCPUBLICKEYBLOB* pECCPubKeyBlob,
									ECCPUBLICKEYBLOB* pTempECCPubKeyBlob, BYTE* pbID,
									ULONG ulIDLen, HANDLE* phKeyHandle )
{
	CHAR* pszLog = ( "**********Start to execute SKF_GenerateKeyWithECC ********** \n" );

	WriteLogToFile( pszLog );

	return SAR_OK;
}

//22
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_ExportPublicKey
* �������ܣ�������Կ
* �����б�hContainer: [IN], �������
*           bSignFlag:  [IN], TRUE��ʾ����ǩ����Կ��FALSE��ʾ�������ܹ�Կ
*           pbBlob:     [OUT], ָ��RSA��Կ�ṹ��ECC��Կ�ṹ��������ΪNULL������pBlob�ĳ���
*           pulBlobLen: [IN/OUT], �����ʾpbBlob�������Ĵ�С�������ʾ������Կ�ṹ�Ĵ�С
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_ExportPublicKey( HANDLE hDev, BYTE* pbBlob, ULONG* pulBlobLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_ExportPublicKey ********** \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE apdu[0x07];
    DWORD nResponseLen = 0;
	sv_fEnd = FALSE;
	memset( apdu, 0x00, sizeof(apdu) );
	memset( szLog, 0x0, strlen(szLog) );
	
	WriteLogToFile( pszLog );

    if( hDev < 0 ) {
        return SAR_INVALIDHANDLEERR;
    }
    if (pbBlob == NULL) {
        LOGE("SKF_ExportPublicKey param is null.");
        return -1;
    }
    memcpy(apdu, (unsigned char *)apdu_CE_01, 0x05);
    memcpy(apdu + 0x05, apdu_A002, 0x02);
    unsigned long send_len = strlen(apdu);
    unsigned char check_sum = 0;
    int ret;
    unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    //copy the raw data
    memcpy(tmpBuffer_wr, (unsigned char *)apdu, send_len);

    unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    unsigned long recv_len = 0;

    //fill the checksum byte
    check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

    //fill the data ...........................................
    *(tmpBuffer_wr+send_len) = check_sum;
    send_len = send_len + 1;

    int repeat_times = 10;
    for (int i = 0; i < repeat_times; i++) {
        if (repeat_times > 1)
            usleep(500 * 1000);  //gap between each cycle

        memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
        recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
        ret = TransmitData(trans_dev_id, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
        if (ret < 0) {
            sprintf( szLog, "SKF_ExportPublicKey failed, error code: %d \n", ret );
            WriteLogToFile( szLog );
            LOGE("SKF_ExportPublicKey return failed, ret %d.", ret);
            ret = -1;
            continue;
        }
        if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
            // get data if need
            memcpy(pbBlob, tmpBuffer_rd, recv_len - 2);
            break;
        } else {
            sprintf( szLog, "SKF_ExportPublicKey failed, status code: %02X%02X \n", tmpBuffer_rd[nResponseLen-2], tmpBuffer_rd[nResponseLen-1] );
            WriteLogToFile( szLog );
            LOGE("SKF_ExportPublicKey failed, status code: %02X%02X \n", tmpBuffer_rd[nResponseLen-2], tmpBuffer_rd[nResponseLen-1]);
        }
    }

    free(tmpBuffer_wr);
    free(tmpBuffer_rd);
    if (ret < 0) {
        return SAR_FAIL;
    }

	return SAR_OK;
}
//23
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_ImportSessionKey
* �������ܣ�����Ự��Կ
* �����б�hContainer:   [IN], �������
*           ulAlgId:      [IN], �Ự��Կ�㷨��ʶ
*           pbWrapedData: [IN], ������ĻỰ��Կ���ģ�������ΪECCʱ���˲���ΪECCCIPHERBLOB; ��ΪRSAʱ���˲���ΪRSA��Կ���ܺ������
*           ulWrapedLen:  [IN], �Ự��Կ���ĳ���
*           phKey:        [OUT], �Ự��Կ���
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_ImportSessionKey( HANDLE hContainer, ULONG ulAlgId, BYTE* pbWrapedData,
								  ULONG ulWrapedLen, HANDLE* phKey )
{
	CHAR* pszLog = ( "**********Start to execute SKF_ImportSessionKey ********** \n");

	WriteLogToFile( pszLog );

	return SAR_OK;
}

//24
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_SetSymmKey
* �������ܣ����ĵ���Ự��Կ�����豸HANDLE, �㷨ID����Կ���ȣ���Կֵ���PSESSIONKEY�ṹ��Ϊ�ӽ���ʹ��
* �����б�hDev:    [IN], �豸���
*           pbKey:   [IN], ָ��Ự��Կֵ�û�����
*           ulAlgID: [IN], �Ự��Կ�㷨��ʶ
*           phKey:   [OUT], �Ự��Կ�ṹ���
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_SetSymmKey( HANDLE hDev,  BYTE *pbKey, ULONG ulAlgID, HANDLE *phKey )
{
	CHAR* pszLog = ( "**********Start to execute SKF_SetSymmKey ********** \n" );
    ULONG keyLen = 0;
 
	sv_fEnd = FALSE;
	WriteLogToFile( pszLog );

	if( hDev == NULL )
		return SAR_INVALIDHANDLEERR;	

	switch( ulAlgID )
	{
	    case SGD_SM1_ECB:
			break;
		case SGD_SM1_CBC:
			break;
		case SGD_SSF33_ECB:
			break;
		case SGD_SSF33_CBC:
			break;
		case SGD_SM4_ECB:
			break;
		case SGD_SM4_CBC:
			break;
		default:
			return SAR_NOTSUPPORTYETERR;
	}

	keyLen = 16;
	SESSIONKEY *pKey;

	(* pKey).AlgID = ulAlgID;        //����㷨ID
	(* pKey).KeyLen = (BYTE)keyLen;  //�����Կ���ȣ�Ϊ�̶�ֵ0x10 bytes
	(* pKey).hDev = hDev;            //����豸���

	memset( ( * pKey).KeyVal, 0x00, sizeof((* pKey).KeyVal) );
	memcpy( (* pKey).KeyVal, pbKey, keyLen); //�����Կ���䳤��ΪkeyLen

	*phKey = pKey;
	
	return SAR_OK;
}

//25
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_EncryptInit
* �������ܣ����ܳ�ʼ��
* �����б�hKey:  [IN], ��Կ���
*           encryptParam: [IN], ���������㷨��ز�������ʼ���������ȣ���䷽��������ֵ����
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ:������
*/
ULONG SKF_EncryptInit( HANDLE hKey, BLOCKCIPHERPARAM encryptParam )
{	
 	CHAR* pszLog = ( "**********Start to execute SKF_EncryptInit ********** \n" );
	BYTE blockLen = 0x00;

	sv_fEnd = FALSE;
    WriteLogToFile( pszLog );

	if( hKey == NULL )
	    return SAR_INVALIDHANDLEERR;

	(*(PSESSIONKEY)hKey).Params = encryptParam;

	(*((PSESSIONKEY)hKey)).MsgLen=0;

	return SAR_OK;

}

//26
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_Encrypt
* �������ܣ�����
* �����б�hKey:            [IN], ��Կ���
*           pbData:          [IN], ����������
*           ulDataLen:       [IN], ���������ݳ���
*           pbEncryptedData: [OUT], ���Ļ�������ΪNULLʱ��pulEncryptedLen���س���
*           pulEncryptedLen: [IN/OUT], ���Ļ�������С������ʵ�ʳ���
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/

ULONG SKF_Encrypt( HANDLE hKey, BYTE *pbData, ULONG ulDataLen,
										  BYTE *pbEncryptedData, ULONG * pulEncryptedLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_Encrypt ********** \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE apdu[SIZE_BUFFER_1024];
	BYTE response[SIZE_BUFFER_1024];
	ULONG ulAlgID = 0;
	PSESSIONKEY sessionKey;
	HANDLE hDev;
	DWORD nResponseLen = 0;
	LONG nRet = 0;

#ifdef _DEBUG
    ULONG m = 0;
#endif
	sv_fEnd = FALSE;
	memset( szLog, 0x0, strlen(szLog) );
	memset( apdu, 0x00, sizeof(apdu) );
	memset( response, 0x00, sizeof(response) );
	
	WriteLogToFile( pszLog );

	//--------�жϾ���Ƿ�Ϊ��
	if( hKey == NULL )
	{
        sprintf( szLog, "����ʧ�ܣ���Կ���Ϊ�գ�\n" );
		WriteLogToFile( szLog );
		return SAR_INVALIDHANDLEERR;
	}
    
	//--------�������ݲ���Ϊ��
	if( pbData == NULL )
	{
		sprintf( szLog, "�����ܵ��������ݴ��� \n" );
		WriteLogToFile( szLog );
		return SAR_INDATAERR;
	}

#ifdef _DEBUG
	WriteLogToFile( TEXT("SKF_Encrypt, plaintText: \n") );
	sprintf( szLog, "%d \n", ulDataLen );
	WriteLogToFile( szLog );
	for( m=0; m<ulDataLen; m++ )
	{
		sprintf( szLog, "%02X", pbData[m] );
		WriteLogToFile( szLog );
	}
	WriteLogToFile( TEXT("\n") );
#endif

	//--------�ж��㷨���ͣ�ָ����ӦAPDU
	sessionKey = ((PSESSIONKEY)hKey);
	ulAlgID = sessionKey -> AlgID;
	hDev    = sessionKey -> hDev;

    //--------�����㷨���ͣ����üӽ��ܺ���
	switch( ulAlgID )
	{
	    case SGD_SM1_ECB:  //SM1�㷨ECB����ģʽ
		    memcpy( sv_APDU, apdu_encrypt_sm1_ecb, 0x05 );
		    return ( Algo_Group_ECB( hKey, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen ) );
	    case SGD_SM1_CBC:  //SM1�㷨CBC����ģʽ
		    memcpy( sv_APDU, apdu_encrypt_sm1_cbc, 0x05 );
			return ( Algo_Group_CBC( hKey, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen ) );
        case SGD_SM1_CFB:  //SM1�㷨CFB����ģʽ
		    return SAR_NOTSUPPORTYETERR;
        case SGD_SM1_OFB:  //SM1�㷨OFB����ģʽ
		    return SAR_NOTSUPPORTYETERR;
        case SGD_SM1_MAC:  //SM1�㷨MAC����
		    return SAR_NOTSUPPORTYETERR;
	    case SGD_SSF33_ECB:  //SSF33�㷨ECB����ģʽ
		    memcpy( sv_APDU, apdu_encrypt_ssf33_ecb, 0x05 );
			return ( Algo_Group_ECB( hKey, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen ) );
	    case SGD_SSF33_CBC:  //SSF33�㷨CBC����ģʽ
		    memcpy( sv_APDU, apdu_encrypt_ssf33_cbc, 0x05 );
		    return ( Algo_Group_CBC( hKey, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen ) );
	    case SGD_SSF33_CFB:  //SSF33�㷨CFB����ģʽ
		    return SAR_NOTSUPPORTYETERR;
	    case SGD_SSF33_OFB:  //SSF33�㷨OFB����ģʽ
		    return SAR_NOTSUPPORTYETERR;
	    case SGD_SSF33_MAC:  //SSF33�㷨MAC����
		    return SAR_NOTSUPPORTYETERR;
	    case SGD_SM4_ECB:  //SMS4�㷨ECB����ģʽ
		    memcpy( sv_APDU, apdu_encrypt_sm4_ecb, 0x05 );
		    return ( Algo_Group_ECB( hKey, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen ) );
	    case SGD_SM4_CBC:  ////SMS4�㷨CBC����ģʽ
		    memcpy( sv_APDU, apdu_encrypt_sm4_cbc, 0x05 );
		    return ( Algo_Group_CBC( hKey, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen ) );
	    case SGD_SM4_CFB:  //SMS4�㷨CFB����ģʽ
		    return SAR_NOTSUPPORTYETERR;
	    case SGD_SM4_OFB:  //SMS4�㷨OFB����ģʽ
		    return SAR_NOTSUPPORTYETERR;
	    case SGD_SM4_MAC:  //SMS4�㷨MAC����
		    return SAR_NOTSUPPORTYETERR;
	    default: 
		    return SAR_NOTSUPPORTYETERR;
	}
    
	return SAR_FAIL;
}

//27
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_EncryptUpdate
* �������ܣ��������ݼ���
* �����б�hKey:            [IN], ��Կ���
*           pbData:          [IN], ����������
*           ulDataLen:       [IN], ���������ݳ���
*           pbEncryptedData: [OUT], ���Ļ�������ΪNULLʱ��pulEncryptedLen���س���
*           pulEncryptedLen: [IN/OUT], ���Ļ�������С������ʵ�ʳ���
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_EncryptUpdate( HANDLE hKey, BYTE * pbData, ULONG ulDataLen, BYTE *pbEncryptedData,
							   ULONG *pulEncryptedLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_EncryptUpdate ********** \n" );
	ULONG ulRet = 0;

    WriteLogToFile( pszLog );

	ulRet = SKF_Encrypt( hKey, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen );
	
    return ulRet;
}

//28
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_EncryptFinal
* �������ܣ���������
* �����б�hKey:            [IN], ��Կ���
*           pbEncryptedData: [OUT], ���Ļ�������ΪNULLʱ��pulEncryptedLen���س���
*           pulEncryptedLen: [IN/OUT], ���Ļ�������С������ʵ�ʳ���
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_EncryptFinal (HANDLE hKey, BYTE *pbEncryptedData, ULONG *pulEncryptedLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_EncryptFinal ********** \n" );
	WriteLogToFile( pszLog );

	*pulEncryptedLen = 0;

	return SAR_OK;
}

//29
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_DecryptInit
* �������ܣ����ܳ�ʼ��
* �����б�hKey:         [IN], ��Կ���
*           encryptParam: [IN], ���������㷨��ز�������ʼ���������ȣ���䷽��������ֵ����
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_DecryptInit( HANDLE hKey, BLOCKCIPHERPARAM encryptParam )
{
	CHAR* pszLog = ( "**********Start to execute SKF_EncryptInit ********** \n" );
	BYTE blockLen = 0x00;

    WriteLogToFile( pszLog );

	if( hKey == NULL )
	    return SAR_INVALIDHANDLEERR;

	(*(PSESSIONKEY)hKey).Params = encryptParam;

	(*((PSESSIONKEY)hKey)).MsgLen=0;

	return SAR_OK;

}

//30
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_Decrypt
* �������ܣ��������ݽ���
* �����б�hKey:            [IN], ��Կ���
*           pbEncryptedData: [IN], ����������
*           ulEncryptedLen:  [IN], ���������ݳ���
*           pbData:          [OUT], ���Ļ�������ΪNULLʱ��pulDataLen���س���
*           pulDataLen:      [IN,OUT], ���Ļ�������С������ʵ�ʳ���
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_Decrypt( HANDLE hKey, BYTE *pbEncryptedData, ULONG ulEncryptedLen,
										  BYTE *pbData, ULONG *pulDataLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_Decrypt ********** \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE response[SIZE_BUFFER_1024];
    BYTE apdu[SIZE_BUFFER_1024];
    INT divider = 0;
	INT remainder = 0;
    PSESSIONKEY sessionKey;
	HANDLE hDev;
	ULONG ulAlgID = 0;
	DWORD nResponseLen = 0;
	LONG nRet = 0;
#ifdef _DEBUG
	ULONG m = 0;
#endif
	sv_fEnd = FALSE;
	divider = remainder = 0;
    WriteLogToFile( pszLog );
	memset( szLog, 0, sizeof(szLog) );
    
	//--------�жϾ���Ƿ�Ϊ��
	if( hKey == NULL )
	{
        sprintf( szLog, "����ʧ�ܣ���Կ���Ϊ�գ�\n" );
		WriteLogToFile( szLog );
		return SAR_INVALIDHANDLEERR;
	}
    
	//--------�������ݲ���Ϊ��
	if( pbEncryptedData == NULL )
	{
        sprintf( szLog, "�����ܵ��������ݴ��� \n" );
		WriteLogToFile( szLog );
		return SAR_INDATAERR;
	}

#ifdef _DEBUG
	WriteLogToFile( TEXT("SKF_Encrypt, cipherText: \n") );
	sprintf( szLog, "%d \n", ulEncryptedLen );
	WriteLogToFile( szLog );
	for( m=0; m<ulEncryptedLen; m++ )
	{
		sprintf( szLog, "%02X", pbEncryptedData[m] );
		WriteLogToFile( szLog );
	}
	WriteLogToFile( TEXT("\n") );
#endif

	//--------�ж��㷨���ͣ�ָ����ӦAPDU
	sessionKey = ((PSESSIONKEY)hKey);
	ulAlgID = sessionKey -> AlgID;
	hDev    = sessionKey -> hDev;

	//--------ѡ��CA����DDF3
	memcpy( apdu, apdu_selectDF, 0x07 );
	apdu[5] = APDU_CA_FID[0];
	apdu[6] = APDU_CA_FID[1];
    nResponseLen = sizeof( response );
    nRet = TransmitData( hDev, apdu, 0x07, response, &nResponseLen );
    if( nRet != SAR_OK )
	{
        sprintf( szLog, "ѡ��CA����ʧ�ܣ�������: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}
	
//	PrintApduToFile( 1, response, nResponseLen );

	if( (response[nResponseLen-2] != 0x90) || (response[nResponseLen-1] != 0x00) )
	{
        sprintf( szLog, "ѡ��CA����ʧ�ܣ�״̬��: %02x%02x \n", response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

	 //--------�����㷨���ͣ����üӽ��ܺ���
	switch( ulAlgID )
	{
	    case SGD_SM1_ECB:  //SM1�㷨ECB����ģʽ
		    memcpy( sv_APDU, apdu_decrypt_sm1_ecb, 0x05 );
		    return ( Algo_Group_ECB( hKey, pbEncryptedData, ulEncryptedLen, pbData, pulDataLen ) );
	    case SGD_SM1_CBC:  //SM1�㷨CBC����ģʽ
		    memcpy( sv_APDU, apdu_decrypt_sm1_cbc, 0x05 );
		    return ( Algo_Group_CBC( hKey, pbEncryptedData, ulEncryptedLen, pbData, pulDataLen ) );
        case SGD_SM1_CFB:  //SM1�㷨CFB����ģʽ
		    return SAR_NOTSUPPORTYETERR;
        case SGD_SM1_OFB:  //SM1�㷨OFB����ģʽ
		    return SAR_NOTSUPPORTYETERR;
        case SGD_SM1_MAC:  //SM1�㷨MAC����
		    return SAR_NOTSUPPORTYETERR;
	    case SGD_SSF33_ECB:  //SSF33�㷨ECB����ģʽ
		    memcpy( sv_APDU, apdu_decrypt_ssf33_ecb, 0x05 );
		    return ( Algo_Group_ECB( hKey, pbEncryptedData, ulEncryptedLen, pbData, pulDataLen ) );
	    case SGD_SSF33_CBC:  //SSF33�㷨CBC����ģʽ
		    memcpy( sv_APDU, apdu_decrypt_ssf33_cbc, 0x05 );
		    return ( Algo_Group_CBC( hKey, pbEncryptedData, ulEncryptedLen, pbData, pulDataLen ) );
	    case SGD_SSF33_CFB:  //SSF33�㷨CFB����ģʽ
		    return SAR_NOTSUPPORTYETERR;
	    case SGD_SSF33_OFB:  //SSF33�㷨OFB����ģʽ
		    return SAR_NOTSUPPORTYETERR;
	    case SGD_SSF33_MAC:  //SSF33�㷨MAC����
		    return SAR_NOTSUPPORTYETERR;
	    case SGD_SM4_ECB:  //SMS4�㷨ECB����ģʽ
		    memcpy( sv_APDU, apdu_decrypt_sm4_ecb, 0x05 );
		    return ( Algo_Group_ECB( hKey, pbEncryptedData, ulEncryptedLen, pbData, pulDataLen ) );
	    case SGD_SM4_CBC:  ////SMS4�㷨CBC����ģʽ
		    memcpy( sv_APDU, apdu_decrypt_sm4_cbc, 0x05 );
		    return ( Algo_Group_CBC( hKey, pbEncryptedData, ulEncryptedLen, pbData, pulDataLen ) );
	    case SGD_SM4_CFB:  //SMS4�㷨CFB����ģʽ
		    return SAR_NOTSUPPORTYETERR;
	    case SGD_SM4_OFB:  //SMS4�㷨OFB����ģʽ
		    return SAR_NOTSUPPORTYETERR;
	    case SGD_SM4_MAC:  //SMS4�㷨MAC����
		    return SAR_NOTSUPPORTYETERR;
	    default: 
		    return SAR_NOTSUPPORTYETERR;
	}
	
	return SAR_FAIL;
}


//31
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_DecryptUpdate
* �������ܣ��������ݽ���
* �����б�hKey:            [IN], ��Կ���
*           pbEncryptedData: [IN], ����������
*           ulEncryptedLen:  [IN], ���������ݳ���
*           pbData:          [OUT], ָ�����Ļ�������ΪNULLʱ��pulDataLen���س���
*           pulDataLen:      [IN,OUT], ���Ļ�������С������ʵ�ʳ���
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_DecryptUpdate( HANDLE hKey, BYTE * pbEncryptedData, ULONG ulEncryptedLen, BYTE * pbData,
							   ULONG * pulDataLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_DecryptUpdate ********** \n" );
	ULONG ulRet = 0;
	WriteLogToFile( pszLog );

	ulRet = SKF_Decrypt( hKey, pbEncryptedData, ulEncryptedLen, pbData, pulDataLen );
    return SAR_OK;
}

//32
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_DecryptFinal
* �������ܣ���������
* �����б�hKey:            [IN], ��Կ���
*           pbEncryptedData: [IN], ָ����ܽ���Ļ�������ΪNULLʱ��ulEncryptedLen���س���
*           ulEncryptedLen:  [IN], ����ʱ��ʾ���ܽ�����������ȣ����ʱ��ʾ���ܽ������
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_DecryptFinal (HANDLE hKey, BYTE *pbDecryptedData, ULONG *pulDecryptedLen)
{
	CHAR* pszLog = ( "**********Start to execute SKF_DecryptFinal ********** \n" );
	WriteLogToFile( pszLog );

	*pulDecryptedLen = 0;
	return SAR_OK;
}

//33
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_DigestInit
* �������ܣ������Ӵճ�ʼ��
* �����б�hDev:    [IN], �豸���
*           ulAlgID: [IN], �Ӵ��㷨��ʶ
*           pPubKey: [IN], ǩ���߹�Կ����ulAlgID=SGD_SM3ʱ��Ч
*           pucID:   [IN], ǩ���ߵ�IDֵ����ulAlgID=SGD_SM3ʱ��Ч
*           ulIDLen: [IN], ǩ����ID�ĳ��ȣ���ulAlgID=SGD_SM3ʱ��Ч
*           phHash:  [OUT], �����Ӵն�����
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_DigestInit( HANDLE hDev, ULONG ulAlgID, ECCPUBLICKEYBLOB* pPubKey, BYTE* pucID,
							ULONG ulIDLen, HANDLE *phHash )
{
	CHAR* pszLog = ( "**********Start to execute SKF_DigestInit ********** \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE apdu[SIZE_BUFFER_1024];
	BYTE response[SIZE_BUFFER_1024];
	DWORD nResponseLen = 0;
	LONG nRet = 0;
	memset( apdu, 0x00, sizeof(apdu) );
	memset( response, 0x00, sizeof(response) );
	memset( szLog, 0x0, strlen(szLog) );

	WriteLogToFile( pszLog );

	if( hDev == NULL )
	{
		return SAR_INVALIDHANDLEERR;
	}

	switch(ulAlgID)
	{
	case SGD_SHA1:
		return SAR_NOTSUPPORTYETERR;
	case SGD_SM3:
		break;
	case SGD_SHA256:
		return SAR_NOTSUPPORTYETERR;
	default:
		return SAR_NOTSUPPORTYETERR;
	}

	//--------ѡ��MF

    //--------ѡ��CA����DDF3

	memcpy( apdu, apdu_selectDF, 0x07 );
	apdu[5] = APDU_CA_FID[0];
	apdu[6] = APDU_CA_FID[1];
    nResponseLen = sizeof( response );
    nRet = TransmitData( hDev, apdu, 0x07, response, &nResponseLen );
    if( nRet != SAR_OK )
	{
        sprintf( szLog, "ѡ��CA����ʧ�ܣ������룺%d \n", nRet );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

//	PrintApduToFile( 1, response, nResponseLen );

	if( (response[nResponseLen-2] != 0x90) || (response[nResponseLen-1] != 0x00) )
	{
        sprintf( szLog, "ѡ��CA����ʧ�ܣ�״̬��: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

	sv_stHash.hDev = hDev;
	*phHash = &sv_stHash;
	return SAR_OK;
}

//34
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_Digest
* �������ܣ��������������Ӵ�
* �����б�hHash:      [IN], �����Ӵն�����
*           pbData:     [IN], ָ����Ϣ���ݵĻ�����
*           ulDataLen:  [IN], ��Ϣ���ݵĳ���
*           pbHashData: [OUT], �Ӵս����������ΪNULLʱ��pulHashLen���س���
*           pulHashLen: [IN,OUT], ����ʱ��ʾ�Ӵս�����������ȣ����ʱ��ʾ�Ӵս������
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
/*
BYTE ss[32] = {
    0xD2, 0x81, 0xBD, 0x10, 0xAE, 0x62, 0x4A, 0xFE, 
	0x17, 0x3D, 0x97, 0x1F, 0x93, 0x3F, 0xE2, 0xFC, 
	0x9B, 0xC2, 0xF1, 0xC5, 0x5E, 0xF9, 0x1F, 0xB5, 
	0x5C, 0x38, 0x7B, 0x22, 0x39, 0xE4, 0xC7, 0xE6
};
*/
BYTE ss[32] = {
    0xC4, 0x0D, 0x25, 0xD5, 0xB2, 0xA4, 0xCB, 0x1A, 
    0xBE, 0x58, 0x08, 0x35, 0x5B, 0x2D, 0x22, 0xC9, 
	0x7A, 0xF0, 0x04, 0xDA, 0x29, 0x84, 0xD9, 0xE5, 
	0xD7, 0x76, 0x11, 0xB1, 0x44, 0x62, 0x75, 0xA1
};

BYTE xx[20480];
ULONG SKF_Digest( HANDLE hHash, BYTE* pbData, ULONG ulDataLen, BYTE* pbHashData, ULONG* pulHashLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_Digest ********** \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE apdu[SIZE_BUFFER_1024];
	BYTE response[SIZE_BUFFER_1024];
	DWORD dwTotalLen = 0;
	INT nIndex = 0;
	INT nDivider = 0;
	INT nRemainder = 0;
	PHASHINFO pHash;
    HANDLE hDev;
	DWORD nResponseLen = 0;
	LONG nRet = 0;
	//--------��ϣ�������Ϊ��
	if( hHash == NULL )
	{
		return SAR_INVALIDHANDLEERR;
	}

	memcpy( xx, pbData, ulDataLen );

	pHash = (PHASHINFO)hHash;
	hDev = pHash -> hDev;

	memset( apdu, 0x00, sizeof(apdu) );
	memset( response, 0x00, sizeof(response) );
	memset( szLog, 0x0, strlen(szLog) );

	WriteLogToFile( pszLog );

	nDivider = ulDataLen / SIZE_BUFFER_64;
	nRemainder = ulDataLen % SIZE_BUFFER_64;

	//--------�������ݳ�����64������
	if( nRemainder != 0 )
	{
		return SAR_INDATALENERR;
	}

	//ÿ���Ӵյ�������һ��blockΪ��λ��ÿ��blockΪ64bytes������nDivider��block

	//��Ŀǰ��nRemainder����Ϊ0
	//--------SM3�Ӵ�����
	memcpy( apdu, apdu_sm3_digest, 0x05 );
	apdu[4] = 0x40;

	for( nIndex=0; nIndex<nDivider; nIndex++ )
	{
		if( nDivider == 1 )
			apdu[2] = 0x01;
		else if( nIndex == 0 )
			apdu[2] = 0x00;
		else if( nIndex == nDivider-1 )
			apdu[2] = 0x04;
		else
			apdu[2] = 0x02;

		memcpy( apdu+0x05, pbData+(nIndex*SIZE_BUFFER_64), SIZE_BUFFER_64 );

//		PrintApduToFile( 0, apdu, 0x05+SIZE_BUFFER_64 );

        nResponseLen = sizeof( response );
        nRet = TransmitData( hDev, apdu, 0x05+SIZE_BUFFER_64, response, &nResponseLen );
        if( nRet != SAR_OK )
		{
            sprintf( szLog, "SM3�Ӵ�ʧ�ܣ�������: %d \n", nRet );
			WriteLogToFile( szLog );
			sv_nStatus = 1;
			return SAR_FAIL;
		}
	
//		PrintApduToFile( 1, response, nResponseLen );

		if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
		{
			if( pbHashData != NULL )  //ע�⣬ÿ���ӴյĽ��Ϊ32�ֽ�
			{
				memcpy( pbHashData, ss, 32 );
				memcpy( pbHashData, response, nResponseLen-2 );
			}
			
			dwTotalLen += (nResponseLen-2);

		}
		else
		{
			sprintf( szLog, "SM4�Ӵ�ʧ�ܣ�״̬��: %02x%02x \n", response[nResponseLen-2], response[nResponseLen-1] );
			WriteLogToFile( szLog );
			return SAR_FAIL;	
		}
	}

	if( nRemainder != 0 )
	{
		memcpy( apdu+0x05, pbData+(nDivider*SIZE_BUFFER_64), nRemainder );

//		PrintApduToFile( 0, apdu, 0x05+nRemainder );

        nResponseLen = sizeof( response );
        nRet = TransmitData( hDev, apdu, 0x05+nRemainder, response, &nResponseLen );
        if( nRet != SAR_OK )
		{
            sprintf( szLog, "SM3�Ӵ�ʧ�ܣ�������: %d \n", nRet );
			WriteLogToFile( szLog );
			sv_nStatus = 1;
			return SAR_FAIL;
		}

//		PrintApduToFile( 1, response, nResponseLen );

		if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
		{
			if( pbHashData != NULL )
			{
				memcpy( pbHashData, response, nResponseLen-2 );
			}
			dwTotalLen += (nResponseLen-2);

		}
		else
		{
			sprintf( szLog, "SM3�Ӵ�ʧ�ܣ�״̬��: %02x%02x \n", response[nResponseLen-2], response[nResponseLen-1] );
			WriteLogToFile( szLog );
			return SAR_FAIL;
		}
	}

	if( pbHashData != NULL )
	{
		sprintf( szLog, "Hash size: %d \n", dwTotalLen );
		WriteLogToFile( szLog );
		for( DWORD mm=0; mm<dwTotalLen; mm++ )
		{
		    sprintf( szLog, "%02x", pbHashData[mm] );
			WriteLogToFile( szLog );
		}
	}
	WriteLogToFile( ("\n") );
    *pulHashLen = dwTotalLen;
	return SAR_OK;
}


//35
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_DigestUpdate
* �������ܣ��������������Ӵ�
* �����б�hHash:      [IN], �����Ӵն�����
*           pbData:     [IN], ָ����Ϣ���ݵĻ�����
*           ulDataLen:  [IN], ��Ϣ���ݵĳ���
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
BYTE  sm3_finalBlock[SIZE_BUFFER_64];
BYTE  sm3_firstBlockFlag = 0x00;
ULONG SKF_DigestUpdate( HANDLE hHash, BYTE* pbData, ULONG ulDataLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_DigestUpdate ********** \n" );
	WriteLogToFile( pszLog );

    if( sv_tmpData != NULL ) 
	{
		memcpy( sv_tmpData+sv_tmpDataLen, pbData, ulDataLen );
	}
			
	sv_tmpDataLen += ulDataLen;
	return SAR_OK;
}


//36
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_DigestFinal
* �������ܣ����������Ӵ�
* �����б�hHash:       [IN], ��Կ�Ӵն�����
*           pHashData:   [IN], �����Ӵս����������ΪNULLʱ��pulHashLen�����Ӵս���ĳ���
*           pulHashLen:  [IN], ����ʱ��ʾ�Ӵջ��������ȣ����ʱ��ʾ�Ӵս������

* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_DigestFinal( HANDLE hHash, BYTE* pbHashData, ULONG* pulHashLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_DigestFinal ********** \n" );
    ULONG ulRet = 0;
	WriteLogToFile( pszLog );

	ulRet = SKF_Digest( hHash, sv_tmpData, sv_tmpDataLen, pbHashData, pulHashLen );

	return ulRet;
}

//37--------------------NO
ULONG SKF_MacInit( HANDLE hKey, BLOCKCIPHERPARAM* pMacParam, HANDLE* phMac )
{
	CHAR* pszLog = ( "**********Start to execute SKF_MacInit ********** \n" );
    WriteLogToFile( pszLog );

	return SAR_OK;
}

//38--------------------NO
ULONG SKF_Mac( HANDLE hMac, BYTE* pbData, ULONG ulDataLen, BYTE* pbMacData, ULONG* pulMacLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_Mac ********** \n" );
	WriteLogToFile( pszLog );

	return SAR_OK;
}

//39--------------------NO
ULONG SKF_MacUpdate( HANDLE hMac, BYTE* pbData, ULONG ulDataLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_MacUpdate ********** \n" );
	WriteLogToFile( pszLog );

	return SAR_OK;
}

//40--------------------NO
ULONG SKF_MacFinal( HANDLE hMac, BYTE* pbMacData, ULONG* pulMacDataLen )
{
	CHAR* pszLog = ( "**********Start to execute SKF_MacFinal ********** \n" );
	WriteLogToFile( pszLog );

	return SAR_OK;
}

//41
////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_CloseHandle
* �������ܣ��ر����������(�Ự��Կ�������Ӵն�����Ϣ������ECC��ԿЭ�̵Ⱦ��)
* �����б�hHandle:           [IN], Ҫ�رյĶ�����
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ: ������
*/
ULONG SKF_CloseHandle( HANDLE hHandle )
{
	CHAR* pszLog = ( "**********Start to execute SKF_CloseHandle ********** \n" );
	
	WriteLogToFile( pszLog );
	sv_fEnd = FALSE;

	return SAR_OK;
}

// need update.
ULONG V_ECCPrvKeyDecrypt( HANDLE hDev, BYTE *bKeyFlag, BYTE *pData, BYTE *pbOutData, ULONG *uOutLen )
{
    CHAR* pszLog = ( "**********Start to execute V_ECCPrvKeyDecrypt ********** \n");
    CHAR szLog[SIZE_BUFFER_1024];
    BYTE apdu[0x0B];
    int nIndex = 0;

    if( hDev < 0 ) {
        return SAR_INVALIDHANDLEERR;
    }
    if (bKeyFlag == NULL) {
        LOGE("V_ECCPrvKeyDecrypt param bKeyFlag is null.");
        return -1;
    }
    if (pData == NULL) {
        LOGE("V_ECCPrvKeyDecrypt param pData is null.");
        return -1;
    }
    if (pbOutData == NULL) {
        LOGE("V_ECCPrvKeyDecrypt param pbOutData is null.");
        return -1;
    }
	WriteLogToFile( pszLog );
	sv_fEnd = FALSE;
	memset( apdu, '\0', sizeof(apdu) );
	memcpy( apdu, apdu_FA_01, 0x05 );
    memcpy( apdu + 0x05, apdu_0107, 0x02 );
    memcpy( apdu + 0x07, bKeyFlag, 0x02 );
    memcpy( apdu + 0x09, apdu_0200, 0x02 );

	unsigned long send_len = strlen(apdu);
	unsigned char check_sum = 0;
	int ret;
	unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	//copy the raw data
	memcpy(tmpBuffer_wr, (unsigned char *)apdu, send_len);

	unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	unsigned long recv_len = 0;

	//fill the checksum byte
	check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

	//fill the data ...........................................
	*(tmpBuffer_wr+send_len) = check_sum;
	send_len = send_len + 1;

	for (int i = 0; i < REPEAT_TIMES; i++) {
		if (REPEAT_TIMES > 1)
			usleep(500 * 1000);  //gap between each cycle

		memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
		recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
		ret = TransmitData(trans_dev_id, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
		if (ret < 0) {
			sprintf( szLog, "V_ECCPrvKeyDecrypt failed, error code: %d \n", ret );
			WriteLogToFile( szLog );
			LOGE("V_ECCPrvKeyDecrypt return failed, error code: %d \n", ret );
			ret = -1;
			continue;
		}
		if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
			// get data if need
			break;
		} else {
			sprintf( szLog, "V_ECCPrvKeyDecrypt failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
			WriteLogToFile( szLog );
			LOGE("V_ECCPrvKeyDecrypt failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
		}
	}
	if (ret < 0) {
		sprintf( szLog, "V_ECCPrvKeyDecrypt Certificate failed, error code: %d \n", ret );
		WriteLogToFile( szLog );
		LOGE("V_ECCPrvKeyDecrypt return failed, error code: %d \n", ret );
		free(tmpBuffer_wr);
		free(tmpBuffer_rd);
		return SAR_FAIL;
	}
	// next private key decrypt
	int size = strlen(pData);
	if (size > SIZE_BUFFER_255) {
		int parts = size / SIZE_BUFFER_255;
		int i = 0;
		unsigned char DataTobeSend[0x0104];
		for (i = 0; i < parts; i++) {
			send_len = 0x0104;
			memset(DataTobeSend, '\0', 0x0104);
			memcpy(DataTobeSend, apdu_FA_02, 0x04);
			memcpy(DataTobeSend + 0x04, apdu_FF, 0x01);
			memcpy(DataTobeSend + 0x05, pData + i * SIZE_BUFFER_255, SIZE_BUFFER_255);
			memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
			//copy the raw data
			memcpy(tmpBuffer_wr, (unsigned char *)DataTobeSend, send_len);

			//fill the checksum byte
			check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

			//fill the data ...........................................
			*(tmpBuffer_wr+send_len) = check_sum;
			send_len = send_len + 1;
			for (int i = 0; i < REPEAT_TIMES; i++) {
				if (REPEAT_TIMES > 1)
					usleep(500 * 1000);  //gap between each cycle

				memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
				recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
				ret = TransmitData(trans_dev_id, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
				if (ret < 0) {
					sprintf( szLog, "V_ECCPrvKeyDecrypt failed, error code: %d \n", ret );
					WriteLogToFile( szLog );
					LOGE("V_ECCPrvKeyDecrypt return failed, error code: %d \n", ret );
					continue;
				}
				if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
					// get data if need
					break;
				} else {
					sprintf( szLog, "V_ECCPrvKeyDecrypt failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
					WriteLogToFile( szLog );
					LOGE("V_ECCPrvKeyDecrypt failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
				}
			}
		}
		int last = size - i * SIZE_BUFFER_255;
		send_len = last + 5;
		unsigned char LastToBeSend[send_len];
		unsigned char len;
		sprintf(len, "%X", last);
		memset(LastToBeSend, '\0', send_len);
		memcpy(LastToBeSend, apdu_FA_03, 0x04);
		memcpy(LastToBeSend + 0x04, apdu_02, 0x01);
		memcpy(LastToBeSend + 0x05, pData + i * SIZE_BUFFER_255, last);
		memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
		//copy the raw data
		memcpy(tmpBuffer_wr, (unsigned char *)LastToBeSend, send_len);

		//fill the checksum byte
		check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

		//fill the data ...........................................
		*(tmpBuffer_wr+send_len) = check_sum;
		send_len = send_len + 1;

		for (int i = 0; i < REPEAT_TIMES; i++) {
			if (REPEAT_TIMES > 1)
				usleep(500 * 1000);  //gap between each cycle

			memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
			recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
			ret = TransmitData(trans_dev_id, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
			if (ret < 0) {
				LOGE("V_ECCPrvKeyDecrypt return failed, error code: %d \n", ret );
				sprintf( szLog, "V_ECCPrvKeyDecrypt failed, error code: %d \n", ret );
				WriteLogToFile( szLog );
				continue;
			}
			if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
				// get data if need
                memcpy(pbOutData + nIndex, tmpBuffer_rd, recv_len - 2);
                nIndex = nIndex + recv_len - 2;
				break;
			} else {
				sprintf( szLog, "V_ECCPrvKeyDecrypt failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
				WriteLogToFile( szLog );
				LOGE("V_ECCPrvKeyDecrypt failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
			}
		}
	}
    send_len = 5;
    memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    //copy the raw data
    memcpy(tmpBuffer_wr, (unsigned char *)apdu_C6_A0, send_len);

    //fill the checksum byte
    check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

    //fill the data ...........................................
    *(tmpBuffer_wr+send_len) = check_sum;
    send_len = send_len + 1;

    for (int i = 0; i < REPEAT_TIMES; i++) {
        if (REPEAT_TIMES > 1)
            usleep(500 * 1000);  //gap between each cycle

        memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
        recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
        ret = TransmitData(trans_dev_id, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
        if (ret < 0) {
            LOGE("V_ECCPrvKeyDecrypt return failed, error code: %d \n", ret );
            sprintf( szLog, "V_ECCPrvKeyDecrypt failed, error code: %d \n", ret );
            WriteLogToFile( szLog );
            continue;
        }
        if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
            // get data if need
            memcpy(pbOutData + nIndex, tmpBuffer_rd, recv_len - 2);
            nIndex = nIndex + recv_len - 2;
            break;
        } else {
            sprintf( szLog, "V_ECCPrvKeyDecrypt failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
            WriteLogToFile( szLog );
            LOGE("V_ECCPrvKeyDecrypt failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
        }
    }

    *uOutLen = nIndex;
	free(tmpBuffer_wr);
	free(tmpBuffer_rd);

	if (ret < 0) {
		return SAR_FAIL;
	}
	return SAR_OK;
}

ULONG V_Cipher(HANDLE hContainer, BYTE *pbData, ULONG ulDataLen, BYTE *pbSignature,
			   ULONG *pulSignLen)
{
    CHAR* pszLog = ( "**********Start to execute SKF_Cipher ********** \n" );

    WriteLogToFile( pszLog );

    return SAR_OK;
}

ULONG V_GetZA( HANDLE hContainer, BYTE *pData, BYTE *pZA, ULONG  *ulZALen )
{
    CHAR* pszLog = ( "**********Start to execute V_GetZA ********** \n" );
    CHAR szLog[SIZE_BUFFER_1024];
    memset( szLog, 0x0, strlen(szLog) );

    WriteLogToFile( pszLog );
    if( hContainer < 0 ) {
        return SAR_INVALIDHANDLEERR;
    }
    if (pData == NULL || (strlen(pData) != SIZE_BUFFER_64)) {
        LOGE("V_GetZA param pData is not correct.");
        return -1;
    }
	if (pZA == NULL) {
		LOGE("V_GetZA param pZA is null.");
		return -1;
	}

    // 1st command  80F10000 40 64�ֽ�SM2��Կ
    unsigned char DataTobeSend[0x45];
    unsigned long send_len = 0x45;
    unsigned char check_sum = 0;

    int ret;
    unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);

    unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    unsigned long recv_len = 0;
    memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);

    memset(DataTobeSend, '\0', 0x45);
    memcpy(DataTobeSend, apdu_F1_40, 0x05);
    memcpy(DataTobeSend + 0x05, pData, 0x40);
    //copy the raw data
    memcpy(tmpBuffer_wr, (unsigned char *)DataTobeSend, send_len);

    //fill the checksum byte
    check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

    //fill the data ...........................................
    *(tmpBuffer_wr+send_len) = check_sum;
    send_len = send_len + 1;

    for (int i = 0; i < REPEAT_TIMES; i++) {
        if (REPEAT_TIMES > 1)
            usleep(500 * 1000);  //gap between each cycle

        memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
        recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
        ret = TransmitData(hContainer, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
        if (ret < 0) {
            sprintf( szLog, "V_GetZA failed, error code: %d \n", ret );
            WriteLogToFile( szLog );
            LOGE("V_GetZA return failed, error code: %d \n", ret );
            ret = -1;
            continue;
        }
        if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
            // get ZA
            *ulZALen = recv_len-2;
            memcpy( pZA, tmpBuffer_rd, *ulZALen );
            break;
        } else {
            sprintf( szLog, "V_GetZA failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
            WriteLogToFile( szLog );
            LOGE("V_GetZA failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
        }
    }

    free(tmpBuffer_wr);
    free(tmpBuffer_rd);

	if (ret < 0) {
		return SAR_FAIL;
	}
    return SAR_OK;
}

ULONG V_GenerateKey( HANDLE hContainer, ULONG ulAlgId, BYTE *bKeyFlag, BYTE *pKeyData, ULONG  *uKeyLen )
{
    CHAR* pszLog = ( "**********Start to execute V_GenerateKey ********** \n" );
    CHAR szLog[SIZE_BUFFER_1024];
    memset( szLog, 0x0, strlen(szLog) );

    WriteLogToFile( pszLog );
    if( hContainer < 0 ) {
        return SAR_INVALIDHANDLEERR;
    }
    if (pKeyData == NULL) {
        LOGE("V_GenerateKey param pKeyData is null.");
        return -1;
    }
	if (bKeyFlag == NULL) {
		LOGE("V_GenerateKey param bKeyFlag is null.");
		return -1;
	}

    // command  80C80000 06 00+XX��02:SM1,03:SM4��+2�ֽ�KID+ 0080
    unsigned char DataTobeSend[0x0B];
    unsigned long send_len = 0x0B;
    unsigned char check_sum = 0;

    int ret;
    unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);

    unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    unsigned long recv_len = 0;
    memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);

    memset(DataTobeSend, '\0', 0x0B);
    memcpy(DataTobeSend, apdu_C8_06, 0x06);
    if ( ulAlgId == SGD_SM1 ) {
        memcpy( DataTobeSend + 0x06, apdu_02, 0x01 );
    } else if ( ulAlgId == SGD_SM4 ) {
		memcpy( DataTobeSend + 0x06, apdu_03, 0x01 );
	} else {
		LOGE("V_GenerateKey param ulAlgId is not correct.");
		return -1;
    }
	memcpy(DataTobeSend + 0x07, bKeyFlag, 0x02);
	memcpy(DataTobeSend + 0x09, apdu_0800, 0x02);
    //copy the raw data
    memcpy(tmpBuffer_wr, (unsigned char *)DataTobeSend, send_len);

    //fill the checksum byte
    check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

    //fill the data ...........................................
    *(tmpBuffer_wr+send_len) = check_sum;
    send_len = send_len + 1;

    for (int i = 0; i < REPEAT_TIMES; i++) {
        if (REPEAT_TIMES > 1)
            usleep(500 * 1000);  //gap between each cycle

        memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
        recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
        ret = TransmitData(hContainer, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
        if (ret < 0) {
            sprintf( szLog, "V_GenerateKey failed, error code: %d \n", ret );
            WriteLogToFile( szLog );
            LOGE("V_GenerateKey return failed, error code: %d \n", ret );
            ret = -1;
            continue;
        }
        if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
            // get ZA
            *uKeyLen = recv_len-2;
            memcpy( pKeyData, tmpBuffer_rd, *uKeyLen );
            break;
        } else {
            sprintf( szLog, "V_GenerateKey failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
            WriteLogToFile( szLog );
            LOGE("V_GenerateKey failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
        }
    }

    free(tmpBuffer_wr);
    free(tmpBuffer_rd);

	if (ret < 0) {
		return SAR_FAIL;
	}
    return SAR_OK;
}

ULONG V_ECCExportSessionKeyByHandle( HANDLE hContainer, BYTE *bKeyFlag, BYTE *pKeyData, ULONG uKeyLen, BYTE *pOutData, ULONG  *uOutLen )
{
	CHAR* pszLog = ( "**********Start to execute V_GenerateKey ********** \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	memset( szLog, 0x0, strlen(szLog) );

	WriteLogToFile( pszLog );
	if( hContainer < 0 ) {
		return SAR_INVALIDHANDLEERR;
	}
	if (pKeyData == NULL) {
		LOGE("V_ECCExportSessionKeyByHandle param pKeyData is null.");
		return -1;
	}
	if (bKeyFlag == NULL) {
		LOGE("V_ECCExportSessionKeyByHandle param bKeyFlag is null.");
		return -1;
	}
	if (pOutData == NULL) {
		LOGE("V_ECCExportSessionKeyByHandle param pOutData is null.");
		return -1;
	}

	// command  80C80000 06 00+XX��02:SM1,03:SM4��+2�ֽ�KID+ 0080
	unsigned char DataTobeSend[0x2A];
	unsigned long send_len = 0x2A;
	unsigned char check_sum = 0;

	int ret;
	unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);

	unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	unsigned long recv_len = 0;
	memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);

	memset(DataTobeSend, '\0', 0x0B);
	memcpy(DataTobeSend, apdu_FA_06, 0x05);
    memcpy( DataTobeSend + 0x05, apdu_2007, 0x02 );
	memcpy(DataTobeSend + 0x07, bKeyFlag, 0x02);
	memcpy(DataTobeSend + 0x09, apdu_20, 0x01);
    memcpy(DataTobeSend + 0x0A, pKeyData, 0x20);
	//copy the raw data
	memcpy(tmpBuffer_wr, (unsigned char *)DataTobeSend, send_len);

	//fill the checksum byte
	check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

	//fill the data ...........................................
	*(tmpBuffer_wr+send_len) = check_sum;
	send_len = send_len + 1;

	for (int i = 0; i < REPEAT_TIMES; i++) {
		if (REPEAT_TIMES > 1)
			usleep(500 * 1000);  //gap between each cycle

		memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
		recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
		ret = TransmitData(hContainer, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
		if (ret < 0) {
			sprintf( szLog, "V_ECCExportSessionKeyByHandle failed, error code: %d \n", ret );
			WriteLogToFile( szLog );
			LOGE("V_ECCExportSessionKeyByHandle return failed, error code: %d \n", ret );
			ret = -1;
			continue;
		}
		if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
			// get ZA
			*uOutLen = recv_len-2;
			memcpy( pOutData, tmpBuffer_rd, *uOutLen );
			break;
		} else {
			sprintf( szLog, "V_ECCExportSessionKeyByHandle failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
			WriteLogToFile( szLog );
			LOGE("V_ECCExportSessionKeyByHandle failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
		}
	}

	free(tmpBuffer_wr);
	free(tmpBuffer_rd);

	if (ret < 0) {
		return SAR_FAIL;
	}
	return SAR_OK;
}

#ifdef __cplusplus
}
#endif  /*__cplusplus*/
