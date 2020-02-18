//#include "stdafx.h"
#include "Global_Def.h"

#define SIZE_BUFFER_224        (16*14)
#define SIZE_ECB_BLOCK SIZE_BUFFER_224
#define SIZE_CBC_BLOCK SIZE_BUFFER_224
//�ú���ʹ���ڷ����㷨��ECBģʽ����SM1 ECB, SSF33 ECB��SM4 ECB
ULONG Algo_Group_ECB( HANDLE hKey, BYTE *pbInData, ULONG ulInDataLen, 
										  BYTE *pbOutData, ULONG * pulOutDataLen )
{
	CHAR* pszLog = ( "Start to execute Algo_Group_ECB \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	DWORD dwTotalLen = 0;
	BYTE response[SIZE_BUFFER_1024];
    BYTE apdu[SIZE_BUFFER_1024];
    INT nDivider = 0;
	INT nRemainder = 0;
    INT nKeyLen = 0;
	BYTE keyVal[SIZE_BUFFER_128];
	ULONG ulAlgID = 0;
	PSESSIONKEY stSessionKey;
	DEVHANDLE hDev;
	INT nIndex = 0;

#ifdef READER_TYPE_HID
    BYTE nResponseLen = 0;
	SHORT nRet = 0;
#endif
#ifdef READER_TYPE_CCID
	DWORD nResponseLen = 0;
	LONG nRet = 0;
	sv_IORequest.dwProtocol = 0;
	sv_IORequest.cbPciLength = sizeof( SCARD_IO_REQUEST );
#endif
    
	memset( szLog, 0x0, strlen(szLog) );
	memset( keyVal, 0x00, sizeof(keyVal) );

    WriteLogToFile( pszLog );

//	_stprintf_s( szLog, _countof(szLog), TEXT("����ECB����/���ܣ����ݳ��� %d \n"), ulInDataLen );
	WriteLogToFile( szLog );

	stSessionKey = ((PSESSIONKEY)hKey);

	//--------�ж��㷨���ͣ�ָ����ӦAPDU
	ulAlgID = stSessionKey -> AlgID;
	hDev    = stSessionKey -> hDev;
	nKeyLen = stSessionKey -> KeyLen;
	memcpy( keyVal, stSessionKey->KeyVal, nKeyLen );

	//--------������Կ��16�ֽ�
	memcpy( apdu, sv_APDU, 0x05 );
	memcpy( apdu+0x05, keyVal, nKeyLen );

	nDivider = ulInDataLen / SIZE_ECB_BLOCK;   
	nRemainder = ulInDataLen % SIZE_ECB_BLOCK;

	//ÿ�μ��ܵ�������һ��blockΪ��λ��ÿ��blockΪSIZE_ECB_BLOCK������divider��block

	//remainder�Ƿ����Ϊ0��

	for( nIndex=0; nIndex<nDivider; nIndex++ )
	{
		memcpy( apdu+0x15, pbInData+(nIndex*SIZE_ECB_BLOCK), SIZE_ECB_BLOCK );
		apdu[4] = 0x10+SIZE_ECB_BLOCK;

//		PrintApduToFile( 0, apdu, 0x15+SIZE_ECB_BLOCK );

#ifdef READER_TYPE_HID
		nRet = dc_pro_command( hDev, 0x15+SIZE_ECB_BLOCK, apdu, &nResponseLen, response, 7 );
		if( nRet != 0 )
#endif
#ifdef READER_TYPE_CCID	
		nResponseLen = sizeof( response );
        nRet = SCardTransmit( (SCARDHANDLE)hDev, &sv_IORequest, apdu, 0x15+SIZE_ECB_BLOCK, NULL, response, &nResponseLen );
        if( nRet != SCARD_S_SUCCESS )
#endif
		{
//            _stprintf_s( szLog, _countof(szLog), TEXT("����ECB����/����ʧ�ܣ���%d�飬������: %d \n"), nIndex, nRet );
			WriteLogToFile( szLog );
			sv_nStatus = 1;
			return SAR_FAIL;
		}

//		PrintApduToFile( 1, response, nResponseLen );
	
		if( 1)//(response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
		{
			if( pbOutData != NULL )
			{
//				memcpy( pbOutData+(nIndex*SIZE_ECB_BLOCK), response, nResponseLen-2 );
			}	

//			dwTotalLen += (nResponseLen-2);
		}
		else
		{
//			_stprintf_s( szLog, _countof(szLog), TEXT("����ECB����/����ʧ�ܣ�״̬��: %02x%02x \n"), response[nResponseLen-2], response[nResponseLen-1] );
			WriteLogToFile( szLog );
			return SAR_FAIL;	
		}
	}

	if( nRemainder != 0 )
	{
		memcpy( apdu+0x15, pbInData+(nDivider*SIZE_ECB_BLOCK), nRemainder );
		//apdu[0x15+nRemainder] = 0x80;
		//for( int k=nRemainder+1; k<SIZE_ECB_BLOCK; k++ )
		//	apdu[0x15+k] = 0x00;
		//apdu[4] = 0x10+SIZE_ECB_BLOCK;
		apdu[4] = 0x10+(BYTE)nRemainder;

//		PrintApduToFile( 0, apdu, 0x15+nRemainder );

#ifdef READER_TYPE_HID
		nRet = dc_pro_command(hDev, 0x15+nRemainder, apdu, &nResponseLen, response, 7 );
		if( nRet != 0 )
#endif
#ifdef READER_TYPE_CCID	
		nResponseLen = sizeof( response );
        nRet = SCardTransmit( (SCARDHANDLE)hDev, &sv_IORequest, apdu, 0x15+nRemainder, NULL, response, &nResponseLen );
        if( nRet != SCARD_S_SUCCESS )
#endif	
		{
//            _stprintf_s( szLog, _countof(szLog), TEXT("����ECB����/����ʧ�ܣ�������: %d \n"), nRet );
			WriteLogToFile( szLog );
			sv_nStatus = 1;
			return SAR_FAIL;
		}

//		PrintApduToFile( 1, response, nResponseLen );

//		if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
//		{
//			if( pbOutData != NULL )
//			{
//				memcpy( pbOutData+(nDivider*SIZE_ECB_BLOCK), response, nResponseLen-2 );
//			}
//
//			dwTotalLen += (nResponseLen-2);
//		}
//		else
//		{
//			_stprintf_s( szLog, _countof(szLog), TEXT("����ECB����/����ʧ�ܣ�״̬��: %02x%02x \n"), response[nResponseLen-2], response[nResponseLen-1] );
//			WriteLogToFile( szLog );
//			return SAR_FAIL;
//		}
	}
	
	*pulOutDataLen = dwTotalLen;

#ifdef _DEBUG
    ULONG m = 0;
	WriteLogToFile( TEXT("Algo_Group_ECB, ciperText/plaintText: \n") );
	if( pbOutData != NULL )
	{
	    for( m=0; m<dwTotalLen; m++ )
		{
		    _stprintf_s( szLog, _countof(szLog), TEXT("%02X"), pbOutData[m] );
		    WriteLogToFile( szLog );
		}
	}
	WriteLogToFile( TEXT("\n") );
#endif
	

    return SAR_OK;
}

//�ú���ʹ���ڷ����㷨��CBCģʽ����SM1 CBC, SSF33 CBC��SM4 CBC
ULONG Algo_Group_CBC( HANDLE hKey, BYTE *pbInData, ULONG ulInDataLen, 
										  BYTE *pbOutData, ULONG * pulOutDataLen )
{
	CHAR *pszLog = ( "Start to execute Algo_Group_CBC \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	DWORD dwTotalLen = 0;
	BYTE response[SIZE_BUFFER_1024];
    BYTE apdu[SIZE_BUFFER_1024];
    INT nDivider = 0;
	INT nRemainder = 0;
    INT nKeyLen = 0;
	BYTE keyVal[SIZE_BUFFER_128];
	ULONG ulAlgID = 0;
	PSESSIONKEY stSessionKey;
	BLOCKCIPHERPARAM param;
	DEVHANDLE hDev;
	INT nIndex = 0;
#ifdef READER_TYPE_HID
    BYTE nResponseLen = 0;
	SHORT nRet = 0;
#endif
#ifdef READER_TYPE_CCID
	DWORD nResponseLen = 0;
	LONG nRet = 0;
	sv_IORequest.dwProtocol = 0;
	sv_IORequest.cbPciLength = sizeof( SCARD_IO_REQUEST );
#endif
    
	memset( szLog, 0, sizeof(szLog) );
	memset( keyVal, 0x00, sizeof(keyVal) );
		
	WriteLogToFile( pszLog );
	
//	_stprintf_s( szLog, _countof(szLog), TEXT("����CBC����/���ܣ����ݳ��� %d \n"), ulInDataLen );
	WriteLogToFile( szLog );

	stSessionKey = ((PSESSIONKEY)hKey);

	//--------�ж��㷨���ͣ�ָ����ӦAPDU
	ulAlgID = stSessionKey -> AlgID;
	hDev    = stSessionKey -> hDev;
	nKeyLen = stSessionKey -> KeyLen;
	memcpy( keyVal, stSessionKey->KeyVal, nKeyLen );
    param = stSessionKey -> Params;

	nDivider = ulInDataLen / SIZE_CBC_BLOCK;
	nRemainder = ulInDataLen % SIZE_CBC_BLOCK;

	//ÿ�μ��ܵ�������һ��blockΪ��λ��ÿ��blockΪSIZE_CBC_BLOCK������divider��block

	//remainder�Ƿ����Ϊ0��

	for( nIndex=0; nIndex<nDivider; nIndex++ )
	{
		//--------����IV�ֽ�
        memcpy( apdu, apdu_cbc_sendIV, 0x05 );
	    apdu[4] = 0x10;
	    memcpy( apdu+0x05, param.IV, param.IVLen );	

//		PrintApduToFile( 0, apdu, 0x15 );

#ifdef READER_TYPE_HID	
	    nRet = dc_pro_command( hDev, 0x15, apdu, &nResponseLen, response, 7 );
	    if( nRet != 0 )
#endif
#ifdef READER_TYPE_CCID
		nResponseLen = sizeof( response );
        nRet = SCardTransmit( (SCARDHANDLE)hDev, &sv_IORequest, apdu, 0x15, NULL, response, &nResponseLen );
        if( nRet != SCARD_S_SUCCESS )
#endif
		{
//            _stprintf_s( szLog, _countof(szLog), TEXT("CBCģʽ�·���IV�ֽ�ʧ�ܣ�������: %d \n"), nRet );
		    WriteLogToFile( szLog );
			sv_nStatus = 1;
	        return SAR_FAIL;
		}

//		PrintApduToFile( 1, response, nResponseLen );
	
//	    if( (response[nResponseLen-2] != 0x90) || (response[nResponseLen-1] != 0x00) )
//		{
//		    _stprintf_s( szLog, _countof(szLog), TEXT("CBCģʽ�·���IV�ֽ�ʧ�ܣ�״̬��: %02x%02x \n"), response[nResponseLen-2], response[nResponseLen-1] );
//		    WriteLogToFile( szLog );
//		    return SAR_FAIL;
//		}

		//--------���ͼӽ���APDU
		//--------������Կ��16�ֽ�
	    memcpy( apdu, sv_APDU, 0x05 );
	    memcpy( apdu+0x05, keyVal, nKeyLen );
		memcpy( apdu+0x15, pbInData+(nIndex*SIZE_CBC_BLOCK), SIZE_CBC_BLOCK );
		apdu[4] = 0x10 + SIZE_CBC_BLOCK;

//		PrintApduToFile( 0, apdu, 0x15+SIZE_CBC_BLOCK );

#ifdef READER_TYPE_HID
		nRet = dc_pro_command( hDev, 0x15+SIZE_CBC_BLOCK, apdu, &nResponseLen, response, 7 );
		if( nRet != 0 )
#endif
#ifdef READER_TYPE_CCID	
		nResponseLen = sizeof( response );
        nRet = SCardTransmit( (SCARDHANDLE)hDev, &sv_IORequest, apdu, 0x15+SIZE_CBC_BLOCK, NULL, response, &nResponseLen );
        if( nRet != SCARD_S_SUCCESS )
#endif
		{
//            _stprintf_s( szLog, _countof(szLog), TEXT("����CBC����/����ʧ�ܣ�������: %d \n"), nRet );
			WriteLogToFile( szLog );
			sv_nStatus = 1;
			return SAR_FAIL;
		}
//		PrintApduToFile( 1, response, nResponseLen );
	
		if( 1)//(response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
		{
			if( pbOutData != NULL )
			{
//				memcpy( pbOutData+(nIndex*SIZE_CBC_BLOCK), response, nResponseLen-2 );
			}
			
//			dwTotalLen += (nResponseLen-2);

		}
		else
		{
//			_stprintf_s( szLog, _countof(szLog), TEXT("����CBC����/����ʧ�ܣ�״̬��: %02x%02x \n"), response[nResponseLen-2], response[nResponseLen-1] );
			WriteLogToFile( szLog );
			return SAR_FAIL;	
		}
	}

	if( nRemainder != 0 )
	{
		//--------����IV�ֽ�
        memcpy( apdu, apdu_cbc_sendIV, 0x05 );
	    apdu[4] = 0x10;
	    memcpy( apdu+0x05, param.IV, param.IVLen );	

//		PrintApduToFile( 0, apdu, 0x15 );

#ifdef READER_TYPE_HID	
	    nRet = dc_pro_command( hDev, 0x15, apdu, &nResponseLen, response, 7 );
	    if( nRet != 0 )
#endif
#ifdef READER_TYPE_CCID	
		nResponseLen = sizeof( response );
        nRet = SCardTransmit( (SCARDHANDLE)hDev, &sv_IORequest, apdu, 0x15, NULL, response, &nResponseLen );
        if( nRet != SCARD_S_SUCCESS )
#endif
		{
//            _stprintf_s( szLog, _countof(szLog), TEXT("CBCģʽ�·���IV�ֽ�ʧ�ܣ�������: %d \n"), nRet );
		    WriteLogToFile( szLog );
	        return SAR_FAIL;
		}

//		PrintApduToFile( 1, response, nResponseLen );
	
	    if( 1)//(response[nResponseLen-2] != 0x90) || (response[nResponseLen-1] != 0x00) )
		{
//		    _stprintf_s( szLog, _countof(szLog), TEXT("CBCģʽ�·���IV�ֽ�ʧ�ܣ�״̬��: %02x%02x \n"), response[nResponseLen-2], response[nResponseLen-1] );
		    WriteLogToFile( szLog );
		    return SAR_FAIL;	
		}

		//--------���ͼӽ���APDU
	    memcpy( apdu, sv_APDU, 0x05 );
	    memcpy( apdu+0x05, keyVal, nKeyLen );
		memcpy( apdu+0x15, pbInData+(nDivider*SIZE_CBC_BLOCK), nRemainder );
		apdu[4] = 0x10 + (BYTE)nRemainder;

//		PrintApduToFile( 0, apdu, 0x15+nRemainder );

#ifdef READER_TYPE_HID
		nRet = dc_pro_command(hDev, 0x15+nRemainder, apdu, &nResponseLen, response, 7 );
		if( nRet != 0 )
#endif
#ifdef READER_TYPE_CCID	
		nResponseLen = sizeof( response );
        nRet = SCardTransmit( (SCARDHANDLE)hDev, &sv_IORequest, apdu, 0x15+nRemainder, NULL, response, &nResponseLen );
        if( nRet != SCARD_S_SUCCESS )
#endif
		{
//            _stprintf_s( szLog, _countof(szLog), TEXT("����CBC����/����ʧ�ܣ�������: %d \n"), nRet );
			WriteLogToFile( szLog );
			sv_nStatus = 1;
			return SAR_FAIL;
		}

//		PrintApduToFile( 1, response, nResponseLen );

		if( 1)//(response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
		{
			if( pbOutData != NULL )
			{
//				memcpy( pbOutData+(nDivider*SIZE_CBC_BLOCK), response, nResponseLen-2 );
			}

//			dwTotalLen += (nResponseLen-2);
		}
		else
		{
//			_stprintf_s( szLog, _countof(szLog), TEXT("����CBC����/����ʧ�ܣ�״̬��: %02x%02x \n"), response[nResponseLen-2], response[nResponseLen-1] );
			WriteLogToFile( szLog );
			return SAR_FAIL;
		}
	}
	
	*pulOutDataLen = dwTotalLen;
    return SAR_OK;
}


