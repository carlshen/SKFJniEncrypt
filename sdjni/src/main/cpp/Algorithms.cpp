//#include "stdafx.h"
#include "Global_Def.h"

#define SIZE_BUFFER_224        (16*14)
#define SIZE_ECB_BLOCK SIZE_BUFFER_224
#define SIZE_CBC_BLOCK SIZE_BUFFER_224
//该函数使用于分组算法的ECB模式，如SM1 ECB, SSF33 ECB和SM4 ECB
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

//	_stprintf_s( szLog, _countof(szLog), TEXT("分组ECB加密/解密，数据长度 %d \n"), ulInDataLen );
	WriteLogToFile( szLog );

	stSessionKey = ((PSESSIONKEY)hKey);

	//--------判断算法类型，指定对应APDU
	ulAlgID = stSessionKey -> AlgID;
	hDev    = stSessionKey -> hDev;
	nKeyLen = stSessionKey -> KeyLen;
	memcpy( keyVal, stSessionKey->KeyVal, nKeyLen );

	//--------导入密钥，16字节
	memcpy( apdu, sv_APDU, 0x05 );
	memcpy( apdu+0x05, keyVal, nKeyLen );

	nDivider = ulInDataLen / SIZE_ECB_BLOCK;   
	nRemainder = ulInDataLen % SIZE_ECB_BLOCK;

	//每次加密的数据以一个block为单位，每个block为SIZE_ECB_BLOCK，共计divider个block

	//remainder是否必须为0？

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
//            _stprintf_s( szLog, _countof(szLog), TEXT("分组ECB加密/解密失败，第%d组，错误码: %d \n"), nIndex, nRet );
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
//			_stprintf_s( szLog, _countof(szLog), TEXT("分组ECB加密/解密失败，状态码: %02x%02x \n"), response[nResponseLen-2], response[nResponseLen-1] );
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
//            _stprintf_s( szLog, _countof(szLog), TEXT("分组ECB加密/解密失败，错误码: %d \n"), nRet );
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
//			_stprintf_s( szLog, _countof(szLog), TEXT("分组ECB加密/解密失败，状态码: %02x%02x \n"), response[nResponseLen-2], response[nResponseLen-1] );
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

//该函数使用于分组算法的CBC模式，如SM1 CBC, SSF33 CBC和SM4 CBC
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
	
//	_stprintf_s( szLog, _countof(szLog), TEXT("分组CBC加密/解密，数据长度 %d \n"), ulInDataLen );
	WriteLogToFile( szLog );

	stSessionKey = ((PSESSIONKEY)hKey);

	//--------判断算法类型，指定对应APDU
	ulAlgID = stSessionKey -> AlgID;
	hDev    = stSessionKey -> hDev;
	nKeyLen = stSessionKey -> KeyLen;
	memcpy( keyVal, stSessionKey->KeyVal, nKeyLen );
    param = stSessionKey -> Params;

	nDivider = ulInDataLen / SIZE_CBC_BLOCK;
	nRemainder = ulInDataLen % SIZE_CBC_BLOCK;

	//每次加密的数据以一个block为单位，每个block为SIZE_CBC_BLOCK，共计divider个block

	//remainder是否必须为0？

	for( nIndex=0; nIndex<nDivider; nIndex++ )
	{
		//--------发送IV字节
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
//            _stprintf_s( szLog, _countof(szLog), TEXT("CBC模式下发送IV字节失败，错误码: %d \n"), nRet );
		    WriteLogToFile( szLog );
			sv_nStatus = 1;
	        return SAR_FAIL;
		}

//		PrintApduToFile( 1, response, nResponseLen );
	
//	    if( (response[nResponseLen-2] != 0x90) || (response[nResponseLen-1] != 0x00) )
//		{
//		    _stprintf_s( szLog, _countof(szLog), TEXT("CBC模式下发送IV字节失败，状态码: %02x%02x \n"), response[nResponseLen-2], response[nResponseLen-1] );
//		    WriteLogToFile( szLog );
//		    return SAR_FAIL;
//		}

		//--------发送加解密APDU
		//--------导入密钥，16字节
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
//            _stprintf_s( szLog, _countof(szLog), TEXT("分组CBC加密/解密失败，错误码: %d \n"), nRet );
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
//			_stprintf_s( szLog, _countof(szLog), TEXT("分组CBC加密/解密失败，状态码: %02x%02x \n"), response[nResponseLen-2], response[nResponseLen-1] );
			WriteLogToFile( szLog );
			return SAR_FAIL;	
		}
	}

	if( nRemainder != 0 )
	{
		//--------发送IV字节
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
//            _stprintf_s( szLog, _countof(szLog), TEXT("CBC模式下发送IV字节失败，错误码: %d \n"), nRet );
		    WriteLogToFile( szLog );
	        return SAR_FAIL;
		}

//		PrintApduToFile( 1, response, nResponseLen );
	
	    if( 1)//(response[nResponseLen-2] != 0x90) || (response[nResponseLen-1] != 0x00) )
		{
//		    _stprintf_s( szLog, _countof(szLog), TEXT("CBC模式下发送IV字节失败，状态码: %02x%02x \n"), response[nResponseLen-2], response[nResponseLen-1] );
		    WriteLogToFile( szLog );
		    return SAR_FAIL;	
		}

		//--------发送加解密APDU
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
//            _stprintf_s( szLog, _countof(szLog), TEXT("分组CBC加密/解密失败，错误码: %d \n"), nRet );
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
//			_stprintf_s( szLog, _countof(szLog), TEXT("分组CBC加密/解密失败，状态码: %02x%02x \n"), response[nResponseLen-2], response[nResponseLen-1] );
			WriteLogToFile( szLog );
			return SAR_FAIL;
		}
	}
	
	*pulOutDataLen = dwTotalLen;
    return SAR_OK;
}


