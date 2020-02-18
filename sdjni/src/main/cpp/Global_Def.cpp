// SharedVariables.cpp: implementation of the SharedVariables class.
//
//////////////////////////////////////////////////////////////////////

//#include "stdafx.h"
//#include <skf_type.h>
#include "Global_Def.h"
#include "APDUs.h"
//#include "winscard.h"


#ifdef READER_TYPE_HID
#pragma comment( lib, "dcrf32.lib" )
#endif
#ifdef READER_TYPE_CCID
#pragma comment( lib, "winscard.lib" )
#endif


#ifdef READER_TYPE_HID
    CHAR*  sv_pszD8DevNameA = "HID_D8_TFHC";
	TCHAR* sv_pszD8DevName = TEXT( "HID_D8_TFHC" );
#endif
#ifdef READER_TYPE_CCID
    SCARDCONTEXT        sv_hContext;
    SCARD_IO_REQUEST	sv_IORequest;
	CHAR  sv_pszCCIDDevNameA[SIZE_BUFFER_1024];
	WCHAR* sv_pszCCIDDevName = _T( "SCM Microsystems Inc. SDI011G Contactless Reader 0" );
#endif
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
ULONG sv_containerType = CONTAINER_NULL;
/*
CONTAINERINFO sv_containerInfo[MAX_CONTAINER_NUM] = {
};
*/

// 有关日志变量
const CHAR* SV_PSZLOGPATH =  ("D://TMC_HealthCard_CA.log");
const CHAR* SV_PSZLOGTHREADPATH = ("D://TMC_HealthCard_CA_Thread.log");

//全局结构体变量
APPLICATIONINFO  sv_stApplication;  //应用
CONTAINERINFO    sv_stContainer;    //容器
DEVINFO          sv_stDevice;       //设备
DEVHANDLE        sv_hDev;           //设备句柄
HASHINFO         sv_stHash;         //哈希杂凑对象
//SCARDCONTEXT hSC = 0;
//SCARDHANDLE     hCardHandle;
//SCARD_IO_REQUEST	pioSendPci;


//有关容器定义变量
//注：
//--容器名称
BYTE  sv_containerNameInfo[MAX_CONTAINER_NUM][SIZE_CONTAINER_ITEM];
BYTE  sv_containerCurrentIndex = 0;

//--容器内密钥文件SFI
const BYTE SV_CONTAINER_SFI[MAX_CONTAINER_NUM][6] = {
	{0x0A, 0x0B, 0x0C, 0x13, 0x14, 0x19}, //容器1
	{0x0D, 0x0E, 0x0F, 0x15, 0x16, 0x1A}, //容器2
	{0x10, 0x11, 0x12, 0x17, 0x18, 0x1B}  //容器3
};

//有关文件定义变量
//--文件名称
BYTE  sv_fileNameInfo[MAX_FILE_NUM][SIZE_FILE_ITEM];
BYTE  sv_fileCurrentIndex = 0;

//--文件FID和SFI
const BYTE SV_EF_FID[MAX_FILE_NUM][2] = {
	{0xEF,0x04},  //文件1
	{0xEF,0x05},  //文件2
	{0xEF,0x06},  //文件3
	{0xEF,0x07},  //文件4
	{0xEF,0x08}   //文件5
};

//有关应用定义变量
//--应用名称
BYTE  sv_appNameInfo[MAX_APPLICATION_NUM][SIZE_APPLICATION_ITEM];
BYTE  sv_appCurrentIndex = 0;
CHAR  sv_appName[33];
//--应用FID
const BYTE SV_ADF_FID[MAX_APPLICATION_NUM][2] = {
	{0xDF,0x01},  //应用1
	{0xDF,0x02},  //应用2
	{0xDF,0x03},  //应用3
	{0xDF,0x04},  //应用4
	{0xDF,0x05},  //应用5
	{0xDF,0x06},  //应用6
	{0xDF,0x07}   //应用7
};


//有关PIN定义变量
BYTE  sv_pinIndex[2] = { 0x02, 0x01 };

BYTE  sv_APDU[0x05];

//有关设备认证定义变量
int sv_nAuth  = 0;   //外部认证，设备认证
int sv_nUser  = 0;   //用户PIN
int sv_nAdmin = 0;  //管理员PIN

//有关随机数定义变量
BYTE  sv_random[SIZE_BUFFER_1024];   //全局随机数缓冲区，最大为1024字节
DWORD sv_randomLength = 0;           //全局随机数缓冲区长度计数；

//有关签名定义变量
ECCSIGNATUREBLOB sv_eccSignBlob;
BYTE sv_signEF_FID[2] = { 0x00, 0x00 };

//全局数据缓冲区
BYTE  sv_tmpData[1024000];  //1000K
DWORD sv_tmpDataLen = 0;


INT sv_nStatus = -1;
BOOL sv_fEnd = TRUE;
//BYTE sv_devAuth = 0x00;    //设备是否认证，0x00：没有认证；0x01：已经认证。默认没有认证
#ifdef READER_TYPE_HID
void PrintApduToFile( BYTE bFlag, BYTE* pbApdu, BYTE nLength )
{
	FILE* pFileLog;
	errno_t nErr = -1;
	TCHAR szLog[1024];
	nErr = _tfopen_s( &pFileLog, SV_PSZLOGPATH, TEXT("a+") );
	if( nErr == 0 )
	{
		if( bFlag == 0 )
			_fputts( TEXT("Apdu:\n"), pFileLog );
		else
			_fputts( TEXT("Response:\n"), pFileLog );
		for( BYTE bIndex=0; bIndex<nLength; bIndex++ )
		{
			_stprintf_s( szLog, _countof(szLog), TEXT("%02X"), pbApdu[bIndex] );
            _fputts( szLog, pFileLog );
		}
	
		_fputts( TEXT("\n"), pFileLog );
		fclose( pFileLog );
	}
}
#endif

#ifdef READER_TYPE_CCID
void PrintApduToFile( BYTE bFlag, BYTE* pbApdu, DWORD bLength )
{
	FILE* pFileLog;
	errno_t nErr = -1;
	TCHAR szLog[1024];
	nErr = _tfopen_s( &pFileLog, SV_PSZLOGPATH, TEXT("a+") );
	if( nErr == 0 )
	{
		if( bFlag == 0 )
			_fputts( TEXT("Apdu:\n"), pFileLog );
		else
			_fputts( TEXT("Response:\n"), pFileLog );
		for( DWORD dwIndex=0; dwIndex<bLength; dwIndex++ )
		{
			_stprintf_s( szLog, _countof(szLog), TEXT("%02X"), pbApdu[dwIndex] );
            _fputts( szLog, pFileLog );
		}
	
		_fputts( TEXT("\n"), pFileLog );
		fclose( pFileLog );
	}
}
#endif

void WriteLogToFile( CHAR* szLog )
{
	FILE* pFileLog;

	pFileLog = fopen( SV_PSZLOGPATH, "a+");
	if( pFileLog == NULL )
	{
//        _fputts( szLog, pFileLog );
	
		fclose( pFileLog );
	}
}

void ResetLogFile(char * lpszName )
{
	FILE* pFileLog;
	pFileLog = fopen( lpszName, ("w+") );
	if( pFileLog == NULL )
	{
		fclose( pFileLog );
	}
}
void WriteLogToFile2( CHAR* szLog )
{
	FILE* pFileLog;

	pFileLog = fopen( SV_PSZLOGTHREADPATH, ("a+") );
	if( pFileLog == NULL )
	{
//        _fputts( szLog, pFileLog );
	
		fclose( pFileLog );
	}
}

ULONG sc_command(DEVHANDLE hDev, BYTE* inBuf, DWORD inLen, BYTE* retBuf, DWORD* pdwLen)
{
	return 0; //SCardTransmit(hDev, &pioSendPci, (LPCBYTE)inBuf, inLen, NULL, retBuf, pdwLen);
}

//DES/TDES，ECB模式，加密

//DES/TDES，ECB模式，加密
BYTE cryptoDESEcbEnc(BYTE *pbKey, BYTE bKeyLen, BYTE *pbDatIn, UINT16 usLen, BYTE *pbDatOut)
{
	des_context des_ctx;
	des3_context des3_ctx;
	int i, divider, remainder;
    
	//包括1个KEY,2个KEY,3个KEY
	unsigned char block[SIZE_BUFFER_8];  //8字节的BLOCK
	unsigned char out[SIZE_BUFFER_8+1];

	memset(block, 0, sizeof(block));
	memset(out, 0, sizeof(out));

	divider = remainder = 0;

	divider = usLen / SIZE_BUFFER_8;
	remainder = usLen % SIZE_BUFFER_8;

	
	switch(bKeyLen)
	{
	    case SIZE_BUFFER_8:
		{
//			des_setkey_enc(&des_ctx, pbKey);
			break;
		}
	    case SIZE_BUFFER_16:
		{
//			des3_set2key_enc(&des3_ctx, pbKey);
			break;
		}
	    default:
		{
			return 0x01;
			break;
		}
	}
	
	for( i=0; i<divider; i++ )
	{
		memcpy(block, pbDatIn+(i*SIZE_BUFFER_8), SIZE_BUFFER_8);

		if(bKeyLen == SIZE_BUFFER_8)
		{
//		    des_crypt_ecb(&des_ctx, block, out);
		}
		else
		{
//			des3_crypt_ecb(&des3_ctx, block, out);
		}
		
		memcpy(pbDatOut+(i*SIZE_BUFFER_8), out, SIZE_BUFFER_8);
	}
			
	if(remainder != 0)
	{
		memcpy(block, pbDatIn+(divider*SIZE_BUFFER_8), remainder);
		block[remainder] = 0x80;
		remainder ++;
		i = remainder;
		for(; i<SIZE_BUFFER_8; i++)
		{
			block[i] = 0x00;
		}

		if(bKeyLen == SIZE_BUFFER_8)
		{
//		    des_crypt_ecb(&des_ctx, block, out);
		}
		else
		{
//			des3_crypt_ecb(&des3_ctx, block, out);
		}
		memcpy(pbDatOut+(divider*SIZE_BUFFER_8), out, SIZE_BUFFER_8);
	}

	return 0x00; 
	
}


BYTE cryptoDESMAC(BYTE *pbKey, BYTE *pbIv, BYTE * pbDatIn, BYTE bDatLen, BYTE *pbDatOut)
{
	int i,k;
	BYTE size;
	BYTE remainder;
	BYTE block[SIZE_BUFFER_8];
	BYTE in[SIZE_BUFFER_8];
	BYTE out[SIZE_BUFFER_8];
	BYTE key[SIZE_BUFFER_32];
	BYTE datIn[SIZE_BUFFER_1024];
	BYTE initV[SIZE_BUFFER_8];
	des_context des_ctx;
	BYTE ret;

	memset(block, 0, sizeof(block));
	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));
	memset(key, 0, sizeof(key));
	memset(datIn, 0, sizeof(datIn));
	memset(initV, 0, sizeof(initV));

	
	ret = 1;
	size = remainder = 0;
    
	//
	memcpy( key, pbKey, 0x08 );
	memcpy( datIn, pbDatIn, bDatLen );
	memcpy( initV, pbIv, 0x08 );
	
	size = bDatLen / SIZE_BUFFER_8;
	remainder = bDatLen % SIZE_BUFFER_8;
	
//	des_setkey_enc(&des_ctx, key);
	memcpy(out, initV, SIZE_BUFFER_8);
	
	for(k=0; k< size; k++)
	{
		memcpy(block, datIn+(k*SIZE_BUFFER_8), SIZE_BUFFER_8);
		i = 0;
		for(i=0; i<SIZE_BUFFER_8; i++)
		{
			in[i] = out[i] ^ block[i];
		}
//		des_crypt_ecb(&des_ctx, in, out);
	}

	memcpy(block, datIn+(size*SIZE_BUFFER_8), remainder);
	block[remainder] = 0x80;
	remainder ++;
	i = remainder;
	for(; i<SIZE_BUFFER_8; i++)
	{
		block[i] = 0x00;
	}
	
	for(i=0; i<SIZE_BUFFER_8; i++)
	{
		in[i] = out[i] ^ block[i];
	}

//	des_crypt_ecb(&des_ctx, in, out);
	
	memcpy(pbDatOut, out, 4);
	
	return 0x00;
}

BYTE crypto3DESMAC(BYTE *pbKey, BYTE *pbIv, BYTE * pbDatIn, BYTE bDatLen, BYTE *pbDatOut)
{
    int i,k;
	unsigned char size;
	unsigned char remainder;
	unsigned char block[SIZE_BUFFER_8];
	unsigned char in[SIZE_BUFFER_8];
	unsigned char out[SIZE_BUFFER_8];
	unsigned char key_l[SIZE_BUFFER_8];
	unsigned char key_r[SIZE_BUFFER_8];
	unsigned char key[SIZE_BUFFER_32];
	unsigned char datIn[SIZE_BUFFER_1024];
	unsigned char initV[SIZE_BUFFER_8];
	des_context des_ctx;
	BYTE ret;
	
	memset(block, 0, sizeof(block));
	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));
	memset(key_l, 0 ,sizeof(key_l));
	memset(key_r, 0, sizeof(key_r));
	memset(key, 0, sizeof(key));
	memset(datIn, 0, sizeof(datIn));
	memset(initV, 0, sizeof(initV));
	
	ret = 1;
	size = remainder = 0;
	
	//将输入数据分块
	size = bDatLen / SIZE_BUFFER_8;
	remainder = bDatLen % SIZE_BUFFER_8;
	
	//将16字节Key分别放入左键和右键内，个8字节
	memcpy(key_l, key, SIZE_BUFFER_8);
	memcpy(key_r, key+8, SIZE_BUFFER_8);
	
	//左键加密
//	des_setkey_enc(&des_ctx, key_l);
	
	memcpy(out, initV, SIZE_BUFFER_8);
	
	for(k=0; k<size; k++)
	{
	    memcpy(block, datIn+(k*SIZE_BUFFER_8), SIZE_BUFFER_8);
		i = 0;
		for(i=0; i<SIZE_BUFFER_8; i++)
		{
		    in[i] = out[i] ^ block[i];
		}
		
//		des_crypt_ecb(&des_ctx, in, out);
	}
	
	memcpy(block, datIn+(size*SIZE_BUFFER_8), remainder);
	block[remainder] = 0x80;
	remainder ++;
	i = remainder;
	for(; i<SIZE_BUFFER_8; i++)
	{
	    block[i] = 0x00;
	}
	
	for(i=0; i<SIZE_BUFFER_8; i++)
	{
	    in[i] = out[i] ^ block[i];
	}
	
//	des_crypt_ecb(&des_ctx, in, out);
	
	memcpy(in, out, SIZE_BUFFER_8);

//	des_setkey_dec(&des_ctx, key_r);
//	des_crypt_ecb(&des_ctx, in, out);


	memcpy(in, out, SIZE_BUFFER_8);
//	des_setkey_enc(&des_ctx, key_l);
//	des_crypt_ecb(&des_ctx, in, out);

	memcpy(pbDatOut, out, 4);

	return 0x00;
}


ULONG SV_SelectDFByFID( DEVHANDLE hDev, const BYTE appFID[2], CHAR *pszLog )
{
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE apdu[SIZE_BUFFER_1024];
	BYTE response[SIZE_BUFFER_1024];
	
#ifdef READER_TYPE_CCID
	sv_IORequest.dwProtocol = 0;
	sv_IORequest.cbPciLength = sizeof( SCARD_IO_REQUEST );
#endif

	DWORD nResponseLen = 0;
	LONG nRet = 0;
	memset( apdu, 0x00, sizeof(apdu) );
	memset( response, 0x00, sizeof(response) );
	memset( szLog, 0x0, sizeof(szLog) );

	//--------选择DF
	memcpy( apdu, apdu_selectDF, 0x07 );

	apdu[5] = appFID[0];
	apdu[6] = appFID[1];

//	PrintApduToFile( 0, apdu, 0x07 );

#if 0
	nResponseLen = sizeof( response );
	nRet = sc_command(hDev, apdu, 0x05+0x10, response, &nResponseLen);
   	if( nRet != SCARD_S_SUCCESS )
	{
		_stprintf_s( szLog, _countof(szLog), TEXT("%s失败，错误码: %d \n"), pszLog, nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}

	PrintApduToFile( 1, response, nResponseLen );

	if( (response[nResponseLen-2] != 0x90) || (response[nResponseLen-1] != 0x00) )
	{
		_stprintf_s( szLog, _countof(szLog), TEXT("%s失败，状态码: %02X%02X \n"), pszLog, 
			response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

	return SAR_OK;

#endif

	

#ifdef READER_TYPE_HID
	nRet = dc_pro_command( hDev, 0x07, apdu, &nResponseLen, response, 7 );
	if( nRet != 0 )
#endif
#ifdef READER_TYPE_CCID	
	nResponseLen = sizeof( response );
    nRet = SCardTransmit( (SCARDHANDLE)hDev, &sv_IORequest, apdu, 0x07, NULL, response, &nResponseLen );
    if( nRet != SCARD_S_SUCCESS )
#endif
	{
//		_stprintf_s( szLog, _countof(szLog), TEXT("%s失败，错误码: %d \n"), pszLog, nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}

//	PrintApduToFile( 1, response, nResponseLen );

	if( (response[nResponseLen-2] != 0x90) || (response[nResponseLen-1] != 0x00) )
	{
//		_stprintf_s( szLog, _countof(szLog), TEXT("%s失败，状态码: %02X%02X \n"), pszLog,
//			response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

	return SAR_OK;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONG FindDFByAppName( DEVHANDLE hDev, LPSTR szAppName, BYTE *appFID )
{
	CHAR* pszLog = ( "Start to execute FindDFByAppName \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	DWORD dwAppListSize = 0;
	//BYTE appNameSize = 0x00;
	BYTE response[SIZE_BUFFER_1024];
	BYTE apdu[SIZE_BUFFER_1024];
	BYTE bIsFound = 0x00;
	INT nIndex = 0;
    size_t nAppNameLen = 0;
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
	memset( szLog, 0x0, sizeof(szLog) );

	WriteLogToFile( pszLog );

	if( hDev == NULL )
	{
		return SAR_INVALIDHANDLEERR;
	}

	if( (NULL == szAppName) || (NULL == appFID) )
	{
		return SAR_APPLICATION_NAME_INVALID;
	}

	nAppNameLen = strlen( szAppName );

    //--------选择CA环境DDF3
	if( SV_SelectDFByFID(hDev, APDU_CA_FID, "选择CA环境") != SAR_OK )
		return SAR_FAIL;
	
	//--------读取CA下EF01文件
	memcpy( apdu, apdu_readBinary, 0x05 );
	apdu[2] |= APDU_EF01_FID[1];
	apdu[3] = 0x00;
	apdu[4] = SIZE_CA_EF01;

//	PrintApduToFile( 0, apdu, 0x05 );

#ifdef READER_TYPE_HID
	nRet = dc_pro_command( hDev, 0x05, apdu, &nResponseLen, response, 7 );
	if( nRet != 0 )
#endif
#ifdef READER_TYPE_CCID	
    nResponseLen = sizeof( response );
    nRet = SCardTransmit( (SCARDHANDLE)hDev, &sv_IORequest, apdu, 0x05, NULL, response, &nResponseLen );
    if( nRet != SCARD_S_SUCCESS )
#endif
	{
//		_stprintf_s( szLog, _countof(szLog), TEXT("读取CA下EF01失败，错误码: %d \n"), nRet );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

//	PrintApduToFile( 1, response, nResponseLen );

//	if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
//	{
//        for( nIndex=0; nIndex<MAX_APPLICATION_NUM; nIndex++ )
//		{
//			memcpy( sv_appNameInfo[nIndex], response+(nIndex*SIZE_APPLICATION_ITEM), SIZE_APPLICATION_ITEM );
//		}
//	}
//	else
//	{
//		_stprintf_s( szLog, _countof(szLog), TEXT("读取CA下EF01失败，状态码: %02X%02X \n"), response[nResponseLen-2], response[nResponseLen-1] );
//		WriteLogToFile( szLog );
//		return SAR_FAIL;
//	}

	for( nIndex=0; nIndex<MAX_APPLICATION_NUM; nIndex++ )
	{
		if( nAppNameLen != sv_appNameInfo[nIndex][0] )
		{
			bIsFound = 0x02;
		}
		else  //长度相等
		{
			bIsFound = 0x00;
			for( size_t m=0; m<nAppNameLen; m++ )
			{
                if( szAppName[m] == sv_appNameInfo[nIndex][m+1] )
				{
				}
				else
				{
					bIsFound = 0x01;
					break;
				}
			}
		}

		//一次比对结束
		if( bIsFound == 0x00 )  //比对成功
		{
			appFID[0] = sv_appNameInfo[nIndex][33];
			appFID[1] = sv_appNameInfo[nIndex][34];
			sv_appCurrentIndex = nIndex;
			return SAR_OK;
		}
	}

    return SAR_FAIL;

}


ULONG OpenApplication( DEVHANDLE hDev, LPSTR szAppName )
{
	CHAR* pszLog = ( "OpenApplication \n" );
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE appFID[2] = { 0xDF, 0x00 };

#ifdef READER_TYPE_HID

#endif
#ifdef READER_TYPE_CCID

#endif

    memset( szLog, 0x0, sizeof(szLog) );
	
	WriteLogToFile( pszLog );

	CHAR* pszUnicode;
	INT nRetUNI = 0;
//	nRetUNI = MultiByteToWideChar( CP_ACP , 0, szAppName, -1, NULL, 0 );
//	pszUnicode = new WCHAR[nRetUNI*sizeof(WCHAR)];
//	MultiByteToWideChar( CP_ACP, 0, szAppName, -1, pszUnicode, nRetUNI*sizeof(WCHAR) );
//	_stprintf_s( szLog, _countof(szLog), TEXT("OpenApplication, 应用名称：%s\n"), pszUnicode );
	WriteLogToFile( szLog );
	delete pszUnicode;

	//--------设备句柄不能为空
	if( hDev == NULL )
	{
		return SAR_INVALIDHANDLEERR;
	}

	//--------应用名称不能为空
	if( szAppName == NULL )
	{
//		_stprintf_s( szLog, _countof(szLog), TEXT("应用名称无效，无法打开 \n") );
		WriteLogToFile( szLog );
		return SAR_APPLICATION_NAME_INVALID;
	}

	//--------选择MF

	//--------选择CA环境DDF3

	//--------根据应用名称找到应用的FID
	if( SAR_OK != FindDFByAppName( hDev, szAppName, appFID ) )
	{
//		_stprintf_s( szLog, _countof(szLog), TEXT("应用查找失败，可能不存在该应用或应用名称错误 \n") );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

	//--------选择ADF，通过FID选择
	if( SV_SelectDFByFID( hDev, appFID, "选择ADF") != SAR_OK )
		return SAR_FAIL;

    return SAR_OK;

}
