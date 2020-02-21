// SKF_ContainerManager.cpp: implementation of the SKF_ContainerManager class.
//
//////////////////////////////////////////////////////////////////////

#include <string.h>
#include "SKF_TypeDef.h"
#include "Global_Def.h"
#include "Algorithms.h"
#include "transmit.h"
#include "SKF_ContainerManager.h"

#ifdef __cplusplus
extern "C" {
#endif  /*__cplusplus*/

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* 函数名称：SKF_ImportCertificate
* 函数功能：导入数字证书
* 参数列表：hContainer: [IN], 密钥句柄
*           bSignFlag:  [IN], TRUE表示签名证书；FALSE表示加密证书
*           pbCert:     [IN], 指向证书内容缓冲区
*           ulCertLen:  [IN], 证书长度
* 返 回 值：SAR_OK: 成功
            其他值:错误码
*/
ULONG SKF_ImportCertificate( HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbCert, ULONG ulCertLen )
{
	CHAR* pszLog = "**********Start to execute SKF_ImportCertificate ********** \n";
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE appFID[2] = { 0xDF, 0x00 };
	BYTE fileSFI[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE bSFI = 0x00;
	BYTE apdu[SIZE_BUFFER_1024];
	BYTE response[SIZE_BUFFER_1024];
	HAPPLICATION hApplication;
	PAPPLICATIONINFO pApplication;
    PCONTAINERINFO pContainer;
	INT nDivider = 0;
	INT nRemainder = 0;
	INT nIndex = 0;
	ULONG dwOffset = 0;
	DEVHANDLE hDev;
	DWORD nResponseLen = 0;
	LONG nRet = 0;
	//--------容器句柄不能为空
	if( hContainer == NULL )
	{
		return SAR_INVALIDHANDLEERR;
	}

	pContainer = (PCONTAINERINFO)hContainer;
	hApplication = pContainer -> hApplication;
	memcpy( fileSFI, pContainer->bSFI, sizeof(fileSFI) );
	pApplication = (PAPPLICATIONINFO)hApplication;
	hDev = pApplication -> hDev;
	memcpy( appFID, pApplication->ApplicationFID, 0x02 );

	WriteLogToFile( pszLog );
	sv_fEnd = FALSE;
	memset( apdu, 0x00, sizeof(apdu) );
	memset( response, 0x00, sizeof(response) );
	memset( szLog, 0x0, strlen(szLog) );

	//--------选择ADF，通过FID选择
	if( SV_SelectDFByFID(hDev, appFID, "选择ADF") != SAR_OK )
		return SAR_FAIL;

	//--------更新ADF下的证书文件
	memcpy( apdu, apdu_updateBinary, 0x05 );

	if( !bSignFlag ) //加密证书
	{
		bSFI = fileSFI[0];
	}
	else   //签名证书
	{
		bSFI = fileSFI[1];
	}


	//--------更新证书文件
	nDivider = ulCertLen / 0xF0;
	nRemainder = ulCertLen % 0xF0;

	//--------写入证书长度，4字节
	memcpy( apdu, apdu_updateBinary, 0x05 );

	apdu[2] |= bSFI;
	apdu[3] = 0x00;
	apdu[4] = 0x04;
	apdu[5] = (BYTE)(ulCertLen>>24);
	apdu[6] = (BYTE)(ulCertLen>>16);
	apdu[7] = (BYTE)(ulCertLen>>8);
	apdu[8] = (BYTE)(ulCertLen);

//	PrintApduToFile( 0, apdu, 0x05+0x04 );

    nResponseLen = sizeof( response );
    nRet = TransmitData( hDev, apdu, 0x05+0x04, response, &nResponseLen );
    if( nRet != SAR_OK )
	{
		sprintf( szLog, "导入证书文件失败，错误码: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}

//	PrintApduToFile( 1, response, nResponseLen );

	if( (response[nResponseLen-2] != 0x90) || (response[nResponseLen-1] != 0x00) )
	{
		sprintf( szLog, "导入证书文件失败，状态码: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

	for( nIndex=0; nIndex<nDivider; nIndex++ )
	{
		dwOffset =  0x04 + (nIndex*0xF0);
		if( nIndex == 0 )
		{
		    apdu[2] |= bSFI;            //SFI
		}
		else
		{
			apdu[2] = (BYTE)(dwOffset >> 8);
		}
		apdu[3] = (BYTE)dwOffset;  //偏移量
		apdu[4] = 0xF0;          //大小

		if( pbCert != NULL )
		{
			memcpy( apdu+0x05, pbCert+(nIndex*0xF0), 0xF0 );
		}

//		PrintApduToFile( 0, apdu, 0x05 +0xF0);

        nResponseLen = sizeof( response );
        nRet = TransmitData( hDev, apdu, 0x05+0xF0, response, &nResponseLen );
        if( nRet != SAR_OK )
		{
			sprintf( szLog, "导入证书文件失败，错误码: %d \n", nRet );
		    WriteLogToFile( szLog );
			sv_nStatus = 1;
		    return SAR_FAIL;
		}

//		PrintApduToFile( 1, response, nResponseLen );

	    if( (response[nResponseLen-2] != 0x90) || (response[nResponseLen-1] != 0x00) )
		{
			sprintf( szLog, "导入证书文件失败，状态码: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
		    WriteLogToFile( szLog );
		    return SAR_FAIL;
		}
    }

	if( nRemainder != 0 )
	{
		dwOffset = 0x04 + (nDivider*0xF0);
		if( nDivider == 0 )
		{
		    apdu[2] |= bSFI;  //SFI
		}
		else
		{
			apdu[2] = (BYTE)(dwOffset >> 8);
		}
		apdu[3] = (BYTE)dwOffset;  //偏移量
		apdu[4] = (BYTE)nRemainder; //大小

		if( pbCert != NULL )
			memcpy( apdu+0x05, pbCert+(nDivider*0xF0), nRemainder );

//		PrintApduToFile( 0, apdu, 0x05+nRemainder );

        nResponseLen = sizeof( response );
        nRet = TransmitData( hDev, apdu, 0x05+nRemainder, response, &nResponseLen );
        if( nRet != SAR_OK )
		{
			sprintf( szLog, "导入证书文件失败，错误码: %d \n", nRet );
		    WriteLogToFile( szLog );
			sv_nStatus = 1;
		    return SAR_FAIL;
		}

//		PrintApduToFile( 1, response, nResponseLen );

	    if( (response[nResponseLen-2] != 0x90) || (response[nResponseLen-1] != 0x00) )
		{
			sprintf( szLog, "导入证书文件失败，状态码: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
	    	WriteLogToFile( szLog );
		    return SAR_FAIL;
	   }

    }
	return SAR_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* 函数名称：SKF_ExportCertificate
* 函数功能：导出数字证书
* 参数列表：hContainer: [IN], 容器句柄
*           bSignFlag:  [IN], TRUE表示签名证书；FALSE表示加密证书
*           pbCert:     [IN], 指向证书内容缓冲区，为NULL时，pulCerLen表示返回数据所需要缓冲区的长度，反之返回数字证书内容
*           pulCerLen:  [IN/OUT], 输入时表示pbCert缓冲区长度；输出时表示证书内容的长度
* 返 回 值：SAR_OK: 成功
            其他值:错误码
*/

ULONG SKF_ExportCertificate( HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbCert, ULONG* pulCertLen )
{
	CHAR* pszLog = "**********Start to execute SKF_ExportCertificate ********** \n";
    CHAR szLog[SIZE_BUFFER_1024];
	BYTE appFID[2] = { 0xDF, 0x00 };
	BYTE fileSFI[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE bSFI = 0x00;
	BYTE apdu[SIZE_BUFFER_1024];
	BYTE response[SIZE_BUFFER_1024];
	HAPPLICATION hApplication;
	PAPPLICATIONINFO pApplication;
    PCONTAINERINFO pContainer;
	INT nIndex = 0;
	INT nDivider = 0;
	INT nRemainder = 0;
	ULONG dwOffset = 0;
	DWORD dwCertificateSize = 0;
	DEVHANDLE hDev;
	DWORD nResponseLen = 0;
	LONG nRet = 0;
	sv_fEnd = FALSE;
	memset( apdu, 0x00, sizeof(apdu) );
	memset( response, 0x00, sizeof(response) );
	memset( szLog, 0x0, strlen(szLog) );
	
	WriteLogToFile( pszLog );

	if( hContainer == NULL )
	{
		return SAR_INVALIDHANDLEERR;
	}

	pContainer = (PCONTAINERINFO)hContainer;
	hApplication = pContainer -> hApplication;
	memcpy( fileSFI, pContainer->bSFI, sizeof(fileSFI) );
	pApplication = (PAPPLICATIONINFO)hApplication;
	hDev = pApplication -> hDev;
	memcpy( appFID, pApplication->ApplicationFID, 0x02 );

	//--------选择ADF，通过FID选择
	if( SV_SelectDFByFID(hDev, appFID, "") != SAR_OK )
		return SAR_FAIL;

	//--------读取ADF下的证书文件
	memcpy( apdu, apdu_updateBinary, 0x05 );

	if( !bSignFlag ) //加密证书
	{
		bSFI = fileSFI[0];
	}
	else   //签名证书
	{
		bSFI = fileSFI[1];
	}


	//--------读取证书长度，4字节
	memcpy( apdu, apdu_readBinary, 0x05 );
	
	apdu[2] |= bSFI; //SFI
    apdu[3] = 0x00;  //偏移量
	apdu[4] = 0x04;   //大小

//	PrintApduToFile( 0, apdu, 0x05 );

    nResponseLen = sizeof( response );
    nRet = TransmitData( hDev, apdu, 0x05, response, &nResponseLen );
    if( nRet != SAR_OK )
	{
		sprintf( szLog, "导出证书文件失败，错误码: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}

//	PrintApduToFile( 1, response, nResponseLen );

	if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
	{
		dwCertificateSize = (response[0]<<24) | (response[1]<<16) | (response[2]<<8) | (response[3]);
	}
	else
	{
		sprintf( szLog, "导出证书文件失败，状态码: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

	//--------读取证书文件
	nDivider = dwCertificateSize / 0xF0;
	nRemainder = dwCertificateSize % 0xF0;

	for( nIndex=0; nIndex<nDivider; nIndex++ )
	{	
		dwOffset =  0x04 + (nIndex*0xF0);
		if( nIndex == 0 )
		{
		    apdu[2] |= bSFI;            //SFI
		}
		else
		{
			apdu[2] = (BYTE)(dwOffset >> 8);
		}
		apdu[3] = (BYTE)dwOffset;  //偏移量
		apdu[4] = 0xF0;          //大小

//		PrintApduToFile( 0, apdu, 0x05 );

        nResponseLen = sizeof( response );
        nRet = TransmitData( hDev, apdu, 0x05, response, &nResponseLen );
        if( nRet != SAR_OK )
		{
			sprintf( szLog, "导出证书文件失败，错误码: %d \n", nRet );
		    WriteLogToFile( szLog );
			sv_nStatus = 1;
		    return SAR_FAIL;
		}

//		PrintApduToFile( 1, response, nResponseLen );

	    if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
		{
			if( pbCert != NULL )
			{
				memcpy( pbCert+(nIndex*0xF0), response, nResponseLen-2 );
			}
		}
	    else
		{
			sprintf( szLog, "导出证书文件失败，状态码: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
		    WriteLogToFile( szLog );
		    return SAR_FAIL;
		}

    }

	if( nRemainder != 0 )
	{
		dwOffset = 0x04 + (nDivider*0xF0);
		if( nDivider == 0 )
		{
		    apdu[2] |= bSFI;  //SFI
		}
		else
		{
			apdu[2] = (BYTE)(dwOffset >> 8);
		}
		apdu[3] = (BYTE)dwOffset;  //偏移量
		apdu[4] = (BYTE)nRemainder; //大小

//		PrintApduToFile( 0, apdu, 0x05 );

        nResponseLen = sizeof( response );
        nRet = TransmitData( hDev, apdu, 0x05, response, &nResponseLen );
        if( nRet != SAR_OK )
		{
			sprintf( szLog, "导出证书文件失败，错误码: %d \n", nRet );
		    WriteLogToFile( szLog );
			sv_nStatus = 1;
		    return SAR_FAIL;
		}

//		PrintApduToFile( 1, response, nResponseLen );

	    if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
		{
			if( pbCert != NULL )
			{
				memcpy( pbCert+(nIndex*0xF0), response, nResponseLen-2 );
			}
		}
	   else
	   {
		    sprintf( szLog, "导出证书文件失败，状态码: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
	    	WriteLogToFile( szLog );
		    return SAR_FAIL;
	   }

    }

	*pulCertLen = dwCertificateSize;

	return SAR_OK;
}

#ifdef __cplusplus
}
#endif  /*__cplusplus*/
