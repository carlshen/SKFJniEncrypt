// SKF_DeviceManager.cpp: implementation of the SKF_DeviceManager class.
//
//////////////////////////////////////////////////////////////////////

#include "SKF_TypeDef.h"
#include "Global_Def.h"
#include "Algorithms.h"
#include "transmit.h"
#include <SDSCDev.h>

CHAR pManufacturer[64] = "Tongfang Microelectronics Company";
CHAR pIssuer[64] = "Tongfang Microelectronics Company";
CHAR pLabel[32];
CHAR pSerialNumber[32] = "02569874513625987452136529";


#define  DEV_PLUG_IN_EVENT   1
#define  DEV_PLUG_OUT_EVENT  2
volatile BOOL g_bWaitForDevice = TRUE;
volatile BOOL g_bPresent = FALSE;
INT n1 = 0, n2 = 0, nFirst3 = 0;
INT nA = 0, nB = 0, nFirstC = 0;

#ifdef __cplusplus
extern "C" {
#endif  /*__cplusplus*/

	ULONG del(CHAR *a, ULONG n)
	{
		ULONG i =0,j=0;
		for(; i< n; i+=2,j++)
		{
			a[j] = a[i];
		}
		return j;	
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/*
	* 函数名称：SKF_EnumDev
	* 函数功能：设备枚举
	* 参数列表：bPresent:   [IN], 为TRUE表示存在的设备列表；为FALSE表示驱动支持的设备列表；
	*           szNameList: [OUT], 设备名称列表
	*           pulSize:    [IN/OUT], 设备名称列表缓冲区长度或设备名称列表的占用空间大小
	* 返 回 值：SAR_OK: 成功
	其他值: 错误码
	*/
	ULONG SKF_EnumDev( BOOL bPresent, LPSTR szNameList, ULONG * pulSize )
	{
		CHAR* pszLog = "Start to execute SKF_EnumDev \n";
		CHAR szLog[SIZE_BUFFER_1024];

		DWORD dwStrLen = 0;
		BYTE devName[SIZE_BUFFER_256];
		BYTE hasDevSupported = 0x00;
		DWORD dwOff = 0;
		DWORD dwLen = 0;

		DWORD nResponseLen = 0;
		LONG nRet = 0;
		BYTE response[SIZE_BUFFER_2048];
		DWORD dwActiveProtocol = 0;

		// 清除日志内容
		//ResetLogFile( SV_PSZLOGPATH );
		sv_nStatus = 0;
		sv_fEnd = FALSE;
		memset( devName, '\0', sizeof(devName) );
		memset( response, 0, sizeof(response) );
		memset( szLog, 0x0, strlen(szLog) );


#if 0
		CHAR namebuf[1024];
		ULONG l;
		LONG lReturn;

		lReturn = SCardEstablishContext(SCARD_SCOPE_USER,NULL,NULL, &hSC);
		if(lReturn != SCARD_S_SUCCESS)
		{
			_stprintf_s( szLog, _countof(szLog), TEXT("SCardEstablishContext: %d \n"), lReturn );
			WriteLogToFile( szLog );
			return SAR_FAIL;
		}

		lReturn= SCardListReaders(hSC,NULL,(LPTSTR)namebuf,&l);	
		if(lReturn != SCARD_S_SUCCESS)
		{
			_stprintf_s( szLog, _countof(szLog), TEXT("SCardListReaders: %d \n"), lReturn );
			WriteLogToFile( szLog );
			return SAR_FAIL;
		}
		l = del(namebuf, l*2);
		_stprintf_s( szLog, _countof(szLog), TEXT("szNameList: %s \n"), namebuf );
		WriteLogToFile( szLog );

		memcpy(szNameList, namebuf, l);
		*pulSize = l;

		_stprintf_s( szLog, _countof(szLog), TEXT("SKF_EnumDev success \n"), lReturn );
		WriteLogToFile( szLog );

		return SAR_OK;
#endif


		WriteLogToFile( pszLog );
		nResponseLen = sizeof( response );

		if( bPresent ) //!bPresent ) //TRUE：列出所有设备
		{
			nRet = SDSCListDevs( szNameList, pulSize, &nResponseLen );

			if( nRet != SAR_OK )
			{
				sprintf( szLog, "枚举设备失败，错误码: 0x%08X \n", nRet );
				WriteLogToFile( szLog );

				return SAR_FAIL;
			}

			//2013年07月02日
			//加入对传入的参数非NULL的判断
// 			if( szNameList != NULL )
// 			{
// 				memcpy( szNameList, response, strlen(response) );
// 				szNameList[strlen(response)] = '\0';
// 				szNameList[strlen(response)+1] = '\0';	
// 			}
// 
// 			*pulSize = strlen(response) + 2;
			if( szNameList != NULL )
			{
				memcpy( szNameList, response, nResponseLen );
			}

			*pulSize = nResponseLen;
			return SAR_OK;
		}
		else  //FALSE：支持的设备
		{

			nRet = SDSCListDevs( szNameList, pulSize, &nResponseLen );

			if( nRet != SAR_OK )
			{
				sprintf( szLog, "枚举设备失败，错误码: 0x%08X \n", nRet );
				WriteLogToFile( szLog );

			}
			else
			{
				//2013年07月02日
				//加入对传入的参数非NULL的判断
				*pulSize = 0;
				while (nResponseLen > dwStrLen+1)
				{
					memset(sv_pszCCIDDevNameA,0,sizeof(sv_pszCCIDDevNameA));
					strcpy( sv_pszCCIDDevNameA, (const char *)(response + dwStrLen) );
					dwLen = strlen(sv_pszCCIDDevNameA);
					dwStrLen += dwLen;
					dwStrLen++;
					// need update the params later
					nRet = SDSCConnectDev( sv_pszCCIDDevNameA, &sv_Device);

					if( nRet != SAR_OK )
					{
						sprintf( szLog, "设备枚举失败： 0x%08X \n", nRet );
						WriteLogToFile( szLog );
					}
					else
					{
						if( szNameList  != NULL )
						{
							memcpy( szNameList + dwOff, sv_pszCCIDDevNameA, dwLen );							
						}
						dwOff += dwLen;
						*pulSize = dwStrLen;
					}
				}
				*pulSize += 1;

// 				while( nResponseLen > dwStrLen+1 )
// 				{
// 					strcpy_s( devName, response + dwStrLen );
// 					dwStrLen += strlen( response + dwStrLen +1);
// 					dwStrLen +=2;
// 
// 					if( strcmp(sv_pszCCIDDevNameA, devName) == 0 )
// 					{
// 						nResponseLen = strlen( sv_pszCCIDDevNameA );
// 
// 						if( szNameList  != NULL )
// 						{
// 							memcpy( szNameList, sv_pszCCIDDevNameA, nResponseLen );		
// 							szNameList[nResponseLen] = 0;
// 							szNameList[nResponseLen+1] = 0;
// 						}
// 
// 						*pulSize = nResponseLen + 2;
// 						break;
// 					}
// 				}
// 
// 
// 				nRet = SCardConnectA( sv_hContext, 
// 					sv_pszCCIDDevNameA,
// 					SCARD_SHARE_SHARED,
// 					SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
// 					( LPSCARDHANDLE )&sv_hDev,
// 					&dwActiveProtocol );
// 
// 				if( nRet != SCARD_S_SUCCESS )
// 				{
// 					_stprintf_s( szLog, _countof(szLog), TEXT("设备枚举失败： 0x%08X \n"), nRet );
// 					WriteLogToFile( szLog );
// 					hasDevSupported = 0x00;
// 				}
// 				else
// 				{
// 					hasDevSupported = 0x01;
// 				}

			}

// 			if( hasDevSupported == 0x00 )
// 			{
// 				*pulSize = 0;
// 			}

			return SAR_OK;

		}

		sprintf( szLog, "枚举设备失败，错误码: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		sv_fEnd = TRUE;
		return SAR_FAIL;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/*
	* 函数名称：SKF_ConnectDev
	* 函数功能：连接设备
	* 参数列表：szName:  [IN], 设备名称
	*           phDev:   [OUT], 返回设备句柄
	* 返 回 值：SAR_OK: 成功
	其他值: 错误码
	*/
	ULONG SKF_ConnectDev( LPSTR szName, DEVHANDLE *phDev )
	{
		CHAR* pszLog = ( "**********Start to execute SKF_ConnectDev ********** \n" );
		CHAR szLog[SIZE_BUFFER_1024];

		DWORD nResponseLen = 0;
		DWORD dwActiveProtocol = 0;
		LONG nRet = 0;

		sv_fEnd = FALSE;
		memset( szLog, 0x0, strlen(szLog) );
		WriteLogToFile( pszLog );

#if 0
		wchar_t			wName[SIZE_BUFFER_1024];
		LONG            lReturn;
		DWORD           dwAP;
		LONG            lReturn2;

		int len = strlen(szName);

		mbstowcs(wName, szName, len+1);

		lReturn = SCardConnect( hSC, wName,SCARD_SHARE_SHARED,SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,&hCardHandle,&dwAP );
		if ( SCARD_S_SUCCESS != lReturn )
		{
			_stprintf_s( szLog, _countof(szLog), TEXT("SCardConnect fail: %d \n"), lReturn );
			WriteLogToFile( szLog );
			return SAR_FAIL;
		}

		_stprintf_s( szLog, _countof(szLog), TEXT("SCardConnect success \n"), lReturn );
		WriteLogToFile( szLog );

		// Use the connection.
		// Display the active protocol.
		switch ( dwAP )
		{
		case SCARD_PROTOCOL_T0:
			_stprintf_s( szLog, _countof(szLog), TEXT("Active protocol T0\n"), lReturn );
			WriteLogToFile( szLog );
			break;

		case SCARD_PROTOCOL_T1:
			_stprintf_s( szLog, _countof(szLog), TEXT("Active protocol T1\n"), lReturn );
			WriteLogToFile( szLog );
			break;

		case SCARD_PROTOCOL_UNDEFINED:
		default:
			_stprintf_s( szLog, _countof(szLog), TEXT("Active protocol unnegotiated or unknown\n"), lReturn );
			WriteLogToFile( szLog );
			break;
		}

		pioSendPci.dwProtocol = dwAP;
		pioSendPci.cbPciLength = sizeof(SCARD_IO_REQUEST);

		_stprintf_s( szLog, _countof(szLog), TEXT("SKF_ConnectDev success \n"), lReturn2 );
		WriteLogToFile( szLog );

		//--------选择CA环境DDF3
		if( SV_SelectDFByFID( hCardHandle, APDU_CA_FID, "选择CA环境") != SAR_OK )
		{
			_stprintf_s( szLog, _countof(szLog), TEXT("设备连接失败（选择CA环境）\n") ); 
			WriteLogToFile( szLog );
			sv_fEnd = TRUE;
			return SAR_FAIL;
		}

		//设备句柄
		*phDev = hCardHandle;

		return SAR_OK;

#endif
		nRet = SDSCConnectDev(szName, &sv_Device);
		if( nRet != SAR_OK )
		{
			sprintf( szLog, "设备连接失败： %d \n", nRet );
			WriteLogToFile( szLog );
			return SAR_FAIL;
		}

		//--------选择CA环境DDF3
		if( SV_SelectDFByFID( sv_hDev, APDU_CA_FID, "选择CA环境") != SAR_OK )
		{
//			_stprintf_s( szLog, _countof(szLog), TEXT("设备连接失败（选择CA环境）\n") );
			WriteLogToFile( szLog );
			sv_fEnd = TRUE;
			return SAR_FAIL;
		}

		//设备句柄
		*phDev = sv_hDev;

		return SAR_OK;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/*
	* 函数名称：SKF_DisConnectDev
	* 函数功能：断开设备连接
	* 参数列表：hDev: [IN], 设备句柄
	* 返 回 值：SAR_OK: 成功
	其他值: 错误码
	*/
	ULONG SKF_DisConnectDev( DEVHANDLE hDev )
	{
		CHAR* pszLog = ( "**********Start to execute SKF_DisConnectDev ********** \n" );
//		TCHAR szLog[SIZE_BUFFER_1024];

		sv_fEnd = TRUE;
		WriteLogToFile( pszLog );

/*		LONG            lReturn;*/

// 		lReturn = SCardDisconnect(hDev, SCARD_LEAVE_CARD);
// 		if ( SCARD_S_SUCCESS != lReturn )
// 		{
// 			_stprintf_s( szLog, _countof(szLog), TEXT("SCardDisconnect fail : %d \n"), lReturn );
// 			WriteLogToFile( szLog );
// 			return SAR_FAIL;
// 		}

// 		_stprintf_s( szLog, _countof(szLog), TEXT("SCardDisconnect success \n"), lReturn );
// 		WriteLogToFile( szLog );

		return SAR_OK;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/*
	* 函数名称：SKF_GetDevInfo
	* 函数功能：获取设备西你想
	* 参数列表：hDev:     [IN], 设备句柄
	*           pDevInfo: [OUT], 返回设备信息
	* 返 回 值：SAR_OK: 成功
	其他值: 错误码
	*/
	ULONG SKF_GetDevInfo( DEVHANDLE hDev, DEVINFO * pDevInfo )
	{
		CHAR* pLog = ( "**********Start to execute SKF_GetDevInfo ********** \n" );
		CHAR szLog[SIZE_BUFFER_1024];
		BYTE response[SIZE_BUFFER_1024];
		BYTE apdu[SIZE_BUFFER_1024];

		DWORD nResponseLen = 0;
		LONG nRet = 0;
		sv_fEnd = FALSE;
		WriteLogToFile( pLog );
		memset( apdu, 0x00, sizeof(apdu) );

		//--------判断设备句柄是否为空
		if( hDev == NULL )
		{
			return SAR_INVALIDHANDLEERR;
		}

		memset( sv_stDevice.Manufacturer, 0 , sizeof(sv_stDevice.Manufacturer) );
		memset( sv_stDevice.Issuer, 0, sizeof(sv_stDevice.Issuer) );
		memset( sv_stDevice.Label, 0, sizeof(sv_stDevice.Label) );
		memset( sv_stDevice.SerialNumber, 0, sizeof(sv_stDevice.SerialNumber) );
		memset( sv_stDevice.SerialNumber, 0, sizeof(sv_stDevice.SerialNumber) );

		sv_stDevice.Version.major = 0x01;                                          //版本号
		sv_stDevice.Version.minor = 0x00;

		memcpy( sv_stDevice.Manufacturer, pManufacturer, strlen(pManufacturer) );  //设备厂商信息
		memcpy( sv_stDevice.Issuer, pIssuer, strlen(pIssuer) );                    //发行厂商信息
		memcpy( sv_stDevice.SerialNumber, pSerialNumber, strlen(pSerialNumber) );  //序列号
		sv_stDevice.HWVersion.major       = 0x01;         //设备硬件版本
		sv_stDevice.HWVersion.minor       = 0x00;
		sv_stDevice.FirmwareVersion.major = 0x01;          //设备本身固件版本
		sv_stDevice.FirmwareVersion.minor = 0x00; 
		sv_stDevice.AlgSymCap             = SGD_SM1_ECB;   //分组密码算法标识
		sv_stDevice.AlgAsymCap            = SGD_SM2_1;       //非对称密码算法标识
		sv_stDevice.AlgHashCap            = SGD_SM3;       //密码杂凑算法标识
		sv_stDevice.DevAuthAlgId          = SGD_SSF33_ECB;   //设备认证使用的分组密码算法标识
		sv_stDevice.TotalSpace            = 0x01000000;    //设备空间大小
		sv_stDevice.FreeSpace             = 0x00100000;    //用户可用空间大小
		sv_stDevice.MaxECCBufferSize      = 0X00000100;    //能够处理的ECC加密数据大小
		sv_stDevice.MaxBufferSize         = 0x00000100;    //能够处理的分组运算和杂凑运算的数据大小
		memset( sv_stDevice.Reserved, 0x00, sizeof(sv_stDevice.Reserved) );          //保留扩展

		nResponseLen = sizeof( response );
		//--------选择MF
		//--------选择CA环境

		//--------读二进制文件1E，读取设备标签
		memset( response, 0x00, sizeof(response) );
		memcpy( apdu, apdu_readBinary, 0x05 );

		apdu[2] |= 0x1E;  //SFI
		apdu[3] = 0x00;         //偏移量为0x00
		apdu[4] = 0x21;         //大小为0x21

//		PrintApduToFile( 0, apdu, 0x05 );
		nRet = TransmitData( 1, apdu, 0x05, response, &nResponseLen );
		if( nRet != SAR_OK )
		{
			sprintf( szLog, "读1E（设备标签）文件失败，错误码: %d \n", nRet );
			WriteLogToFile( szLog );
			sv_nStatus = 1;
			return SAR_FAIL;
		}

//		PrintApduToFile( 1, response, nResponseLen );
		if( (response[nResponseLen-2] == 0x90) && (response[nResponseLen-1] == 0x00) )
		{
			for( int n=0; n<response[0]; n++ )
			{
				pLabel[n] = response[n+1];
			}
			memcpy( sv_stDevice.Label, pLabel, response[0] );  //设备标签
		}
		else
		{
			sprintf( szLog, "读1E（设备标签）文件失败，状态码: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
			WriteLogToFile( szLog );
			return SAR_FAIL;
		}

		* pDevInfo = sv_stDevice;

		return SAR_OK;
	}

#ifdef __cplusplus
}
#endif  /*__cplusplus*/
