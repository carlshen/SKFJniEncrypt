// SKF_DeviceManager.cpp: implementation of the SKF_DeviceManager class.
//
//////////////////////////////////////////////////////////////////////

#include <string.h>
#include "SKF_TypeDef.h"
#include "Global_Def.h"
#include "Algorithms.h"
#include "transmit.h"
#include <SDSCDev.h>
#include "SKF_DeviceManager.h"
#include "logger.h"

CHAR pManufacturer[64] = "Tongfang Microelectronics Company";
CHAR pIssuer[64] = "Tongfang Microelectronics Company";
CHAR pLabel[32];
CHAR pSerialNumber[32] = "02569874513625987452136529";


#ifdef __cplusplus
extern "C" {
#endif  /*__cplusplus*/

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
	ULONG SKF_EnumDev( char * pDrives, ULONG * pDrivesLen, ULONG * pulSize )
	{
		CHAR* pszLog = "Start to execute SKF_EnumDev \n";
		sv_fEnd = FALSE;
		WriteLogToFile( pszLog );
		if (pDrives == NULL) {
			LOGE("SKF_EnumDev param pDrives is null.");
			return -1;
		}
		unsigned long baseResult = 0;
#if 0
		baseResult = SDSCListDevs(pDrives, pDrivesLen, pulSize);
#else
		baseResult = ListDevice(pDrives, &pDrivesLen);
		*pulSize = baseResult;
#endif
		if ( LOGCAT_PRINT ) {
			LOGI("SKF_EnumDev baseResult: %ld", baseResult);
			LOGI("SKF_EnumDev pDrivesLen: %ld", pDrivesLen);
			LOGI("SKF_EnumDev pDrives: %s\n", pDrives);
		}

		return baseResult;
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
	ULONG SKF_ConnectDev( char *szDrive, int *szNum )
	{
		CHAR* pszLog = ( "**********Start to execute SKF_ConnectDev ********** \n" );
		sv_fEnd = FALSE;
		WriteLogToFile( pszLog );
		if (szDrive == NULL) {
			LOGE("SKF_ConnectDev szDrive param is null.");
			return -1;
		}
#if 0 //mod by jason, for replace connectdev with opendev
		unsigned long baseResult = SDSCConnectDev(szDrive, szNum);
#else
		unsigned long baseResult = OpenDevice(szDrive, szNum); //SDSCConnectDev(szDrive, &pulDriveNum);
#endif
		if ( LOGCAT_PRINT ) {
			LOGI("connect_dev baseResult: %ld", baseResult);
			LOGI("connect_dev pulDriveNum: %d", *szNum);
			LOGI("SKF_EnumDev szDrive: %s\n", szDrive);
		}
		return baseResult;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/*
	* 函数名称：SKF_DisConnectDev
	* 函数功能：断开设备连接
	* 参数列表：hDev: [IN], 设备句柄
	* 返 回 值：SAR_OK: 成功
	其他值: 错误码
	*/
	ULONG SKF_DisConnectDev( HANDLE handle )
	{
		CHAR* pszLog = ( "**********Start to execute SKF_DisConnectDev ********** \n" );
		sv_fEnd = TRUE;
		WriteLogToFile( pszLog );
#if 0 //mod by jason, for replace connectdev with opendev
		unsigned long baseResult = SDSCDisconnectDev(handle);
#else
		unsigned long baseResult = CloseDevice(handle); //SDSCDisconnectDev(handle);
#endif
		if ( LOGCAT_PRINT ) {
			LOGI("SKF_DisConnectDev baseResult: %ld", baseResult);
		}

		return baseResult;
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
	ULONG SKF_GetDevInfo( HANDLE hDev, DEVINFO * pDevInfo )
	{
		CHAR* pLog = ( "**********Start to execute SKF_GetDevInfo ********** \n" );
		BYTE response[SIZE_BUFFER_1024];

		DWORD nResponseLen = 0;
		LONG nRet = 0;
		sv_fEnd = FALSE;
		WriteLogToFile( pLog );

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

		//--------读二进制文件1E，读取设备标签
		memset( response, 0x00, sizeof(response) );

//		PrintApduToFile( 0, apdu, 0x05 );
		nRet = TransmitData( hDev, apdu_getDevInfo, 0x05, response, &nResponseLen );
		if( nRet != SAR_OK )
		{
			sprintf( pLog, "read 1E (device label) file fail, status code: %d \n", nRet );
			WriteLogToFile( pLog );
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
			sprintf( pLog, "read 1E (device label) file fail, status code: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
			WriteLogToFile( pLog );
			return SAR_FAIL;
		}

		* pDevInfo = sv_stDevice;

		return SAR_OK;
	}

	// need update
ULONG SKF_GetFuncList( HANDLE hDev, char * pDevInfo )
{
	CHAR* pszLog = ("**********Start to execute SKF_GetFuncList ********** \n");

	WriteLogToFile( pszLog );

	return SAR_OK;
}

#ifdef __cplusplus
}
#endif  /*__cplusplus*/
