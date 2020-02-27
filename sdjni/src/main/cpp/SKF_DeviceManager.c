// SKF_DeviceManager.cpp: implementation of the SKF_DeviceManager class.
//
//////////////////////////////////////////////////////////////////////

#include <string.h>
#include <zconf.h>
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
		CHAR szLog[SIZE_BUFFER_1024];
		memset( szLog, 0x0, strlen(szLog) );
		sv_fEnd = FALSE;
		WriteLogToFile( pszLog );
		if (szDrive == NULL) {
			LOGE("SKF_ConnectDev szDrive param is null.");
			return -1;
		}
#if 0 //mod by jason, for replace connectdev with opendev
		if (trans_dev_id != -1) {
			LOGE("SKF_ConnectDev, device is already opened.");
			return -1;
		}
		strcpy(device_path, szDrive);
		unsigned long baseResult = SDSCConnectDev(szDrive, szNum);
		trans_dev_id = *szNum;
#else
		unsigned long baseResult = OpenDevice(szDrive, szNum); //SDSCConnectDev(szDrive, &pulDriveNum);
#endif
		if ( LOGCAT_PRINT ) {
			LOGI("SKF_ConnectDev baseResult: %ld", baseResult);
			LOGI("SKF_ConnectDev trans_dev_id: %d", trans_dev_id);
			LOGI("SKF_ConnectDev szDrive: %s\n", szDrive);
		}
		if (trans_dev_id < 0) {
			LOGE("SKF_ConnectDev failed, trans_dev_id: %d", trans_dev_id);
			return trans_dev_id;
		}

		// command  00A40400 06 746D7373696D
		unsigned char DataTobeSend[0x0B];
		unsigned long send_len = 0;
		unsigned char check_sum = 0;

		int ret;
		unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
		memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
		send_len = sizeof(DataTobeSend);

		unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
		unsigned long recv_len = 0;
		memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);

		memset(DataTobeSend, '\0', 0x0B);
		memcpy(DataTobeSend, apdu_A4_04, 0x04);
		memcpy(DataTobeSend + 0x04, apdu_connect, 0x07);
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
				sprintf( szLog, "SKF_ConnectDev failed, error code: %d \n", ret );
				WriteLogToFile( szLog );
				LOGE("SKF_ConnectDev return failed, error code: %d \n", ret );
				ret = -1;
				continue;
			}
			if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
				// get data if need
				break;
			} else {
				sprintf( szLog, "SKF_ConnectDev failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
				WriteLogToFile( szLog );
				LOGE("SKF_ConnectDev failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
			}
		}

		free(tmpBuffer_wr);
		free(tmpBuffer_rd);

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
	ULONG SKF_DisConnectDev( HANDLE handle )
	{
		CHAR* pszLog = ( "**********Start to execute SKF_DisConnectDev ********** \n" );
		sv_fEnd = TRUE;
		WriteLogToFile( pszLog );
#if 0 //mod by jason, for replace connectdev with opendev
		if ((trans_dev_id == -1) || (handle != trans_dev_id)) {
			LOGE("SKF_DisConnectDev device handler is incorrect.");
			return -1;
		}
		unsigned long baseResult = SDSCDisconnectDev(handle);
		trans_dev_id = -1;
		memset(device_path, 0, sizeof(device_path));
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
		CHAR szLog[SIZE_BUFFER_1024];
		memset( szLog, 0x0, strlen(szLog) );
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

		unsigned long send_len = strlen(apdu_getDevInfo);
		unsigned char check_sum = 0;
		int ret;
		unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
		memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
		//copy the raw data
		memcpy(tmpBuffer_wr, (unsigned char *)apdu_getDevInfo, send_len);

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
				sprintf( szLog, "SKF_GetDevInfo failed, error code: %d \n", ret );
				WriteLogToFile( szLog );
				LOGE("SKF_GetDevInfo failed, error code: %d \n", ret );
				ret = -1;
				continue;
			}
			if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
				// get data if need
				for( int n=0; n<tmpBuffer_rd[0]; n++ )
				{
					pLabel[n] = tmpBuffer_rd[n+1];
				}
				memcpy( sv_stDevice.Label, pLabel, tmpBuffer_rd[0] );  //设备标签
			}
			else {
				sprintf( szLog, "SKF_GetDevInfo device label file fail, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
				WriteLogToFile( szLog );
				LOGE("SKF_GetDevInfo failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
				return SAR_FAIL;
			}
		}

		* pDevInfo = sv_stDevice;

		free(tmpBuffer_wr);
		free(tmpBuffer_rd);
		if (ret < 0) {
			return SAR_FAIL;
		}
		return SAR_OK;
	}

	// need update
ULONG SKF_GetFuncList( char * pDevInfo )
{
	CHAR* pszLog = ("**********Start to execute SKF_GetFuncList ********** \n");

	WriteLogToFile( pszLog );
	if (pDevInfo == NULL) {
		LOGE("SKF_GetFuncList param pDevInfo is null.");
		return -1;
	}
	strcat(pDevInfo, "SKF_EnumDev;");
	strcat(pDevInfo, "SKF_ConnectDev;");
	strcat(pDevInfo, "SKF_DisconnectDev;");
	strcat(pDevInfo, "SKF_ImportCertificate;");
	strcat(pDevInfo, "SKF_ExportCertificate;");
	strcat(pDevInfo, "SKF_GenRandom;");
	strcat(pDevInfo, "SKF_GenECCKeyPair;");
	strcat(pDevInfo, "SKF_ImportECCKeyPair;");
	strcat(pDevInfo, "SKF_ECCSignData;");
	strcat(pDevInfo, "SKF_ECCVerify;");
	strcat(pDevInfo, "SKF_ExtECCVerify;");
	strcat(pDevInfo, "SKF_GenerateAgreementDataWithECC;");
	strcat(pDevInfo, "SKF_GenerateKeyWithECC;");
	strcat(pDevInfo, "SKF_GenerateAgreementDataAndKeyWithECC;");
	strcat(pDevInfo, "SKF_ExportPublicKey;");
	strcat(pDevInfo, "SKF_ImportSessionKey;");
	strcat(pDevInfo, "SKF_SetSymmKey;");
	strcat(pDevInfo, "SKF_EncryptInit;");
	strcat(pDevInfo, "SKF_Encrypt;");
	strcat(pDevInfo, "SKF_EncryptUpdate;");
	strcat(pDevInfo, "SKF_EncryptFinal;");
	strcat(pDevInfo, "SKF_DecryptInit ;");
	strcat(pDevInfo, "SKF_Decrypt;");
	strcat(pDevInfo, "SKF_DecryptUpdate;");
	strcat(pDevInfo, "SKF_DecryptFinal;");
	strcat(pDevInfo, "SKF_DigestInit;");
	strcat(pDevInfo, "SKF_Digest;");
	strcat(pDevInfo, "SKF_DigestUpdate;");
	strcat(pDevInfo, "SKF_DigestFinal;");
	strcat(pDevInfo, "SKF_MacInit;");
	strcat(pDevInfo, "SKF_MacUpdate;");
	strcat(pDevInfo, "SKF_MacFinal;");
	strcat(pDevInfo, "SKF_CloseHandle;");
	strcat(pDevInfo, "SKF_GetDevInfo;");
	strcat(pDevInfo, "V_GenerateKey;");
	strcat(pDevInfo, "V_ECCExportSessionKeyByHandle;");
	strcat(pDevInfo, "V_ECCPrvKeyDecrypt;");
	strcat(pDevInfo, "V_ImportKeyPair;");
	strcat(pDevInfo, "V_Cipher;");
	strcat(pDevInfo, "V_GetZA;");
	strcat(pDevInfo, "V_SetAppPath;");

	return SAR_OK;
}

#ifdef __cplusplus
}
#endif  /*__cplusplus*/
