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
	* �������ƣ�SKF_EnumDev
	* �������ܣ��豸ö��
	* �����б�bPresent:   [IN], ΪTRUE��ʾ���ڵ��豸�б�ΪFALSE��ʾ����֧�ֵ��豸�б�
	*           szNameList: [OUT], �豸�����б�
	*           pulSize:    [IN/OUT], �豸�����б��������Ȼ��豸�����б��ռ�ÿռ��С
	* �� �� ֵ��SAR_OK: �ɹ�
	����ֵ: ������
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
	* �������ƣ�SKF_ConnectDev
	* �������ܣ������豸
	* �����б�szName:  [IN], �豸����
	*           phDev:   [OUT], �����豸���
	* �� �� ֵ��SAR_OK: �ɹ�
	����ֵ: ������
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
	* �������ƣ�SKF_DisConnectDev
	* �������ܣ��Ͽ��豸����
	* �����б�hDev: [IN], �豸���
	* �� �� ֵ��SAR_OK: �ɹ�
	����ֵ: ������
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
	* �������ƣ�SKF_GetDevInfo
	* �������ܣ���ȡ�豸������
	* �����б�hDev:     [IN], �豸���
	*           pDevInfo: [OUT], �����豸��Ϣ
	* �� �� ֵ��SAR_OK: �ɹ�
	����ֵ: ������
	*/
	ULONG SKF_GetDevInfo( HANDLE hDev, DEVINFO * pDevInfo )
	{
		CHAR* pLog = ( "**********Start to execute SKF_GetDevInfo ********** \n" );
		BYTE response[SIZE_BUFFER_1024];

		DWORD nResponseLen = 0;
		LONG nRet = 0;
		sv_fEnd = FALSE;
		WriteLogToFile( pLog );

		//--------�ж��豸����Ƿ�Ϊ��
		if( hDev == NULL )
		{
			return SAR_INVALIDHANDLEERR;
		}

		memset( sv_stDevice.Manufacturer, 0 , sizeof(sv_stDevice.Manufacturer) );
		memset( sv_stDevice.Issuer, 0, sizeof(sv_stDevice.Issuer) );
		memset( sv_stDevice.Label, 0, sizeof(sv_stDevice.Label) );
		memset( sv_stDevice.SerialNumber, 0, sizeof(sv_stDevice.SerialNumber) );
		memset( sv_stDevice.SerialNumber, 0, sizeof(sv_stDevice.SerialNumber) );

		sv_stDevice.Version.major = 0x01;                                          //�汾��
		sv_stDevice.Version.minor = 0x00;

		memcpy( sv_stDevice.Manufacturer, pManufacturer, strlen(pManufacturer) );  //�豸������Ϣ
		memcpy( sv_stDevice.Issuer, pIssuer, strlen(pIssuer) );                    //���г�����Ϣ
		memcpy( sv_stDevice.SerialNumber, pSerialNumber, strlen(pSerialNumber) );  //���к�
		sv_stDevice.HWVersion.major       = 0x01;         //�豸Ӳ���汾
		sv_stDevice.HWVersion.minor       = 0x00;
		sv_stDevice.FirmwareVersion.major = 0x01;          //�豸����̼��汾
		sv_stDevice.FirmwareVersion.minor = 0x00; 
		sv_stDevice.AlgSymCap             = SGD_SM1_ECB;   //���������㷨��ʶ
		sv_stDevice.AlgAsymCap            = SGD_SM2_1;       //�ǶԳ������㷨��ʶ
		sv_stDevice.AlgHashCap            = SGD_SM3;       //�����Ӵ��㷨��ʶ
		sv_stDevice.DevAuthAlgId          = SGD_SSF33_ECB;   //�豸��֤ʹ�õķ��������㷨��ʶ
		sv_stDevice.TotalSpace            = 0x01000000;    //�豸�ռ��С
		sv_stDevice.FreeSpace             = 0x00100000;    //�û����ÿռ��С
		sv_stDevice.MaxECCBufferSize      = 0X00000100;    //�ܹ������ECC�������ݴ�С
		sv_stDevice.MaxBufferSize         = 0x00000100;    //�ܹ�����ķ���������Ӵ���������ݴ�С
		memset( sv_stDevice.Reserved, 0x00, sizeof(sv_stDevice.Reserved) );          //������չ

		nResponseLen = sizeof( response );

		//--------���������ļ�1E����ȡ�豸��ǩ
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
			memcpy( sv_stDevice.Label, pLabel, response[0] );  //�豸��ǩ
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
