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
	* �������ƣ�SKF_EnumDev
	* �������ܣ��豸ö��
	* �����б�bPresent:   [IN], ΪTRUE��ʾ���ڵ��豸�б�ΪFALSE��ʾ����֧�ֵ��豸�б�
	*           szNameList: [OUT], �豸�����б�
	*           pulSize:    [IN/OUT], �豸�����б��������Ȼ��豸�����б��ռ�ÿռ��С
	* �� �� ֵ��SAR_OK: �ɹ�
	����ֵ: ������
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

		// �����־����
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

		if( bPresent ) //!bPresent ) //TRUE���г������豸
		{
			nRet = SDSCListDevs( szNameList, pulSize, &nResponseLen );

			if( nRet != SAR_OK )
			{
				sprintf( szLog, "ö���豸ʧ�ܣ�������: 0x%08X \n", nRet );
				WriteLogToFile( szLog );

				return SAR_FAIL;
			}

			//2013��07��02��
			//����Դ���Ĳ�����NULL���ж�
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
		else  //FALSE��֧�ֵ��豸
		{

			nRet = SDSCListDevs( szNameList, pulSize, &nResponseLen );

			if( nRet != SAR_OK )
			{
				sprintf( szLog, "ö���豸ʧ�ܣ�������: 0x%08X \n", nRet );
				WriteLogToFile( szLog );

			}
			else
			{
				//2013��07��02��
				//����Դ���Ĳ�����NULL���ж�
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
						sprintf( szLog, "�豸ö��ʧ�ܣ� 0x%08X \n", nRet );
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
// 					_stprintf_s( szLog, _countof(szLog), TEXT("�豸ö��ʧ�ܣ� 0x%08X \n"), nRet );
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

		sprintf( szLog, "ö���豸ʧ�ܣ�������: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		sv_fEnd = TRUE;
		return SAR_FAIL;
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

		//--------ѡ��CA����DDF3
		if( SV_SelectDFByFID( hCardHandle, APDU_CA_FID, "ѡ��CA����") != SAR_OK )
		{
			_stprintf_s( szLog, _countof(szLog), TEXT("�豸����ʧ�ܣ�ѡ��CA������\n") ); 
			WriteLogToFile( szLog );
			sv_fEnd = TRUE;
			return SAR_FAIL;
		}

		//�豸���
		*phDev = hCardHandle;

		return SAR_OK;

#endif
		nRet = SDSCConnectDev(szName, &sv_Device);
		if( nRet != SAR_OK )
		{
			sprintf( szLog, "�豸����ʧ�ܣ� %d \n", nRet );
			WriteLogToFile( szLog );
			return SAR_FAIL;
		}

		//--------ѡ��CA����DDF3
		if( SV_SelectDFByFID( sv_hDev, APDU_CA_FID, "ѡ��CA����") != SAR_OK )
		{
//			_stprintf_s( szLog, _countof(szLog), TEXT("�豸����ʧ�ܣ�ѡ��CA������\n") );
			WriteLogToFile( szLog );
			sv_fEnd = TRUE;
			return SAR_FAIL;
		}

		//�豸���
		*phDev = sv_hDev;

		return SAR_OK;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/*
	* �������ƣ�SKF_DisConnectDev
	* �������ܣ��Ͽ��豸����
	* �����б�hDev: [IN], �豸���
	* �� �� ֵ��SAR_OK: �ɹ�
	����ֵ: ������
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
	* �������ƣ�SKF_GetDevInfo
	* �������ܣ���ȡ�豸������
	* �����б�hDev:     [IN], �豸���
	*           pDevInfo: [OUT], �����豸��Ϣ
	* �� �� ֵ��SAR_OK: �ɹ�
	����ֵ: ������
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
		//--------ѡ��MF
		//--------ѡ��CA����

		//--------���������ļ�1E����ȡ�豸��ǩ
		memset( response, 0x00, sizeof(response) );
		memcpy( apdu, apdu_readBinary, 0x05 );

		apdu[2] |= 0x1E;  //SFI
		apdu[3] = 0x00;         //ƫ����Ϊ0x00
		apdu[4] = 0x21;         //��СΪ0x21

//		PrintApduToFile( 0, apdu, 0x05 );
		nRet = TransmitData( 1, apdu, 0x05, response, &nResponseLen );
		if( nRet != SAR_OK )
		{
			sprintf( szLog, "��1E���豸��ǩ���ļ�ʧ�ܣ�������: %d \n", nRet );
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
			memcpy( sv_stDevice.Label, pLabel, response[0] );  //�豸��ǩ
		}
		else
		{
			sprintf( szLog, "��1E���豸��ǩ���ļ�ʧ�ܣ�״̬��: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
			WriteLogToFile( szLog );
			return SAR_FAIL;
		}

		* pDevInfo = sv_stDevice;

		return SAR_OK;
	}

#ifdef __cplusplus
}
#endif  /*__cplusplus*/
