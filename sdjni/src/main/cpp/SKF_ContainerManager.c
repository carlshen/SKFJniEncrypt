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
* �������ƣ�SKF_ImportCertificate
* �������ܣ���������֤��
* �����б�hContainer: [IN], ��Կ���
*           bSignFlag:  [IN], TRUE��ʾǩ��֤�飻FALSE��ʾ����֤��
*           pbCert:     [IN], ָ��֤�����ݻ�����
*           ulCertLen:  [IN], ֤�鳤��
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ:������
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
	//--------�����������Ϊ��
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

	//--------ѡ��ADF��ͨ��FIDѡ��
	if( SV_SelectDFByFID(hDev, appFID, "ѡ��ADF") != SAR_OK )
		return SAR_FAIL;

	//--------����ADF�µ�֤���ļ�
	memcpy( apdu, apdu_updateBinary, 0x05 );

	if( !bSignFlag ) //����֤��
	{
		bSFI = fileSFI[0];
	}
	else   //ǩ��֤��
	{
		bSFI = fileSFI[1];
	}


	//--------����֤���ļ�
	nDivider = ulCertLen / 0xF0;
	nRemainder = ulCertLen % 0xF0;

	//--------д��֤�鳤�ȣ�4�ֽ�
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
		sprintf( szLog, "����֤���ļ�ʧ�ܣ�������: %d \n", nRet );
		WriteLogToFile( szLog );
		sv_nStatus = 1;
		return SAR_FAIL;
	}

//	PrintApduToFile( 1, response, nResponseLen );

	if( (response[nResponseLen-2] != 0x90) || (response[nResponseLen-1] != 0x00) )
	{
		sprintf( szLog, "����֤���ļ�ʧ�ܣ�״̬��: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
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
		apdu[3] = (BYTE)dwOffset;  //ƫ����
		apdu[4] = 0xF0;          //��С

		if( pbCert != NULL )
		{
			memcpy( apdu+0x05, pbCert+(nIndex*0xF0), 0xF0 );
		}

//		PrintApduToFile( 0, apdu, 0x05 +0xF0);

        nResponseLen = sizeof( response );
        nRet = TransmitData( hDev, apdu, 0x05+0xF0, response, &nResponseLen );
        if( nRet != SAR_OK )
		{
			sprintf( szLog, "����֤���ļ�ʧ�ܣ�������: %d \n", nRet );
		    WriteLogToFile( szLog );
			sv_nStatus = 1;
		    return SAR_FAIL;
		}

//		PrintApduToFile( 1, response, nResponseLen );

	    if( (response[nResponseLen-2] != 0x90) || (response[nResponseLen-1] != 0x00) )
		{
			sprintf( szLog, "����֤���ļ�ʧ�ܣ�״̬��: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
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
		apdu[3] = (BYTE)dwOffset;  //ƫ����
		apdu[4] = (BYTE)nRemainder; //��С

		if( pbCert != NULL )
			memcpy( apdu+0x05, pbCert+(nDivider*0xF0), nRemainder );

//		PrintApduToFile( 0, apdu, 0x05+nRemainder );

        nResponseLen = sizeof( response );
        nRet = TransmitData( hDev, apdu, 0x05+nRemainder, response, &nResponseLen );
        if( nRet != SAR_OK )
		{
			sprintf( szLog, "����֤���ļ�ʧ�ܣ�������: %d \n", nRet );
		    WriteLogToFile( szLog );
			sv_nStatus = 1;
		    return SAR_FAIL;
		}

//		PrintApduToFile( 1, response, nResponseLen );

	    if( (response[nResponseLen-2] != 0x90) || (response[nResponseLen-1] != 0x00) )
		{
			sprintf( szLog, "����֤���ļ�ʧ�ܣ�״̬��: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
	    	WriteLogToFile( szLog );
		    return SAR_FAIL;
	   }

    }
	return SAR_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_ExportCertificate
* �������ܣ���������֤��
* �����б�hContainer: [IN], �������
*           bSignFlag:  [IN], TRUE��ʾǩ��֤�飻FALSE��ʾ����֤��
*           pbCert:     [IN], ָ��֤�����ݻ�������ΪNULLʱ��pulCerLen��ʾ������������Ҫ�������ĳ��ȣ���֮��������֤������
*           pulCerLen:  [IN/OUT], ����ʱ��ʾpbCert���������ȣ����ʱ��ʾ֤�����ݵĳ���
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ:������
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

	//--------ѡ��ADF��ͨ��FIDѡ��
	if( SV_SelectDFByFID(hDev, appFID, "") != SAR_OK )
		return SAR_FAIL;

	//--------��ȡADF�µ�֤���ļ�
	memcpy( apdu, apdu_updateBinary, 0x05 );

	if( !bSignFlag ) //����֤��
	{
		bSFI = fileSFI[0];
	}
	else   //ǩ��֤��
	{
		bSFI = fileSFI[1];
	}


	//--------��ȡ֤�鳤�ȣ�4�ֽ�
	memcpy( apdu, apdu_readBinary, 0x05 );
	
	apdu[2] |= bSFI; //SFI
    apdu[3] = 0x00;  //ƫ����
	apdu[4] = 0x04;   //��С

//	PrintApduToFile( 0, apdu, 0x05 );

    nResponseLen = sizeof( response );
    nRet = TransmitData( hDev, apdu, 0x05, response, &nResponseLen );
    if( nRet != SAR_OK )
	{
		sprintf( szLog, "����֤���ļ�ʧ�ܣ�������: %d \n", nRet );
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
		sprintf( szLog, "����֤���ļ�ʧ�ܣ�״̬��: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
		WriteLogToFile( szLog );
		return SAR_FAIL;
	}

	//--------��ȡ֤���ļ�
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
		apdu[3] = (BYTE)dwOffset;  //ƫ����
		apdu[4] = 0xF0;          //��С

//		PrintApduToFile( 0, apdu, 0x05 );

        nResponseLen = sizeof( response );
        nRet = TransmitData( hDev, apdu, 0x05, response, &nResponseLen );
        if( nRet != SAR_OK )
		{
			sprintf( szLog, "����֤���ļ�ʧ�ܣ�������: %d \n", nRet );
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
			sprintf( szLog, "����֤���ļ�ʧ�ܣ�״̬��: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
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
		apdu[3] = (BYTE)dwOffset;  //ƫ����
		apdu[4] = (BYTE)nRemainder; //��С

//		PrintApduToFile( 0, apdu, 0x05 );

        nResponseLen = sizeof( response );
        nRet = TransmitData( hDev, apdu, 0x05, response, &nResponseLen );
        if( nRet != SAR_OK )
		{
			sprintf( szLog, "����֤���ļ�ʧ�ܣ�������: %d \n", nRet );
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
		    sprintf( szLog, "����֤���ļ�ʧ�ܣ�״̬��: %02X%02X \n", response[nResponseLen-2], response[nResponseLen-1] );
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
