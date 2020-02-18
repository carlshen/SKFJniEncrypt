
#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <xchar.h>
#include "SKF_StatusCode.h"
#include "SKF_TypeDef.h"
//#include "skf_type.h"
#include "APDUs.h"
#include "des.h"
//#include <WinSCard.h>

#ifdef READER_TYPE_HID
#include "dcrf32.h"
#endif
#ifdef READER_TYPE_CCID
#include <WinSCard.h>
#endif



//���建������С
#define SIZE_BUFFER_4          4
#define SIZE_BUFFER_8          8
#define SIZE_BUFFER_16         16
#define SIZE_BUFFER_24         24
#define SIZE_BUFFER_32         32
#define SIZE_BUFFER_64         64
#define SIZE_BUFFER_96         96
#define SIZE_BUFFER_128        128
#define SIZE_BUFFER_255        255
#define SIZE_BUFFER_256        256
#define SIZE_BUFFER_512        512
#define SIZE_BUFFER_1024       1024
#define SIZE_BUFFER_2048       2048
#define SIZE_BUFFER_3072       3072
#define SIZE_BUFFER_4096       4096
#define SIZE_BUFFER_8192       8192
#define SIZE_BUFFER_10240      10240
#define SIZE_BUFFER_102400     102400

#define PARAM_E_EXIST		0x01
#define PARAM_A_EXIST		0x02
#define PARAM_B_EXIST		0x04

#ifdef READER_TYPE_HID
extern CHAR*  sv_pszD8DevNameA;
extern TCHAR* sv_pszD8DevName;
#endif
#ifdef READER_TYPE_CCID
extern SCARDCONTEXT     sv_hContext;
extern SCARD_IO_REQUEST	sv_IORequest;
extern CHAR  sv_pszCCIDDevNameA[SIZE_BUFFER_1024];
extern WCHAR* sv_pszCCIDDevName;
#endif

// 
extern DWORD ThreadSemiAutoProc( void* lpParam );
extern HANDLE            g_hSemiAutoEvent[2];  //
//extern CRITICAL_SECTION  g_criticalSect;     //
extern HANDLE            g_hSemiAutoThread;        // �߳̾��
extern DWORD             g_dwSemiAutoThreadID;     // �߳�ID

// �й���־����
extern const CHAR* SV_PSZLOGPATH;
extern const CHAR* SV_PSZLOGTHREADPATH;

//��������
#define  CONTAINER_NULL  0  //δ֪����
#define  CONTAINER_RSA   1  //RSA����
#define  CONTAINER_SM2   2  //SM2����

//�й�Ӧ�ö���
//--���Ӧ�ø���
#define  MAX_APPLICATION_NUM    7
//--Ӧ�����Ƶ���Ϣ����
//--35=1(Ӧ�����Ƴ���) + 32(Ӧ������) + 2(FID)
#define  SIZE_APPLICATION_ITEM  35

//�й��ļ�����
//--����ļ�����
#define  MAX_FILE_NUM           5
//--�ļ����Ƶ���Ϣ����
//--47=1(�ļ����Ƴ���) + 32(�ļ�����) + 4(�ļ���С) + 4(�ļ���Ȩ��) + 4(�ļ�дȨ��) + 2(FID)
#define  SIZE_FILE_ITEM         47

//�й���������
//--�����������
#define  MAX_CONTAINER_NUM      3
//--�������Ƶ���Ϣ����
//--71=1(�������Ƴ���) + 64(��������) + 6(6��EF�ļ���SFI) + 1(��������)
#define  SIZE_CONTAINER_ITEM    72

//Ӧ��ADF��EF02�ļ��Ĵ�С���洢�������Ƶ���Ϣ
#define  SIZE_ADF_EF02  (MAX_CONTAINER_NUM*SIZE_CONTAINER_ITEM )

//Ӧ��ADF��EF01�ļ��Ĵ�С���洢�ļ����Ƶ���Ϣ
#define  SIZE_ADF_EF01  (MAX_FILE_NUM*SIZE_FILE_ITEM)

//CA������EF01�ļ��Ĵ�С���洢Ӧ�����Ƶ���Ϣ
#define  SIZE_CA_EF01  (MAX_APPLICATION_NUM*SIZE_APPLICATION_ITEM)

//CA������EF1E�ļ��Ĵ�С���洢�豸��ǩ���豸������Ϣ���豸�㷨����Ϣ
#define  SIZE_CA_EF1E  240

//ȫ�����ݻ�����
extern BYTE  sv_tmpData[1024000];  //1000K
extern DWORD sv_tmpDataLen;

//ȫ�ֽṹ�����
extern  APPLICATIONINFO  sv_stApplication;  //Ӧ��
extern  CONTAINERINFO    sv_stContainer;    //����
extern  DEVINFO          sv_stDevice;       //�豸
extern  DEVHANDLE        sv_hDev;           //�豸���
extern  HASHINFO         sv_stHash;         //��ϣ�Ӵն���
//extern SCARDCONTEXT hSC;
//extern SCARDHANDLE     hCardHandle;
//extern SCARD_IO_REQUEST	pioSendPci;

//�й������������
//ע��
//--��������
extern BYTE sv_containerNameInfo[MAX_CONTAINER_NUM][SIZE_CONTAINER_ITEM];
extern BYTE sv_containerCurrentIndex;
//--��������Կ�ļ�SFI
extern const BYTE SV_CONTAINER_SFI[MAX_CONTAINER_NUM][6];
//--����ȫ������
extern ULONG sv_containerType;


//�й��ļ��������
//--�ļ�����
extern BYTE sv_fileNameInfo[MAX_FILE_NUM][SIZE_FILE_ITEM];
extern BYTE sv_fileCurrentIndex;
//--�ļ�FID��SFI
extern const BYTE SV_EF_FID[MAX_FILE_NUM][2];


//�й�Ӧ�ö������
//--Ӧ������
extern BYTE sv_appNameInfo[MAX_APPLICATION_NUM][SIZE_APPLICATION_ITEM];
extern BYTE sv_appCurrentIndex;
extern CHAR sv_appName[33];
//--Ӧ��FID
extern const BYTE SV_ADF_FID[MAX_APPLICATION_NUM][2];


//�й�PIN�������
extern BYTE sv_pinIndex[2];

//�й��豸��֤�������
extern int sv_nAuth;   //�ⲿ��֤���豸��֤
extern int sv_nUser;   //�û�PIN
extern int sv_nAdmin;  //����ԱPIN

//�й�������������
//ȡ�������BLOCK���� 
#define RANDOM_BLOCK_SIZE SIZE_BUFFER_16 
extern BYTE sv_random[SIZE_BUFFER_1024];   //ȫ�����������������󳤶�1024�ֽ�
extern DWORD sv_randomLength;              //ȫ����������������ȼ�����

//�й�ǩ���������
extern ECCSIGNATUREBLOB sv_eccSignBlob;
extern BYTE sv_signEF_FID[2];

//�ⲿ����
#ifdef READER_TYPE_HID
extern void PrintApduToFile( BYTE bFlag, BYTE* pbApdu, BYTE nLength );
#endif

#ifdef READER_TYPE_CCID
extern void PrintApduToFile( BYTE bFlag, BYTE* pbApdu, DWORD bLength );
#endif
extern void WriteLogToFile( CHAR* szLog );
extern void ResetLogFile( CHAR*  lpszName );
extern void WriteLogToFile2( CHAR* szLog );
extern ULONG sc_command(DEVHANDLE hDev, BYTE* inBuf, DWORD inLen, BYTE* retBuf, DWORD* pdwLen);
extern BYTE cryptoDESMAC(BYTE *pbKey, BYTE *pbIv, BYTE * pbDatIn, BYTE bDatLen, BYTE *pbDatOut);
extern BYTE cryptoDESEcbEnc(BYTE *pbKey, BYTE bKeyLen, BYTE *pbDatIn, UINT16 usLen, BYTE *pbDatOut);
extern ULONG SV_SelectDFByFID( DEVHANDLE hDev, const BYTE appFID[2], CHAR *pszLog );
extern ULONG FindDFByAppName( DEVHANDLE hDev, LPSTR szAppName, BYTE *appFID );
extern ULONG OpenApplication( DEVHANDLE hDev, LPSTR szAppName );

extern BYTE  sv_APDU[0x05];
//extern BYTE sv_devAuth;
extern INT sv_nStatus;
extern BOOL sv_fEnd;
