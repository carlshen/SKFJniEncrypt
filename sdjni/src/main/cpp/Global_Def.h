#ifndef SKF_GLOBAL_H
#define SKF_GLOBAL_H

#include <stdio.h>
#include <stdlib.h>
#include "SKF_StatusCode.h"
#include "SKF_TypeDef.h"
#include "APDUs.h"

//���建������С
#define SIZE_BUFFER_4          4
#define SIZE_BUFFER_8          8
#define SIZE_BUFFER_16         16
#define SIZE_BUFFER_24         24
#define SIZE_BUFFER_32         32
#define SIZE_BUFFER_64         64
#define SIZE_BUFFER_96         96
#define SIZE_BUFFER_128        128
#define SIZE_BUFFER_256        256
#define SIZE_BUFFER_512        512
#define SIZE_BUFFER_1024       1024
#define SIZE_BUFFER_2048       2048

#define PARAM_E_EXIST		0x01
#define PARAM_A_EXIST		0x02
#define PARAM_B_EXIST		0x04

static int sv_Device = -1;
static CHAR sv_pszCCIDDevNameA[SIZE_BUFFER_1024];

// �й���־����
static CHAR SV_PSZLOGPATH[SIZE_BUFFER_128];

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
BYTE  sv_tmpData[1024000];  //1000K
DWORD sv_tmpDataLen;

//ȫ�ֽṹ�����
APPLICATIONINFO  sv_stApplication;  //Ӧ��
CONTAINERINFO    sv_stContainer;    //����
DEVINFO          sv_stDevice;       //�豸
DEVHANDLE        sv_hDev;           //�豸���
HASHINFO         sv_stHash;         //��ϣ�Ӵն���

//�й��ļ��������
//--�ļ�����
BYTE sv_fileNameInfo[MAX_FILE_NUM][SIZE_FILE_ITEM];
BYTE sv_fileCurrentIndex;
//--�ļ�FID��SFI
const BYTE SV_EF_FID[MAX_FILE_NUM][2];


//�й�Ӧ�ö������
//--Ӧ������
BYTE sv_appNameInfo[MAX_APPLICATION_NUM][SIZE_APPLICATION_ITEM];
BYTE sv_appCurrentIndex;
CHAR sv_appName[33];
//--Ӧ��FID
const BYTE SV_ADF_FID[MAX_APPLICATION_NUM][2];


//�й�PIN�������
BYTE sv_pinIndex[2];

//�й��豸��֤�������
int sv_nAuth;   //�ⲿ��֤���豸��֤
int sv_nUser;   //�û�PIN
int sv_nAdmin;  //����ԱPIN

//�й�������������
//ȡ�������BLOCK���� 
#define RANDOM_BLOCK_SIZE SIZE_BUFFER_16 
BYTE sv_random[SIZE_BUFFER_1024];   //ȫ�����������������󳤶�1024�ֽ�
DWORD sv_randomLength;              //ȫ����������������ȼ�����

//�й�ǩ���������
ECCSIGNATUREBLOB sv_eccSignBlob;
BYTE sv_signEF_FID[2];

void WriteLogToFile( CHAR* szLog );
ULONG sc_command(DEVHANDLE hDev, BYTE* inBuf, DWORD inLen, BYTE* retBuf, DWORD* pdwLen);
BYTE cryptoDESMAC(BYTE *pbKey, BYTE *pbIv, BYTE * pbDatIn, BYTE bDatLen, BYTE *pbDatOut);
BYTE cryptoDESEcbEnc(BYTE *pbKey, BYTE bKeyLen, BYTE *pbDatIn, UINT16 usLen, BYTE *pbDatOut);
ULONG SV_SelectDFByFID( DEVHANDLE hDev, const BYTE appFID[2], CHAR *pszLog );
ULONG FindDFByAppName( DEVHANDLE hDev, LPSTR szAppName, BYTE *appFID );
ULONG OpenApplication( DEVHANDLE hDev, LPSTR szAppName );

BYTE  sv_APDU[0x05];
//extern BYTE sv_devAuth;
INT sv_nStatus;
BOOL sv_fEnd;

#endif //SKF_GLOBAL_H
