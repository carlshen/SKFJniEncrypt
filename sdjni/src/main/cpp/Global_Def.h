#ifndef SKF_GLOBAL_H
#define SKF_GLOBAL_H

#include <stdio.h>
#include <stdlib.h>
#include "SKF_StatusCode.h"
#include "SKF_TypeDef.h"
#include "APDUs.h"

//定义缓冲区大小
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

static int sv_Device = -1;
static CHAR sv_pszCCIDDevNameA[SIZE_BUFFER_1024];
// 
extern DWORD ThreadSemiAutoProc( void* lpParam );
extern HANDLE            g_hSemiAutoEvent[2];  //
extern HANDLE            g_hSemiAutoThread;        // 线程句柄
extern DWORD             g_dwSemiAutoThreadID;     // 线程ID

// 有关日志变量
static CHAR SV_PSZLOGPATH[SIZE_BUFFER_128];
static CHAR SV_PSZLOGTHREADPATH[SIZE_BUFFER_128];

//容器类型
#define  CONTAINER_NULL  0  //未知容器
#define  CONTAINER_RSA   1  //RSA容器
#define  CONTAINER_SM2   2  //SM2容器

//有关应用定义
//--最大应用个数
#define  MAX_APPLICATION_NUM    7
//--应用名称等信息长度
//--35=1(应用名称长度) + 32(应用名称) + 2(FID)
#define  SIZE_APPLICATION_ITEM  35

//有关文件定义
//--最大文件个数
#define  MAX_FILE_NUM           5
//--文件名称等信息长度
//--47=1(文件名称长度) + 32(文件名称) + 4(文件大小) + 4(文件读权限) + 4(文件写权限) + 2(FID)
#define  SIZE_FILE_ITEM         47

//有关容器定义
//--最大容器个数
#define  MAX_CONTAINER_NUM      3
//--容器名称等信息长度
//--71=1(容器名称长度) + 64(容器名称) + 6(6个EF文件的SFI) + 1(容器类型)
#define  SIZE_CONTAINER_ITEM    72

//应用ADF下EF02文件的大小，存储容器名称等信息
#define  SIZE_ADF_EF02  (MAX_CONTAINER_NUM*SIZE_CONTAINER_ITEM )

//应用ADF下EF01文件的大小，存储文件名称等信息
#define  SIZE_ADF_EF01  (MAX_FILE_NUM*SIZE_FILE_ITEM)

//CA环境下EF01文件的大小，存储应用名称等信息
#define  SIZE_CA_EF01  (MAX_APPLICATION_NUM*SIZE_APPLICATION_ITEM)

//CA环境下EF1E文件的大小，存储设备标签，设备厂商信息，设备算法等信息
#define  SIZE_CA_EF1E  240

//全局数据缓冲区
extern BYTE  sv_tmpData[1024000];  //1000K
extern DWORD sv_tmpDataLen;

//全局结构体变量
extern  APPLICATIONINFO  sv_stApplication;  //应用
extern  CONTAINERINFO    sv_stContainer;    //容器
extern  DEVINFO          sv_stDevice;       //设备
extern  DEVHANDLE        sv_hDev;           //设备句柄
extern  HASHINFO         sv_stHash;         //哈希杂凑对象

//有关容器定义变量
//注：
//--容器名称
extern BYTE sv_containerNameInfo[MAX_CONTAINER_NUM][SIZE_CONTAINER_ITEM];
extern BYTE sv_containerCurrentIndex;
//--容器内密钥文件SFI
extern const BYTE SV_CONTAINER_SFI[MAX_CONTAINER_NUM][6];
//--容器全局类型
extern ULONG sv_containerType;


//有关文件定义变量
//--文件名称
extern BYTE sv_fileNameInfo[MAX_FILE_NUM][SIZE_FILE_ITEM];
extern BYTE sv_fileCurrentIndex;
//--文件FID和SFI
extern const BYTE SV_EF_FID[MAX_FILE_NUM][2];


//有关应用定义变量
//--应用名称
extern BYTE sv_appNameInfo[MAX_APPLICATION_NUM][SIZE_APPLICATION_ITEM];
extern BYTE sv_appCurrentIndex;
extern CHAR sv_appName[33];
//--应用FID
extern const BYTE SV_ADF_FID[MAX_APPLICATION_NUM][2];


//有关PIN定义变量
extern BYTE sv_pinIndex[2];

//有关设备认证定义变量
extern int sv_nAuth;   //外部认证，设备认证
extern int sv_nUser;   //用户PIN
extern int sv_nAdmin;  //管理员PIN

//有关随机数定义变量
//取随机数的BLOCK长度 
#define RANDOM_BLOCK_SIZE SIZE_BUFFER_16 
BYTE sv_random[SIZE_BUFFER_1024];   //全局随机数缓冲区，最大长度1024字节
DWORD sv_randomLength;              //全局随机数缓冲区长度计数；

//有关签名定义变量
ECCSIGNATUREBLOB sv_eccSignBlob;
BYTE sv_signEF_FID[2];

void WriteLogToFile( CHAR* szLog );
void ResetLogFile( CHAR*  lpszName );
void WriteLogToFile2( CHAR* szLog );
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
