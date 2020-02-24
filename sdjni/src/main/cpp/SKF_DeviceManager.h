#ifndef SKF_DEVICE_MANAGER_H
#define SKF_DEVICE_MANAGER_H

#include "SKF_TypeDef.h"

ULONG SKF_EnumDev( char *pDrives, ULONG * pDrivesLen, ULONG * pulSize );
ULONG SKF_ConnectDev( char *szDrive, int *szNum );
ULONG SKF_DisConnectDev( HANDLE hDev );
ULONG SKF_GetDevInfo( HANDLE hDev, DEVINFO * pDevInfo );
ULONG SKF_GetFuncList( HANDLE hDev, char * pDevInfo );

#endif // SKF_DEVICE_MANAGER_H
