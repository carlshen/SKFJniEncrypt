#ifndef SKF_DEVICE_MANAGER_H
#define SKF_DEVICE_MANAGER_H

#include "SKF_TypeDef.h"

ULONG SKF_EnumDev( BOOL bPresent, LPSTR szNameList, ULONG * pulSize );
ULONG SKF_ConnectDev( LPSTR szName, DEVHANDLE *phDev );
ULONG SKF_DisConnectDev( DEVHANDLE hDev );
ULONG SKF_GetDevInfo( DEVHANDLE hDev, DEVINFO * pDevInfo );
ULONG SKF_GetFuncList( DEVHANDLE hDev, DEVINFO * pDevInfo );

#endif // SKF_DEVICE_MANAGER_H
