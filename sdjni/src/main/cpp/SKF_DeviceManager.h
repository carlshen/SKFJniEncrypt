#ifndef SKF_DEVICEMANAGER_H
#define SKF_DEVICEMANAGER_H

#include "SKF_TypeDef.h"

ULONG del(CHAR *a, ULONG n);
ULONG SKF_EnumDev( BOOL bPresent, LPSTR szNameList, ULONG * pulSize );
ULONG SKF_ConnectDev( LPSTR szName, DEVHANDLE *phDev );
ULONG SKF_DisConnectDev( DEVHANDLE hDev );
ULONG SKF_GetDevInfo( DEVHANDLE hDev, DEVINFO * pDevInfo );

#endif //SKF_DEVICEMANAGER_H
