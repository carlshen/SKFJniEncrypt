#ifndef SKF_CONTAINERMANAGER_H
#define SKF_CONTAINERMANAGER_H

#include "SKF_TypeDef.h"

ULONG SKF_ImportCertificate( DEVHANDLE hContainer, BOOL bSignFlag, BYTE* pbCert, ULONG ulCertLen );
ULONG SKF_ExportCertificate( DEVHANDLE hContainer, BOOL bSignFlag, BYTE* pbCert, ULONG* pulCertLen );

#endif //SKF_CONTAINERMANAGER_H
