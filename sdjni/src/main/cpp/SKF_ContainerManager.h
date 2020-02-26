#ifndef SKF_CONTAINER_MANAGER_H
#define SKF_CONTAINER_MANAGER_H

#include "SKF_TypeDef.h"

ULONG SKF_ImportCertificate( HANDLE hContainer, BOOL bSignFlag, BYTE* pbCert );
ULONG SKF_ExportCertificate( HANDLE hContainer, BOOL bSignFlag, BYTE* pbCert, ULONG* pulCertLen );

#endif //SKF_CONTAINER_MANAGER_H
