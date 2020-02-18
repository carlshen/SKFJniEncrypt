#ifndef SKF_ALGORITHM_H
#define SKF_ALGORITHM_H

#include "Global_Def.h"

ULONG Algo_Group_ECB( HANDLE hKey, BYTE* pbInData, ULONG ulInDataLen, 
							BYTE* pbOutData, ULONG* pulOutDataLen );
ULONG Algo_Group_CBC( HANDLE hKey, BYTE* pbInData, ULONG ulInDataLen,
							BYTE* pbOutData, ULONG* pulOutDataLen );

#endif //SKF_ALGORITHM_H
