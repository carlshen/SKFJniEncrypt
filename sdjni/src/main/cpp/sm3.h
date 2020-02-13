#ifndef TMC_PKCS11_SM3_H
#define TMC_PKCS11_SM3_H


#ifdef  __cplusplus
extern "C" {
#endif

#include <types.h>


void SM3(const uint8_t *pInBuf, int inLen, uint8_t *pOutBuf);



#ifdef  __cplusplus
}
#endif

#endif
