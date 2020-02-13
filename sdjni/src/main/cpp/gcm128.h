
#ifndef GCM_GCM_H
#define GCM_GCM_H

#include "sdk.h"

#define OK  (0)
#define NOK (1)
#define FAIL (2)

#define BYTE_BIT_LEN   (8)
#define BLOCK_BIT_LEN   (128)
#define BLOCK_BYTE_LEN   (16)
#define GHASH_IN_LEN   (32)

typedef void (*block128_f) (struct tmc_card *card, unsigned long mechanism, unsigned char in[BLOCK_BYTE_LEN], unsigned char out[BLOCK_BYTE_LEN], void *key);

struct st_ciph_128 {
    block128_f func;
    void *key;
    tmc_card_t *card;
    unsigned long mech;
};
typedef struct st_ciph_128 CIPH_CTX;

struct st_gcm_ctx {
    CIPH_CTX ciph;
    unsigned char H[BLOCK_BYTE_LEN];
    unsigned char J0[BLOCK_BYTE_LEN];
};
typedef struct st_gcm_ctx GCM_CTX;

struct st_ghash_ctx {
    unsigned char H[BLOCK_BYTE_LEN];
    unsigned char block[BLOCK_BYTE_LEN];
};
typedef struct st_ghash_ctx GHASH_CTX;





int GCM128_Init(GCM_CTX *ctx, block128_f block, void *Key, unsigned char *IV, unsigned long IVlen, struct tmc_card *card, unsigned long mechanism);

int GCM128_Encrypt(GCM_CTX *ctx,unsigned char *AAD, unsigned long AADlen,
                   unsigned char *Plaintext, unsigned long Plaintextlen,
                   unsigned char *Ciphertext, unsigned long *Ciphertextlen,
                   unsigned char *Tag, unsigned long *Taglen);

int GCM128_Decrypt(GCM_CTX *ctx,unsigned char *AAD, unsigned long AADlen,
                   unsigned char *Ciphertext, unsigned long Ciphertextlen,
                   unsigned char *Tag, unsigned long Taglen,
                   unsigned char *Plaintext, unsigned long *Plaintextlen);



#endif //GCM_GCM_H