#include <string.h>
#include "gcm128.h"

unsigned char R[16] = {0xE1,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

int compare(unsigned char *in, unsigned char v, unsigned long l)
{
    unsigned long i;

    for(i = 0; i < l; i++) {
        if (in[i] < v) {
            return -1;
        }
        else if(in[i] > v) {
            return 1;
        }
    }

    return 0;
}

void XOR(unsigned char *X, unsigned char *Y, unsigned long len, unsigned char *Z)
{
    unsigned long i;

    for(i = 0; i < len; i++) {
        Z[i] = X[i] ^ Y[i];
    }
}

//single right-shift
void SRS(unsigned char *X, unsigned long len)
{
    unsigned int i;
    unsigned char OR_next = 0,OR_cur = 0;

    for(i = 0; i < len; i++) {
        OR_next = (unsigned char)((X[i] << 7) & 0x80);
        X[i] = (unsigned char)((X[i] >> 1) & 0x7F) | OR_cur;
        OR_cur = OR_next;
    }
}

void Block_XOR(unsigned char *X, unsigned char *Y, unsigned char *Z)
{
    XOR(X,Y,BLOCK_BYTE_LEN,Z);
}

void Block_SRS(unsigned char *X)
{
    SRS(X,BLOCK_BYTE_LEN);
}

int INC(unsigned int s, unsigned char *in, unsigned long len)
{
    unsigned long i,limit;
    unsigned char val = 0;

    if (s == 0) {
        return OK;
    }

    if (s > (len << 3)) {
        return NOK;
    }

    if (s & (BYTE_BIT_LEN - 1)) {//暂不支持非8整数倍的s
        return NOK;
    }

    limit = len - (s >> 3);

    for(i = (len - 1); i >= limit; i--) {
        val = in[i];
        if (val == 0xFF) {
            in[i] = 0;
        }
        else {
            break;
        }
    }

    val++;
    in[i] = val;

    return OK;
}

//out = X*Y
void MOB(unsigned char *X, unsigned char *Y, unsigned char *out)
{
    int i,j;
    unsigned char Z[BLOCK_BYTE_LEN],V[BLOCK_BYTE_LEN];

    memset(Z, 0, sizeof(Z));
    memcpy(V, Y, sizeof(V));

    for(j = 0; j < BLOCK_BYTE_LEN; j++) {//16 bytes
        for(i = 0; i < BYTE_BIT_LEN; i++) {//8 bits
            if ((X[j] >> (7 - i)) & 1) {
                Block_XOR(Z, V, Z);
            }
            if (V[BLOCK_BYTE_LEN - 1] & 1) {
                Block_SRS(V);
                Block_XOR(V, R, V);
            }
            else {
                Block_SRS(V);
            }
        }
    }

    memcpy(out, Z, sizeof(Z));
}

void GHASH_init(GHASH_CTX *ctx, unsigned char *H)
{
    memset(ctx,0,sizeof(GHASH_CTX));
    memcpy(ctx->H, H, sizeof(ctx->H));
}

int GHASH_update(GHASH_CTX *ctx, unsigned char *in, unsigned long len)
{
    unsigned long i;

    if(len & (BLOCK_BYTE_LEN - 1)) {
        return NOK;
    }

    for(i = 0; i < len; i += BLOCK_BYTE_LEN) {
        Block_XOR(ctx->block, in + i, ctx->block);
        MOB(ctx->block, ctx->H, ctx->block);
    }

    return OK;
}

int GHASH_dofinal(GHASH_CTX *ctx, unsigned char *in, unsigned long len, unsigned char *out)
{
    unsigned long i;

    if(len & (BLOCK_BYTE_LEN - 1)) {
        return NOK;
    }

    for(i = 0; i < len; i += BLOCK_BYTE_LEN) {
        Block_XOR(ctx->block, in + i, ctx->block);
        MOB(ctx->block, ctx->H, ctx->block);
    }

    memcpy(out, ctx->block, sizeof(ctx->block));
    memset(ctx->block,0,sizeof(ctx->block));

    return OK;
}

int GHASH(unsigned char *H, unsigned char *in, unsigned long len, unsigned char *out)
{
    unsigned long i;
    unsigned char Y[BLOCK_BYTE_LEN];

    memset(Y,0,sizeof(Y));

    if(len & (BLOCK_BYTE_LEN - 1)) {
        return NOK;
    }

    for(i = 0; i < len; i += BLOCK_BYTE_LEN) {
        Block_XOR(Y, in + i, Y);
        MOB(Y, H, Y);
    }

    memcpy(out, Y, sizeof(Y));

    return OK;
}

unsigned long GCTR(CIPH_CTX *ciph, unsigned char *icb,  unsigned char *in, unsigned long len, unsigned char *out)
{
    unsigned long n,l,i;
    unsigned char block[BLOCK_BYTE_LEN];
    unsigned char IV[BLOCK_BYTE_LEN];

    if(0 == compare(in, 0, len)) {
        memset(out, 0, len);
        return len;
    }

    memcpy(IV, icb, BLOCK_BYTE_LEN);

    l = (len % BLOCK_BYTE_LEN);
    n = (len & (unsigned long)(~(BLOCK_BYTE_LEN - 1)));

    for(i = 0; i < n; i += BLOCK_BYTE_LEN) {
        //AES加密：明文IV,密文block,密钥Key
        (*ciph->func) (ciph->card, ciph->mech, IV, block, ciph->key);
        Block_XOR(in+i, block, out+i);

        INC(32, IV, BLOCK_BYTE_LEN);
    }

    if (l) {
        (*ciph->func) (ciph->card, ciph->mech, IV, block, ciph->key);
        XOR(in+i,block,l,out+i);
    }

    return (n + l);
}


int GCM128_Init(GCM_CTX *ctx, block128_f block, void *Key, unsigned char *IV, unsigned long IVlen, struct tmc_card *card, unsigned long mechanism)
{
    unsigned char Temp[GHASH_IN_LEN];

    if ((IVlen != 4)&&(IVlen != 8)
        &&(IVlen != 12)&&(IVlen != 13)&&(IVlen != 14)&&(IVlen != 15)&&(IVlen != 16)) {
        return NOK;
    }

    memset(ctx, 0, sizeof(*ctx));
    memset(Temp, 0, sizeof(Temp));

    ctx->ciph.func = block;
    ctx->ciph.key = Key;
    ctx->ciph.card = card;
    ctx->ciph.mech = mechanism;

    (*block) (card, mechanism, ctx->H, ctx->H, Key);//GHASH Prerequisites

    //GCTR ICB
    if ((IVlen << 3) == 96) {
        memcpy(ctx->J0, IV, IVlen);
        ctx->J0[BLOCK_BYTE_LEN - 1] |= 0x01;
    }
    else {
        memcpy(Temp, IV, IVlen);
        Temp[GHASH_IN_LEN - 1] |= IVlen;
        GHASH(ctx->H, Temp, sizeof(Temp), ctx->J0);
    }

    return OK;
}

int GCM128_Encrypt(GCM_CTX *ctx,unsigned char *AAD, unsigned long AADlen,
                   unsigned char *Plaintext, unsigned long Plaintextlen,
                   unsigned char *Ciphertext, unsigned long *Ciphertextlen,
                   unsigned char *Tag, unsigned long *Taglen)
{
    unsigned char ICB[BLOCK_BYTE_LEN];
    unsigned char Temp[BLOCK_BYTE_LEN];
    unsigned long length;
    GHASH_CTX ctx_hash;

    //calc Cipher
    memcpy(ICB,ctx->J0,sizeof(ICB));
    INC(32,ICB,sizeof(ICB));
    *Ciphertextlen = GCTR(&ctx->ciph, ICB, Plaintext, Plaintextlen, Ciphertext);

    //calc block S
    GHASH_init(&ctx_hash, ctx->H);
    length = AADlen % BLOCK_BYTE_LEN;
    if (!length) {
        GHASH_update(&ctx_hash, AAD, AADlen);
    }
    else {
        GHASH_update(&ctx_hash, AAD, AADlen - length);
        memset(Temp, 0, sizeof(Temp));
        memcpy(Temp, AAD + AADlen - length, length);
        GHASH_update(&ctx_hash, Temp, BLOCK_BYTE_LEN);
    }
    length = *Ciphertextlen % BLOCK_BYTE_LEN;
    if (!length) {
        GHASH_update(&ctx_hash, Ciphertext, *Ciphertextlen);
    }
    else {
        GHASH_update(&ctx_hash, Ciphertext, *Ciphertextlen - length);
        memset(Temp, 0, sizeof(Temp));
        memcpy(Temp, Ciphertext + *Ciphertextlen - length, length);
        GHASH_update(&ctx_hash, Temp, BLOCK_BYTE_LEN);
    }
    memset(Temp, 0, sizeof(Temp));
    Temp[4] = (unsigned char)((AADlen << 3) >> 24);
    Temp[5] = (unsigned char)((AADlen << 3) >> 16);
    Temp[6] = (unsigned char)((AADlen << 3) >> 8);
    Temp[7] = (unsigned char)((AADlen << 3) >> 0);
    Temp[12] = (unsigned char)(((*Ciphertextlen) << 3) >> 24);
    Temp[13] = (unsigned char)(((*Ciphertextlen) << 3) >> 16);
    Temp[14] = (unsigned char)(((*Ciphertextlen) << 3) >> 8);
    Temp[15] = (unsigned char)(((*Ciphertextlen) << 3) >> 0);
    GHASH_dofinal(&ctx_hash, Temp, BLOCK_BYTE_LEN, Temp);

    //calc Tag
    *Taglen = GCTR(&ctx->ciph, ctx->J0, Temp, BLOCK_BYTE_LEN, Tag);
    return OK;
}

int GCM128_Decrypt(GCM_CTX *ctx,unsigned char *AAD, unsigned long AADlen,
                   unsigned char *Ciphertext, unsigned long Ciphertextlen,
                   unsigned char *Tag, unsigned long Taglen,
                   unsigned char *Plaintext, unsigned long *Plaintextlen) {
    unsigned char ICB[BLOCK_BYTE_LEN];
    unsigned char Temp[BLOCK_BYTE_LEN];
    unsigned long length;
    GHASH_CTX ctx_h;

    if (Taglen != BLOCK_BYTE_LEN) {
        return NOK;
    }

    //calc block S
    GHASH_init(&ctx_h, ctx->H);
    length = AADlen % BLOCK_BYTE_LEN;
    if (!length) {
        GHASH_update(&ctx_h, AAD, AADlen);
    } else {
        GHASH_update(&ctx_h, AAD, AADlen - length);
        memset(Temp, 0, sizeof(Temp));
        memcpy(Temp, AAD + AADlen - length, length);
        GHASH_update(&ctx_h, Temp, BLOCK_BYTE_LEN);
    }
    length = Ciphertextlen % BLOCK_BYTE_LEN;
    if (!length) {
        GHASH_update(&ctx_h, Ciphertext, Ciphertextlen);
    } else {
        GHASH_update(&ctx_h, Ciphertext, Ciphertextlen - length);
        memset(Temp, 0, sizeof(Temp));
        memcpy(Temp, Ciphertext + Ciphertextlen - length, length);
        GHASH_update(&ctx_h, Temp, BLOCK_BYTE_LEN);
    }
    memset(Temp, 0, sizeof(Temp));
    Temp[4] = (unsigned char) ((AADlen << 3) >> 24);
    Temp[5] = (unsigned char) ((AADlen << 3) >> 16);
    Temp[6] = (unsigned char) ((AADlen << 3) >> 8);
    Temp[7] = (unsigned char) ((AADlen << 3) >> 0);
    Temp[12] = (unsigned char) ((Ciphertextlen << 3) >> 24);
    Temp[13] = (unsigned char) ((Ciphertextlen << 3) >> 16);
    Temp[14] = (unsigned char) ((Ciphertextlen << 3) >> 8);
    Temp[15] = (unsigned char) ((Ciphertextlen << 3) >> 0);
    GHASH_dofinal(&ctx_h, Temp, BLOCK_BYTE_LEN, Temp);

    //calc Tag'
    GCTR(&ctx->ciph, ctx->J0, Temp, BLOCK_BYTE_LEN, Temp);

    if (!memcmp(Tag, Temp, Taglen)) {
        memcpy(ICB, ctx->J0, sizeof(ICB));
        INC(32, ICB, sizeof(ICB));
        *Plaintextlen = GCTR(&ctx->ciph, ICB, Ciphertext, Ciphertextlen, Plaintext);
        return OK;
    } else {
        return NOK;
    }
}