#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "sdk.h"
 
//循环左移
static u_int32_t _irol_(u_int32_t a, u_int32_t b)
{
    u_int32_t c = 0;
    b = b % 32;
    c = a >> (32 - b);
    a = a << b;
    a = a|c;

    return a;
}

static void int2char(u_int32_t a, u_int8_t* b)
{
    b[0] = (a >> 24) & 0xFF;
    b[1] = (a >> 16) & 0xFF ;
    b[2] = (a >> 8) & 0xFF;
    b[3] = (a & 0xFF);
}

static u_int32_t char2int(const u_int8_t* a)
{
    return (a[0]<<24)+(a[1]<<16)+(a[2]<<8)+a[3];
}

//初始值
static const u_int32_t IV[] =
        {
                0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
                0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
        };

//常量
static u_int32_t Tj(u_int32_t j)
{
    if(j < 16)
    {
        return 0x79CC4519;
    }
    else if(j < 64)
    {
        return 0x7A879D8A;
    }
    else
    {
        return 0;
    }
}

//置换函数
static u_int32_t P0(u_int32_t a)
{
    return a ^ (_irol_(a, 9)) ^ (_irol_(a, 17));
}

static u_int32_t P1(u_int32_t a)
{
    return a ^ (_irol_(a, 15)) ^ (_irol_(a, 23));
}

//布尔函数
static u_int32_t FFj(u_int32_t x, u_int32_t y, u_int32_t z, u_int32_t j)
{
    if(j < 16)
    {
        return x ^ y ^ z;
    }
    else if( j < 64)
    {
        return (x & y)|(x & z)|(y & z);
    }
    else
    {
        return 0;
    }
}

static u_int32_t GGj(u_int32_t x, u_int32_t y, u_int32_t z, u_int32_t j)
{
    if(j <= 15)
    {
        return x ^ y ^ z;
    }
    if(j >= 16 && j <= 63)
    {
        return (x & y)|(~x & z);
    }

    return 0;
}

//数据填充
static int SM3_Ready(const u_int8_t* inBuf, int inLen, u_int8_t* outBuf, int* outLen)
{
    u_int32_t l = 0, k = 0;
    int n = 0;
    l = inLen * 8;
    k = (447 - l) % 512;
    n = (l+k+65)/512;

    if(*outLen < n *64)
    {
        *outLen = n * 64;
        return 1;
    }
    memmove(outBuf, inBuf, inLen);
    outBuf[inLen] = 0x80;
    *outLen = n * 64;

    memset(outBuf+inLen+1, 0, n*64-inLen-5);
    int2char(l, outBuf+n*64-4);

    return 0;
}

static int SM3_Extend(const u_int8_t inBuf[64], u_int32_t W[68], u_int32_t W1[64])
{
    u_int32_t i = 0;

    for(i=0; i<16; i++)
    {
        W[i] = char2int(inBuf+4*i);
    }

    for(i=16; i<68; i++)
    {
        W[i] = P1(W[i-16] ^ W[i-9] ^ _irol_(W[i-3], 15)) ^ _irol_(W[i-13], 7) ^ W[i-6];
    }
    for(i=0; i<64; i++)
    {
        W1[i] = W[i] ^ W[i+4];
    }

    return 0;
}

static int CF(const u_int32_t Vi[8], u_int32_t W[68], u_int32_t W1[64], u_int32_t Vn[8])
{
    u_int32_t SS1, SS2, TT1, TT2, i=0;
    u_int32_t A[8] = {0};

    memmove(A, Vi, 32);
    memmove(Vn, A, 32);

    for(i=0; i<64; i++)
    {
        SS1 = _irol_(_irol_(A[0], 12) + A[4] + _irol_(Tj(i), i), 7);
        SS2 = SS1 ^ _irol_(A[0], 12);
        TT1 = FFj(A[0], A[1], A[2], i) + A[3] + SS2 + W1[i];
        TT2 = GGj(A[4], A[5], A[6], i) + A[7] + SS1 + W[i];
        A[3] = A[2];
        A[2] = _irol_(A[1], 9);
        A[1] = A[0];
        A[0] = TT1;
        A[7] = A[6];
        A[6] = _irol_(A[5], 19);
        A[5] = A[4];
        A[4] = P0(TT2);
    }
    for(i=0; i<8; i++)
    {
        Vn[i] = Vn[i] ^ A[i];
    }

    return 0;
}

/******************************************************************************
*功能：
*	计算SM3
*参数：
*	pInBuf		[in] 需要计算摘要的源数据
*	inLen		[in] 数据长度
*	pOutBuf  	[out]消息摘要
*返回值：
*
*******************************************************************************/
void SM3(const u_int8_t *pInBuf, int inLen, u_int8_t *pOutBuf)
{
    u_int32_t W[68], W1[64], mVn[8], Vn[8];
    u_int8_t *midBuf = NULL;

    int midLen = ((inLen+8)/64+1)*64, i = 0;
    midBuf = (u_int8_t*)malloc(midLen);
    memmove(Vn, IV, 32);
    SM3_Ready(pInBuf, inLen, midBuf, &midLen);
    for(i=0; i<midLen; i+=64)
    {
        memset(W, 0, 68*4);
        memset(W1, 0, 64*4);
        memmove(mVn, Vn, 32);
        SM3_Extend(midBuf+i, W, W1);
        CF(mVn, W, W1, Vn);
    }

    for(i=0; i<8; i++)
    {
        int2char(Vn[i], pOutBuf+4*i);
    }
    if(midBuf)
    {
        free(midBuf);
    }

    return;
}

/******************************************************************************
*功能：
*	SM3初始化
*参数：
*	ctx		[in] 缓存结构(void指针,与平台相关)
*
*返回值：
*	无
*******************************************************************************/
static SM3_CTX sCtx;
void SM3_Init(void **ctx)
{
    memset(&sCtx, 0, sizeof(SM3_CTX));
    memmove(sCtx.state, IV, 32);
    sCtx.curlen = 0;
    sCtx.len = 0;
    memset(sCtx.buf, 0, 64);
    *ctx = (void *)&sCtx;
}

/******************************************************************************
*功能：
*	计算SM3
*参数：
*	ctx		[in] 缓存结构(void指针,与平台相关)
*	pInBuf	[in] 输入数据
*	inLen	[in] 数据长度
*返回值：
*	无
*******************************************************************************/
void SM3_Update(void *ctx, const u_int8_t *pInBuf, u_int32_t inLen)
{
    int midLen = 0, ll = 0, i = 0;
    u_int8_t *midBuf = NULL;
    u_int32_t W[68], W1[64], mVn[8], Vn[8];

    SM3_CTX *sm3_Ctx = (SM3_CTX *)ctx;
    if(sm3_Ctx->curlen + inLen < 64)
    {
        memmove(sm3_Ctx->buf+sm3_Ctx->curlen, pInBuf, inLen);
        sm3_Ctx->curlen += inLen;

        return;
    }

    midLen = inLen+64;
    ll = (sm3_Ctx->curlen + inLen) % 64;
    midBuf = (u_int8_t*)malloc(inLen + 64);
    memmove(midBuf, sm3_Ctx->buf, sm3_Ctx->curlen);
    memmove(midBuf+sm3_Ctx->curlen, pInBuf, inLen-ll);
    midLen = sm3_Ctx->curlen + inLen - ll;
    sm3_Ctx->len += midLen;
    memmove(sm3_Ctx->buf, pInBuf + inLen -ll, ll);
    sm3_Ctx->curlen = ll;

    memmove(Vn, sm3_Ctx->state, 32);
    for(i=0; i<midLen; i+=64)
    {
        memset(W, 0, 68*4);
        memset(W1, 0, 64*4);
        memmove(mVn, Vn, 32);
        SM3_Extend(midBuf+i, W, W1);
        CF(mVn, W, W1, Vn);
    }
    memmove(sm3_Ctx->state, Vn, 32);
    if(midBuf)
    {
        free(midBuf);
    }

    return;
}

/******************************************************************************
*功能：
*	输出消息摘要
*参数：
*	ctx		[in] 缓存结构(void指针,与平台相关)
*	pOutBuf	[out]消息摘要值
*返回值：
*	无
*******************************************************************************/
void SM3_Final(void *ctx, u_int8_t *pOutBuf)
{
    u_int32_t l = 0, k = 0;
    int n = 0, i=0;
    u_int32_t W[68], W1[64], mVn[8], Vn[8];
    u_int8_t midBuf[128] = {0};
    SM3_CTX *sm3_Ctx = (SM3_CTX *)ctx;

    l = (sm3_Ctx->len + sm3_Ctx->curlen) * 8;
    k = (447 - l) % 512;
    n = (sm3_Ctx->curlen*8+k+65)/512;

    memmove(midBuf, sm3_Ctx->buf, sm3_Ctx->curlen);
    midBuf[sm3_Ctx->curlen] = 0x80;
    int2char(l, midBuf+n*64-4);

    memmove(Vn, sm3_Ctx->state, 32);
    for(i=0; i<n; i++)
    {
        memset(W, 0, 68*4);
        memset(W1, 0, 64*4);
        memmove(mVn, Vn, 32);
        SM3_Extend(midBuf+i*64, W, W1);
        CF(mVn, W, W1, Vn);
    }

    for(i=0; i<8; i++)
    {
        int2char(Vn[i], pOutBuf+4*i);
    }
    return;
}
