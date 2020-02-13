//
// Created by Administrator on 2018/8/8.
//

#include <stdlib.h>
#include <string.h>

#include "sdk.h"

static struct tmc_driver_operations spi_ops;
static struct tmc_driver spi_driver = {
        "SPI driver",
        "spi",
        &spi_ops,
        NULL
};

int tmc_internal_transmit(tmc_context_t * ctx,
                         u8 *sendbuf, int sendsize,
                          u8 *recvbuf, int *recvsize)
{
#ifdef ENABLE_IIC
    int i,err=-1,RETRY_COUNT=3;

    for (i = 0; i < RETRY_COUNT; i++) {

        err = tmc_i2c_send(sendbuf, sendsize);
        if (err) {
            // 重发
            usleep(50000);//50ms
            continue;
        }

        err = tmc_i2c_receive(recvbuf, recvsize);
        if (err) {
            // 重发
            usleep(50000);//50ms
            continue;
        }

        return 0;
    }
    return -1;
#else
    int ret = 0;

    for (int i = 0; i < RETRY_SEND_COUNT; ++i) {

        ret = tmc_spi_send(sendbuf, sendsize);
        if(ret != SC_SUCCESS)
        {
            return ret;
        }


        ret = tmc_spi_receive(recvbuf, recvsize);

        if((ret == 5) || (ret == -1))
        {
            // 重发
            continue;
        }

        if(ret != SC_SUCCESS)
        {
            return ret;
        }
        else
        {
            break;
        }
    }

    return ret;
#endif
}

static int spi_init(tmc_context_t * context)
{
    int rv = 0;
#ifdef ENABLE_IIC
    rv = tmc_i2c_open();
    if (rv < 0) {
        return rv;
    } else {
        tmc_i2c_wakeup();
        return 0;
    }
#else
    rv = tmc_spi_open();
    if (rv < 0) {
        return rv;
    } else {
        tmc_spi_wakeup();
        return 0;
    }
#endif
}

static int spi_finish(tmc_context_t *ctx)
{
    int ret = 0;
#ifdef ENABLE_IIC
    tmc_i2c_sleep();
    ret = tmc_i2c_close();
    return SC_SUCCESS;
#else
    tmc_spi_sleep();
    ret = tmc_spi_close();
    return SC_SUCCESS;
#endif
}



static int spi_transmit(tmc_context_t * ctx, tmc_apdu_t * apdu)
{
    int ssize, rsize = 0;
    int tmpsize = 0;
    u8 *rbuf, *sbuf = NULL;
    int r;
    rsize = SC_MAX_APDU_BUFFER_SIZE;
    rbuf = malloc((size_t)rsize);
    if (rbuf == NULL) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    sbuf = malloc((size_t)rsize);
    if (sbuf == NULL) {
        r = SC_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    tmc_apdu_to_buf(apdu, sbuf);
    ssize = apdu->lc + SC_MAX_APDU_HEADER_SIZE;

    //tmc_spi_lock();

    r = tmc_internal_transmit(ctx, sbuf, ssize, rbuf, &tmpsize);

    if(r != SC_SUCCESS)
    {
        goto out;
    }
    //tmc_spi_unlock();

    if(tmpsize){
        rsize = tmpsize;
    }


    r = tmc_apdu_set_resp(ctx, apdu, rbuf, (size_t)rsize);

    out:

    if(rbuf)
    {
        free(rbuf);
    }
    if(sbuf)
    {
        free(sbuf);
    }
    return r;
}

static int spi_detect_card_presence(tmc_context_t *ctx)
{
    int rv = 0;

    //待确认驱动需要预初始化什么

    return rv;
}

static int spi_release(tmc_context_t *ctx)
{

    return SC_SUCCESS;
}

static int spi_connect(void)
{
    int rv = 0;


    return rv;
}

static int spi_disconnect(tmc_context_t *ctx)
{
    //断开卡片连接

    //更新结构体中的驱动信息

    return SC_SUCCESS;
}


static int spi_reset(tmc_context_t *ctx)
{
    //获取驱动信息，查看是否有其他应用占用等情形

    //发生复位信号

    //更新结构体中的驱动信息

    return SC_SUCCESS;
}


static int spi_lock(tmc_context_t *ctx)
{

    //获取驱动信息，查看是否有其他应用占用等情形

    //发生复位信号

    //更新结构体中的驱动信息

    return SC_SUCCESS;
}

static int spi_unlock(tmc_context_t *ctx)
{

    //获取驱动信息，查看是否有其他应用占用等情形

    //发生复位信号

    //更新结构体中的驱动信息

    return SC_SUCCESS;
}
static int spi_detect_cards(tmc_context_t *ctx)
{

    return SC_SUCCESS;
}

int tmc_apdu_set_resp(tmc_context_t *ctx, tmc_apdu_t *apdu, const u8 *buf,
                      CK_ULONG len)
{
    if (len < 2) {
        /* no SW1 SW2 ... something went terrible wrong */
        return SC_ERROR_INTERNAL;
    }
    /* set the SW1 and SW2 status bytes (the last two bytes of
     * the response */
    apdu->sw1 = (unsigned int)buf[len - 2];

    apdu->sw2 = (unsigned int)buf[len - 1];
    len -= 2;
    /* set output length and copy the returned data if necessary */
    apdu->resplen = len;

    if (apdu->resplen != 0)
        memcpy(apdu->resp, buf, apdu->resplen);

    return SC_SUCCESS;
}

struct tmc_driver * tmc_get_spi_driver(void)
{
    spi_ops.init = spi_init;
    spi_ops.finish = spi_finish;
    spi_ops.transmit = spi_transmit;
    spi_ops.detect_card_presence = spi_detect_card_presence;
    spi_ops.lock = spi_lock;
    spi_ops.unlock = spi_unlock;
    spi_ops.release = spi_release;
    spi_ops.connect = spi_connect;
    spi_ops.disconnect = spi_disconnect;
    spi_ops.detect_cards = spi_detect_cards;
    //spi_ops.perform_verify = pcsc_pin_cmd;
    //spi_ops.wait_for_event = pcsc_wait_for_event;
    //spi_ops.cancel = pcsc_cancel;
    spi_ops.reset = spi_reset;
    //spi_ops.use_reader = pcsc_use_reader;
    //spi_ops.perform_pace = pcsc_perform_pace;

    return &spi_driver;
}
