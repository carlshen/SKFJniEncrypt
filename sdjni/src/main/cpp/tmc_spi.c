
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>

#include "sdk.h"

#define TMC_SEND_MAX 261
#define TMC_RECE_MAX 258
#define TMC_SPI_MAX 4

#ifdef RAS_PI
static const char *device = "/dev/spidev0.0";
#else
static const char *device = "/dev/tmc-spidev";
#endif
static uint8_t mode = 1; /* SPI communicate use full duplex, CPOL = 0, CPHA = 1 */
static uint8_t bits = 8; /* 8bits read&write , MSB First*/
static uint32_t speed = 1 * 1000 * 1000;/* set 1M transmit speed*/
static uint16_t Delay = 20;
static int g_SPI_Fd = 0;

static void PrintAPDU(const char *s, uint8_t *buff, int len)
{
#ifdef APDU_PRINT
    int i;
	tmc_printf_t("%s [Len:%d]: ", s, len);
	for (i = 0; i < len; i++)
	{
		if (i % 8 == 0)
            tmc_printf("\n\t");
        tmc_printf("0x%02X ", buff[i]);
	}
    tmc_printf("\n");
#else
    (void *)s;
    (void *)buff;
    (void *)len;
#endif
}

static void pabort(const char *s)
{
	perror(s);
	abort();
}

static void delayT(int ns)
{
	struct timespec ts, ts1;

	ts.tv_nsec = ns;
	ts.tv_sec = 0;
	nanosleep(&ts, &ts1);
}

static uint8_t tmc_spi_crc(uint8_t *InBuf, int len)
{
	uint8_t ret = 0;
	int i;

	for (i=0;i<len;i++) {
        ret = ret ^ InBuf[i];
	}
	return ret;
}


static int SPI_Write(uint8_t *TxBuf, int len)
{
	int ret;
	int fd = g_SPI_Fd;
    struct spi_ioc_transfer tr = {
            .tx_buf = (unsigned long)TxBuf,
            .rx_buf = (unsigned long)TxBuf,
            .len = (unsigned int)len,
            .delay_usecs = Delay,
            .speed_hz = speed,
            .bits_per_word = bits
    };

//    ret = ioctl(fd, SPI_IOC_MESSAGE(1), &tr);
//	if (ret < 0) {
//        tmc_printf_t("ERROR: spi write failed. error code = %d.\n", ret);
//        return -1;
//	}

	return 0;
}

static int SPI_Read(uint8_t *RxBuf, int len)
{
	int ret;
	int fd = g_SPI_Fd;
    struct spi_ioc_transfer tr = {
            .tx_buf = (unsigned long)RxBuf,
            .rx_buf = (unsigned long)RxBuf,
            .len = (unsigned int)len,
            .delay_usecs = Delay,
            .speed_hz = speed,
            .bits_per_word = bits,
    };

//    ret = ioctl(fd, SPI_IOC_MESSAGE(1), &tr);
//	if (ret < 0) {
//        tmc_printf_t("ERROR: spi read failed. error code =  %d.\n", ret);
//        return -1;
//	}

	return 0;
}

/**
* 功 能：开启设备
* 入口参数 ：
* 出口参数：
* 返回值：0 表示开启成功 1 表示已开启设备 -1 出错
*/
int tmc_spi_open(void)
{
	int fd;
	int ret = 0;

	if (g_SPI_Fd) {/* 设备已打开 */
        return 1;
	}

	fd = open(device, O_RDWR);
	if (fd < 0) {/*  文件可以被打开需要进一步查询锁     */
        tmc_printf_t("ERROR: open the device: %s failed.\n", device);
        abort();
	}
	else {
	    if (flock(fd, LOCK_EX | LOCK_NB)) {
            tmc_printf_t("ERROR: the device was locked.\n");
            sleep(3);
            while(flock(fd, LOCK_EX | LOCK_NB) == 0)
            {
                tmc_printf_t("wait for unlock.\n");
                sleep(3);
            }
	    }
	}

	g_SPI_Fd = fd;
	/*
	* spi mode
	*/
//	ret = ioctl(fd, SPI_IOC_WR_MODE, &mode);
//	if (ret < 0) {
//        pabort("ERROR: can't set spi mode.\n");
//	}
//
//	ret = ioctl(fd, SPI_IOC_RD_MODE, &mode);
//	if (ret < 0) {
//        pabort("ERROR: can't get spi mode.\n");
//	}
//	/*
//	* bits per word
//	*/
//	ret = ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
//	if (ret < 0) {
//        pabort("ERROR: can't set bits per word.\n");
//	}
//
//	ret = ioctl(fd, SPI_IOC_RD_BITS_PER_WORD, &bits);
//	if (ret < 0) {
//        pabort("ERROR: can't get bits per word.\n");
//	}
//	/*
//	* max speed hz
//	*/
//	ret = ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
//	if (ret < 0) {
//        pabort("ERROR: can't set max speed hz.\n");
//	}
//
//	ret = ioctl(fd, SPI_IOC_RD_MAX_SPEED_HZ, &speed);
//	if (ret < 0) {
//        pabort("ERROR: can't get max speed hz.\n");
//	}

    if (speed >= (1 * 1000 * 1000)) {
        tmc_printf_t("SPI Open Success: mode=%d, %dbits, %d MHz\n", mode, bits, speed / 1000 / 1000);
    }
    else {
        tmc_printf_t("SPI Open Success: mode=%d, %dbits, %d KHz\n", mode, bits, speed / 1000);
    }

	return ret;
}

/**
* 功 能：发送SPI数据
* 入口参数 ：
* 出口参数：
* 返回值：0 表示发送成功 -1 出错
*/
int tmc_spi_send(uint8_t *TxBuf, int len)
{
    if (!g_SPI_Fd) {/* 设备已关闭 */
        return -1;
    }

    if (len > TMC_SEND_MAX) {
        tmc_printf_t("ERROR: sending data is too long.\n");
        return -1;
    }

	int outlen = len + TMC_SPI_MAX;
	uint8_t outBuf[outlen];

    memset(outBuf,0,outlen);

	outBuf[0] = 0xAA;
	outBuf[1] = len >> 8;
	outBuf[2] = len >> 0;
	memcpy(outBuf + 3, TxBuf, len);
	outBuf[outlen -1] = tmc_spi_crc(TxBuf, len);

    PrintAPDU("SPI Send", outBuf, len + 4);
    return SPI_Write(outBuf,outlen);
}

/**
* 功 能：接收SPI数据
* 入口参数 ：
* 出口参数：
* 返回值：0 表示接收成功 -1 出错
*/
int tmc_spi_receive(uint8_t *RxBuf, int* len)
{
	int findAA = 0;
	int count = 10000000;
	int inlen;
	uint8_t crc ;
	uint8_t inBuf[TMC_RECE_MAX + TMC_SPI_MAX];

    if (!g_SPI_Fd) {/* 设备已关闭 */
        return -1;
    }

	memset(inBuf,0,TMC_RECE_MAX + TMC_SPI_MAX);

    delayT(200000);//200us

	while(count--)
	{
		if(SPI_Read(inBuf, 1) < 0) {
		    return -1;
		}
		if (inBuf[0] == 0xaa)
		{
            findAA = 1;	//查找到正常返回的tag
			break;
		}
		else if (inBuf[0] == 0x00) {
            tmc_printf_t("ERROR: wrong tag\n");
            delayT(3000000); //主收到异常响应到重发指令的时间大于2ms
            return -1;
		}
        else if (inBuf[0] == 0x10) {
            tmc_printf_t("ERROR: wrong crc\n");
            delayT(3000000); //主收到异常响应到重发指令的时间大于2ms
            return -1;
        }
        else if (inBuf[0] == 0x20) {
            tmc_printf_t("ERROR: time out\n");
            delayT(3000000); //主收到异常响应到重发指令的时间大于2ms
            return -1;
        }
		else if (inBuf[0] == 0xFF) {
		    //busy
		}
		else {
            tmc_printf_t("ERROR: invalid tag: 0x%02X\n", inBuf[0]);
            delayT(3000000); //主收到异常响应到重发指令的时间大于2ms
			return -1;
		}

        delayT(20000);//20us
	}

	if (findAA)
	{
	    if (SPI_Read(inBuf + 1, 2) < 0) {
            return -1;
	    }
	    inlen = (inBuf[1] << 8) | (inBuf[2]);

        if (SPI_Read(inBuf + 3, inlen + 1) < 0) {
            return -1;
        }

        crc = tmc_spi_crc(inBuf + 3, inlen);
        if (crc != inBuf[inlen + 3]) {
            tmc_printf_t("ERROR: crc check failed.\n");
            return -1;
        }

        if (RxBuf) {
            memcpy(RxBuf, inBuf + 3, inlen);
        }
        if (len) {
            *len = inlen;
        }

        PrintAPDU("SPI Recv", inBuf, inlen + 4);
        delayT(100000); //receive to send, delay 100us
        return 0;
	}
	else {
        tmc_printf_t("ERROR: not receive tag 0xAA.\n");
        return -1;
	}
}

/**
* 功 能：关闭设备
* 入口参数 ：
* 出口参数：
* 返回值：0 表示关闭成功 1 表示已关闭
*/
int tmc_spi_close(void)
{
	if (!g_SPI_Fd) {/* 设备已关闭 */
	    return 1;
	}
		
	close(g_SPI_Fd);
	g_SPI_Fd = 0;

    tmc_printf_t("SPI Close Success\n");
	return 0;
}

/**
* 功 能：唤醒SPI
* 入口参数 ：
* 出口参数：
* 返回值：0 表示唤醒成功 -1 出错
*/
int tmc_spi_wakeup(void)
{
    int ret = 0;
    uint8_t wakeup = 0x55;

    if (!g_SPI_Fd) {/* 设备已关闭 */
        return -1;
    }

    //SPI唤醒
    ret = SPI_Write(&wakeup, 1);
    if (ret < 0) {
        return ret;
    }

    delayT(200000);//200us

    return 0;
}

/**
* 功 能：休眠SPI
* 入口参数 ：
* 出口参数：
* 返回值：0 表示休眠成功 -1 出错
*/
int tmc_spi_sleep(void)
{
    uint8_t sendbuf[2] = {0x02,0x02};
    uint8_t recebuf[2];
    int len;
    int ret = 0;

    if (!g_SPI_Fd) {/* 设备已关闭 */
        return -1;
    }

    //SPI休眠
    ret = tmc_spi_send(sendbuf, 2);
    if (ret != 0) {
        return ret;
    }

    ret = tmc_spi_receive(recebuf, &len);
    if (ret != 0) {
        return ret;
    }

    if ((len != 2) || ((recebuf[0] != 0x90) || (recebuf[1] != 0x00))) {
        return -1;
    }

    return 0;
}


int spidemo()
{
    int i,err=-1,RETRY_COUNT=3;
    uint8_t sendbuf[5] = {0xFC,0xFF,0x10,0x00,0x05};
    uint8_t recebuf[5] = {0};
    int len;

    tmc_spi_open();
    tmc_spi_wakeup();

    for (i = 0; i < RETRY_COUNT; i++) {

        err = tmc_spi_send(sendbuf, sizeof(sendbuf));
        if (err) {
            return err;
        }

        err = tmc_spi_receive(recebuf, &len);
        if (err) {
            // 重发
            continue;
        }

        break;
    }

    tmc_spi_sleep();
    tmc_spi_close();

    return err;
}
