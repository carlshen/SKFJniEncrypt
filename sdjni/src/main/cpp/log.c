/*
 * Copyright (C) 2018 TMC
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

//1 1.重启仍然用原日志文件
//1 2.日志每一句增加时间点
//1 3.需要支持多线程
//1 4.日志名称固定为tmc_sdk.log

#define LOG_SIZE		(1024*1024*10)// 10M

#ifndef DEBUG
char log_name[] = "/sdcard/log/tmc_sdk.log";
char log_name_bak[] = "/sdcard/log/tmc_sdk.log.0";
#else
char log_name[] = "/home/pi/log/tmc_sdk.log";
char log_name_bak[] = "/home/pi/log/tmc_sdk.log.0";
#endif

FILE *fp = NULL;
pthread_mutex_t m;
unsigned char mutex_init = 0;

void tmc_printf_init(void)
{
    if ((fp = fopen(log_name, "w")) == NULL) {
        printf("Create log file failed!\n");
        return;
    }

    fclose(fp);

    pthread_mutex_init(&m, NULL);
    mutex_init = 1;
}

void tmc_printf_t(const char *fmt,...)
{
	struct timeval tv;
	struct tm * tmp;
	
	time_t t;
	struct tm * lt;
	char s[512] = {0};
	char str[512] = {0};
	struct stat st ;

	va_list ap;
	va_start(ap, fmt);
	vsprintf(str, fmt, ap);
	va_end(ap);

	printf("%s", str);

	if (!mutex_init) {
		pthread_mutex_init(&m, NULL);
	}

	while (pthread_mutex_lock(&m) != 0);//pthread lock

	stat(log_name, &st );
	if (st.st_size > LOG_SIZE) {
		rename(log_name, log_name_bak);
		if ((fp = fopen(log_name, "w")) == NULL) {
			printf("Create log file failed!\n");
			return;
		}
	}
	else {
		if ((fp = fopen(log_name, "a")) == NULL) {
			printf("Open log file failed!\n");
			return;
		}
	}
#if 1
	gettimeofday(&tv, NULL);
	tmp = localtime(&tv.tv_sec);
	if (tmp == NULL) {
		return;
	}
	strftime(s, sizeof(s), "%F %T", tmp);
	sprintf(s, "%s.%03d ", s, (int)tv.tv_usec/1000);
#else
	time(&t);
	lt = localtime(&t);
	sprintf(s, "[%d-%02d-%02d %02d:%02d:%02d] : ", lt->tm_year + 1900, lt->tm_mon+1, lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec);
#endif

	strcat(s, str);

	fputs(s, fp);
	fclose(fp);

	while (pthread_mutex_unlock(&m) != 0);//pthread unlock
}

void tmc_printf(const char *fmt,...)
{
    char s[512] = {0};
    va_list ap;
	
    va_start(ap, fmt);
    vsprintf(s, fmt, ap);
    va_end(ap);
	
    printf("%s", s);

    if (!mutex_init) {
        pthread_mutex_init(&m, NULL);
    }

    while (pthread_mutex_lock(&m) != 0);//pthread lock

    if ((fp = fopen(log_name, "a")) == NULL) {
        printf("Open log file failed!\n");
        return;
    }

    fputs(s, fp);
    fclose(fp);

    while (pthread_mutex_unlock(&m) != 0);//pthread unlock
}

