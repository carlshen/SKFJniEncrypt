//
// Created by carl on 20-2-13.
//

#ifndef SDK_LOG_H
#define SDK_LOG_H

#define LOG_SIZE		(1024*1024*10)// 10M
static const int log_len = 64;
static char log_name[log_len] = "/sdcard/tmc_sdk.log";
static char log_name_bak[log_len] = "/sdcard/tmc_sdk.log.0";
//#ifndef DEBUG
//char log_name[] = "/sdcard/log/tmc_sdk.log";
//char log_name_bak[] = "/sdcard/log/tmc_sdk.log.0";
//#else
//char log_name[] = "/sdcard/log/tmc_sdk.log";
//char log_name_bak[] = "/sdcard/log/tmc_sdk.log.0";
//#endif

#endif //SDK_LOG_H
