//
// Created by 00498 on 2019/12/16.
//

#include <jni.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <zconf.h>
#include <time.h>
#include <string.h>
#include "logger.h"
#include "SDSCErr.h"
#include "SDSCDev.h"
#include "transmit.h"

static unsigned long g_ulDebugLoopIndex;
int trans_dev_id = -1;
uint64_t device_total_size = 0; //block size, 512 bytes/per block

#ifdef __cplusplus
extern "C" {
#endif  /*__cplusplus*/
static void big_intToByte(int i, int len, unsigned char * abyte) {
    memset(abyte,0, len);
    if (len == 1) {
        abyte[0] = (unsigned char) (0xff & i);
    } else if (len == 2) {
        abyte[0] = (unsigned char) ((i >> 8) & 0xff);
        abyte[1] = (unsigned char) (i & 0xff);
    } else {
        abyte[0] = (unsigned char) ((i >> 24) & 0xff);
        abyte[1] = (unsigned char) ((i >> 16) & 0xff);
        abyte[2] = (unsigned char) ((i >> 8) & 0xff);
        abyte[3] = (unsigned char) (i & 0xff);
    }
}

static int big_bytesToInt(unsigned char * bytes, int len) {
    int int_ret = 0;
    if (len == 1) {
        int_ret = bytes[0] & 0xFF;
    } else if (len == 2) {
        int_ret = bytes[0] & 0xFF;
        int_ret = (int_ret << 8) | (bytes[1] & 0xff);
    } else {
        int_ret = bytes[0] & 0xFF;
        int_ret = (int_ret << 8) | (bytes[1] & 0xff);
        int_ret = (int_ret << 8) | (bytes[2] & 0xff);
        int_ret = (int_ret << 8) | (bytes[3] & 0xff);
    }
    return int_ret;
}

unsigned char CalculateCheckSum(unsigned char * ucData, unsigned long ulByteNum){
    unsigned char ucRet = 0;
    unsigned char * pucTmp = ucData;

    for(int i=0;i<ulByteNum;i++){
        ucRet = ucRet^(*pucTmp);
        pucTmp++;
    }

    return ucRet;
}

int GetVersion(char* Version) {
    char * pVersion = (char *) malloc(SDSC_MAX_VERSION_LEN * sizeof(char));
    unsigned long ulResult = 0;
    memset(pVersion, 0x00, SDSC_MAX_VERSION_LEN * sizeof(char));
    unsigned long ulVersionLen = SDSC_MAX_VERSION_LEN * sizeof(char);
    ulResult = SDSCGetSDKVersion(pVersion, &ulVersionLen);
    LOGI("get_sdk_ver pszVersion: %s\n", pVersion);
    LOGI("get_sdk_ver baseResult: %ld", ulResult);

    if (Version == NULL) {
        LOGE("GetVersion Version with null.");
        return -1;
    }

    memcpy(Version, LIBS_VERSION, VERSION_NAME_LEN);
    LOGI("GetVersion name: %s\n", Version);

    return 0;
}

int ListDevice(unsigned char *DevList, unsigned long * DevListLen) {
    unsigned long ulResult;
    unsigned long ulDriveNum;

    if(DevList == NULL) {
        LOGE("DevList para is null.");
        return -1;
    }

    if(DevListLen == NULL) {
        LOGE("DevListLen para is null.");
        return -1;
    }

    if(*DevListLen < (SDSC_MAX_DEV_NUM * SDSC_MAX_DEV_NAME_LEN)) {
        LOGE("*DevListLen para is less than 256.");
        return -1;
    }

    ulDriveNum = 0;
    ulResult = SDSCListDevs(DevList, DevListLen, &ulDriveNum);

    LOGI("RefreshDev result: %ld", ulResult);
    LOGI("RefreshDev pulDriveNum: %ld", ulDriveNum);

    if (ulDriveNum && !ulResult) {
        LOGD("Get %d device, List as: %s", ulDriveNum, DevList);
    } else {
        LOGD("No available device");
    }

    return ulDriveNum;
}

int OpenDevice(char *pDeviceName, int *Result) {
    int ret = 0;
    unsigned long get_size_ret = 0;
    unsigned long connect_ret = 0;
    unsigned long ulHASize;
    unsigned long ulPageSize;

    if (trans_dev_id != -1) {
        ret = -1;
        LOGE("Transimit device is already opened.");
        goto Finished;
    }

    strcpy(device_path, pDeviceName);
    connect_ret = SDSCConnectDev(pDeviceName, &trans_dev_id);
    LOGD("ConnectDev result %d, handler %d.", connect_ret, trans_dev_id);

    *Result = trans_dev_id;

    //get device size
    get_size_ret = SDHAGetHASize(trans_dev_id, &ulHASize, &ulPageSize);
    device_total_size = ulHASize;
    if (!get_size_ret) {
        LOGI("Device Total Size: Page size:%d, HA size:%d",ulPageSize, ulHASize);
    } else {
        LOGE("Get Device Total Size failed return %d.", get_size_ret);
    }

Finished:
    return ret;
}

int CloseDevice(int DeviceHandler) {
    int ret = 0;
    unsigned long disconnect_ret = 0;

    if ((trans_dev_id == -1) || (DeviceHandler != trans_dev_id)) {
        ret = -1;
        LOGE("Transimit device handler is incorret.");
        goto Finished;
    }

    disconnect_ret = SDSCDisconnectDev(trans_dev_id);
    LOGD("ConnectDev result %d, handler %d.", disconnect_ret, trans_dev_id);

    trans_dev_id = -1;
    memset(device_path, 0, sizeof(device_path));

Finished:
    return ret;
}

int ConvertToSectorIndex(int64_t KeyOffset, int KeyLen, int64_t * SectorIndexSt, int64_t * SectorIndexEd, int * OffsetBegin, int * OffsetEnd){
    int tmp = 0;

    if (KeyOffset < 0) {
        LOGE("ConvertToSectorIndex KeyOffset is smaller than 0.");
        return -1;
    }
    if (KeyLen < 1) {
        LOGE("ConvertToSectorIndex KeyLen is smaller than 1.");
        return -1;
    }
    if((SectorIndexSt == NULL) || (SectorIndexEd == NULL) || (OffsetBegin == NULL) || (OffsetEnd == NULL)){
        LOGE("Para is incorrect..");
        return -1;
    }

    //begint to convert.
    *SectorIndexSt = KeyOffset / DATA_TRANSMIT_BLOCK_SIZE;
    *SectorIndexEd = (KeyOffset + KeyLen - 1) / DATA_TRANSMIT_BLOCK_SIZE;

    *OffsetBegin = (int)(KeyOffset % DATA_TRANSMIT_BLOCK_SIZE);
    *OffsetEnd = (int)((KeyOffset + KeyLen - 1) % DATA_TRANSMIT_BLOCK_SIZE);

    return 0;
}

int ReadKey(int fd, unsigned char* KeyData, int64_t KeyOffset, int KeyLen) {
    unsigned long ulResult = 0;

    unsigned char * ucTempBuf = NULL;

    unsigned long ulTempLen = 0;
    int64_t index = 0;
    int ret = 0;
    int64_t SectorIndexSt = 1;
    int64_t SectorIndexEd = 1;
    int OffsetBegin = 0;
    int OffsetEnd = 0;

    if (KeyData == NULL) {
        LOGE("ReadKey KeyData is null.");
        return -1;
    }
    if (KeyOffset < 0) {
        LOGE("ReadKey KeyOffset is smaller than 0.");
        return -1;
    }
    if (KeyLen < 1) {
        LOGE("ReadKey KeyLen is smaller than 1.");
        return -1;
    }

    ucTempBuf = memalign(512, DATA_TRANSMIT_BLOCK_SIZE);
    memset(ucTempBuf, 0, DATA_TRANSMIT_BLOCK_SIZE);

     ret = ConvertToSectorIndex(KeyOffset, KeyLen, &SectorIndexSt, &SectorIndexEd, &OffsetBegin, &OffsetEnd);
    if(ret < 0){
        LOGE("Sorry, it seems that Offset convert failed.");
        ret = -1;
        goto Finished;
    }

    unsigned char * pucDstPointer = KeyData;
    unsigned char * pucSrcPointer = NULL;
    unsigned long ulCurStepLen = 0;

    for(index=SectorIndexSt; index<=SectorIndexEd; index++){
        memset(ucTempBuf, 0, DATA_TRANSMIT_BLOCK_SIZE);
        ulTempLen = DATA_TRANSMIT_BLOCK_SIZE;
        ulResult = SDHAReadData(fd, index, DATA_TRANSMIT_BLOCK_SIZE, ucTempBuf, &ulTempLen);
        if(ulResult){
            LOGE("SDHAReadData ulResult is not correct, 0x%x", ulResult);
            //break; //del by jason, just for the case when sector isn't format, that will return 0x0f000005, and just return 0(no need to care the data read)
        }

        if(DATA_TRANSMIT_BLOCK_SIZE != ulTempLen){
            LOGE("SDHAReadData ulLen != DATA_BLOCK_MAX_SIZE, %d", ulTempLen);
            break;
        }

        if(SectorIndexSt == SectorIndexEd){
            //Init the value of ulCurStepLen for this time
            ulCurStepLen = OffsetEnd - OffsetBegin + 1;

            //Init the value of destination of the source data for this time
            pucSrcPointer = ucTempBuf + OffsetBegin;
        }else{
            //Init the value of ulCurStepLen for this time
            if(index == SectorIndexSt){ //at the beginning of the copy data
                ulCurStepLen = (DATA_TRANSMIT_BLOCK_SIZE - OffsetBegin);  //ready to move how much bytes to the flash actually at this time

                //Init the value of destination of the source data for this time
                pucSrcPointer = ucTempBuf + (DATA_TRANSMIT_BLOCK_SIZE - ulCurStepLen);
            }else if(index == SectorIndexEd){  // at the end of the copy data
                ulCurStepLen = OffsetEnd + 1;

                //Init the value of destination of the source data for this time
                pucSrcPointer = ucTempBuf;
            }else{ // in the middle of the copy data
                ulCurStepLen = DATA_TRANSMIT_BLOCK_SIZE;

                //Init the value of destination of the source data for this time
                pucSrcPointer = ucTempBuf;
            }
            //Init the value of destination of the source data for this time
            //pucSrcPointer = ucTempBuf + (DATA_TRANSMIT_BLOCK_SIZE - ulCurStepLen);
        }

        //Just do it
        memcpy(pucDstPointer, pucSrcPointer, ulCurStepLen);

        //Prepare the source data location for the next time
        pucDstPointer = pucDstPointer + ulCurStepLen;
    }

Finished:
    //free these staff.
    free(ucTempBuf);

    return ret;
}

int WriteKey(int fd, unsigned char* KeyData, int64_t KeyOffset, int KeyLen) {
    unsigned long ulResult = 0;

    unsigned char * ucTempBuf = NULL;
    unsigned long ulTempLen = 0;

    int64_t index = 0;
    int ret = 0;
    int64_t SectorIndexSt = 1;
    int64_t SectorIndexEd = 1;
    int OffsetBegin = 0;
    int OffsetEnd = 0;

    unsigned char * pucSrcPointer = KeyData;
    unsigned char * pucDstPointer = NULL;
    unsigned long ulCurStepLen = 0;

    if (KeyData == NULL) {
        LOGE("WriteKey KeyData is null.");
        return -1;
    }
    if (KeyOffset < 0) {
        LOGE("WriteKey KeyOffset is smaller than 0.");
        return -1;
    }
    if (KeyLen < 1) {
        LOGE("WriteKey KeyLen is smaller than 1.");
        return -1;
    }

    ucTempBuf = memalign(512, DATA_TRANSMIT_BLOCK_SIZE);
    memset(ucTempBuf, 0, DATA_TRANSMIT_BLOCK_SIZE);

    ret = ConvertToSectorIndex(KeyOffset, KeyLen, &SectorIndexSt, &SectorIndexEd, &OffsetBegin, &OffsetEnd);
    if(ret < 0){
        LOGE("Sorry, it seems that Offset convert failed.");
        ret = -1;
        goto Finished;
    }

    for(index=SectorIndexSt; index<=SectorIndexEd; index++){
        memset(ucTempBuf, 0, DATA_TRANSMIT_BLOCK_SIZE);
        ulTempLen = DATA_TRANSMIT_BLOCK_SIZE;
        ulResult = SDHAReadData(fd, index, DATA_TRANSMIT_BLOCK_SIZE, ucTempBuf, &ulTempLen);
        if(ulResult){
            LOGE("SDHAReadData ulResult is not correct, 0x%x", ulResult);
            //break; //del by jason, just for the case when sector isn't format, that will return 0x0f000005, and just return 0(no need to care the data read)
        }

        if(DATA_TRANSMIT_BLOCK_SIZE != ulTempLen){
            LOGE("SDHAReadData ulLen != DATA_BLOCK_MAX_SIZE, %d", ulTempLen);
            break;
        }

        if(SectorIndexSt == SectorIndexEd){
            //Init the value of ulCurStepLen for this time
            ulCurStepLen = OffsetEnd - OffsetBegin + 1;

            //Init the value of destination of the source data for this time
            pucDstPointer = ucTempBuf + OffsetBegin;
        }else {
            //Init the value of ulCurStepLen for this time
            if (index == SectorIndexSt) { //at the beginning of the copy data
                ulCurStepLen = (DATA_TRANSMIT_BLOCK_SIZE - OffsetBegin);  //ready to move how much bytes to the flash actually at this time
            } else if (index == SectorIndexEd) {  // at the end of the copy data
                ulCurStepLen = OffsetEnd + 1;
            } else { // in the middle of the copy data
                ulCurStepLen = DATA_TRANSMIT_BLOCK_SIZE;
            }

            //Init the value of destination of the source data for this time
            pucDstPointer = ucTempBuf + (DATA_TRANSMIT_BLOCK_SIZE - ulCurStepLen);
        }

        //Just do it
        memcpy(pucDstPointer, pucSrcPointer, ulCurStepLen);

        ulResult = SDHAWriteData(fd, index, ucTempBuf, DATA_TRANSMIT_BLOCK_SIZE);
        if(ulResult){
            LOGE("SDHAWriteData ulResult is not correct, 0x%x", ulResult);
            break;
        }

        //Prepare the source data location for the next time
        pucSrcPointer = pucSrcPointer + ulCurStepLen;
    }

Finished:
    //free these staff.
    free(ucTempBuf);
    return ret;
}

int ClearKey(int fd, int64_t KeyOffset, int KeyLen) {
    unsigned long ulResult = 0;

    unsigned char * ucTempBuf = NULL;
    unsigned long ulTempLen = 0;

    int64_t index = 0;
    int ret = 0;
    int64_t SectorIndexSt = 1;
    int64_t SectorIndexEd = 1;
    int OffsetBegin = 0;
    int OffsetEnd = 0;

    unsigned char * pucDstPointer = NULL;
    unsigned long ulCurStepLen = 0;

    if (KeyOffset < 0) {
        LOGE("WriteKey KeyOffset is smaller than 0.");
        return -1;
    }
    if (KeyLen < 1) {
        LOGE("WriteKey KeyLen is smaller than 1.");
        return -1;
    }

    ucTempBuf = memalign(512, DATA_TRANSMIT_BLOCK_SIZE);
    memset(ucTempBuf, 0, DATA_TRANSMIT_BLOCK_SIZE);

    ret = ConvertToSectorIndex(KeyOffset, KeyLen, &SectorIndexSt, &SectorIndexEd, &OffsetBegin, &OffsetEnd);
    if(ret < 0){
        LOGE("Sorry, it seems that Offset convert failed.");
        ret = -1;
        goto Finished;
    }

    for(index=SectorIndexSt; index<=SectorIndexEd; index++){
        memset(ucTempBuf, 0, DATA_TRANSMIT_BLOCK_SIZE);
        ulTempLen = DATA_TRANSMIT_BLOCK_SIZE;

        ulResult = SDHAReadData(fd, index, DATA_TRANSMIT_BLOCK_SIZE, ucTempBuf, &ulTempLen);
        if(ulResult){
            LOGE("SDHAReadData ulResult is not correct, 0x%x", ulResult);
            break;
        }

        if(DATA_TRANSMIT_BLOCK_SIZE != ulTempLen){
            LOGE("SDHAReadData ulLen != DATA_BLOCK_MAX_SIZE, %d", ulTempLen);
            break;
        }

        if(SectorIndexSt == SectorIndexEd){
            //Init the value of ulCurStepLen for this time
            ulCurStepLen = OffsetEnd - OffsetBegin + 1;

            //Init the value of destination of the source data for this time
            pucDstPointer = ucTempBuf + OffsetBegin;
        }else {
            //Init the value of ulCurStepLen for this time
            if (index == SectorIndexSt) { //at the beginning of the copy data
                ulCurStepLen = (DATA_TRANSMIT_BLOCK_SIZE - OffsetBegin);  //ready to move how much bytes to the flash actually at this time
            } else if (index == SectorIndexEd) {  // at the end of the copy data
                ulCurStepLen = OffsetEnd + 1;
            } else { // in the middle of the copy data
                ulCurStepLen = DATA_TRANSMIT_BLOCK_SIZE;
            }

            //Init the value of destination of the source data for this time
            pucDstPointer = ucTempBuf + (DATA_TRANSMIT_BLOCK_SIZE - ulCurStepLen);
        }

        //Just do it
        memset(pucDstPointer, 0, ulCurStepLen);

        ulResult = SDHAWriteData(fd, index, ucTempBuf, DATA_TRANSMIT_BLOCK_SIZE);
        if(ulResult){
            LOGE("SDHAWriteData ulResult is not correct, 0x%x", ulResult);
            break;
        }
    }

Finished:
    //free these staff.
    free(ucTempBuf);

    return ret;
}

int TransmitData_CheckResponse(unsigned char * BufferInput, unsigned char * BufferOutput, unsigned long CheckLen) {
    int ret = 0;
    int i = 0;
    unsigned char * tmp_src;
    unsigned char * tmp_dst;
    unsigned char dst_byte;


    if(!BufferInput || !BufferOutput || !CheckLen){
        return -1;
    }

    tmp_src = BufferInput;
    tmp_dst = BufferOutput;
#if 0  //branch, the response is convert result of the input data.
    for(i=0;i<CheckLen;i++){
        //dst_byte = *tmp_dst;
        //dst_byte = ~dst_byte;
        if((*tmp_src) != (~(*tmp_dst))){
            ret = -2;
        }
        tmp_src ++;
        tmp_dst ++;
    }
#else  //branch, the response is the same with the input data.
    ret = memcmp(tmp_src, tmp_dst, CheckLen);
#endif

    return ret;
}

int TransmitData_WriteThroughTest(int hDevice) {
    unsigned long send_len = 0;
    unsigned char check_sum = 0;

    int ret;
    unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);
    send_len = 1000;

    unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);
    unsigned long recv_len;
    memset(tmpBuffer_rd, 0, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);

    //make sure the first byte is 0xAA, the left ones are random data.
    *tmpBuffer_wr = 0xAA;

    //fill the checksum byte
    check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

    //fill the data ...........................................
    *(tmpBuffer_wr+send_len) = check_sum;
    send_len = send_len + 1;

    int repeat_times = 100;
    for (int i = 0; i < repeat_times; i++) {
        if (repeat_times > 1)
            usleep(500 * 1000);  //gap between each cycle

        memset(tmpBuffer_rd, 0, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);
        recv_len = DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE;
        ret = TransmitData(hDevice, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
        if (ret < 0) {
            LOGE("TransmitData return failed, ret %d.", ret);
            ret = -1;
        }

        //check the response
        ret = TransmitData_CheckResponse(tmpBuffer_wr, tmpBuffer_rd, recv_len);
        if(ret){
            LOGE("Response error, test failed, stop test at loop %d.", i);
            break;
        }
    }

    free(tmpBuffer_wr);
    free(tmpBuffer_rd);

    return ret;
}

//test code, case: test write data to be encrypted
int TransmitData_EncryptTest(int hDevice) {
    //unsigned char DataTobeEncrypted[] = {0xAA, 0x80, 0x92, 0x00, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}; //"AA80920000081122334455667788FF";
    unsigned char DataTobeEncrypted[] = {0x00, 0x01, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}; //"AA80920000081122334455667788FF";
    unsigned long send_len = 0;
    unsigned char check_sum = 0;

    int ret;
    unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);
    memset(tmpBuffer_wr, 0, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);
    send_len = sizeof(DataTobeEncrypted);

    unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);
    unsigned long recv_len;
    memset(tmpBuffer_rd, 0, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);

    //copy the raw data
    memcpy(tmpBuffer_wr, (unsigned char *)DataTobeEncrypted, send_len);

    //fill the checksum byte
    check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

    //fill the data
    *(tmpBuffer_wr+send_len) = check_sum;
    send_len = send_len + 1;

    int repeat_times = 1;
    for (int i = 0; i < repeat_times; i++) {
        if (repeat_times > 1)
            usleep(500 * 1000);  //gap between each cycle

        memset(tmpBuffer_rd, 0, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);
        recv_len = DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE;
        ret = TransmitData(hDevice, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
        if (ret < 0) {
            LOGE("TransmitData return failed, ret %d.", ret);
            ret = -1;
        }
    }

    free(tmpBuffer_wr);
    free(tmpBuffer_rd);

    return ret;
}

int
TransmitData(int hDevice, unsigned char *pSendData, unsigned long SendLen, unsigned char *pRecvData,
             unsigned long *pRecvLen) {
    int ret = 0;
    unsigned long ulLockOpRet = 0;
    unsigned long ulResult = 0;

    if (pSendData == NULL) {
        LOGE("TransmitData SendData is null.");
        return -1;
    }
    if (SendLen < 1) {
        LOGE("TransmitData SendLen is smaller than 1.");
        return -1;
    }
    if (pRecvData == NULL) {
        LOGE("TransmitData RecvData is null.");
        return -1;
    }
    if (pRecvLen == NULL) {
        LOGE("TransmitData RecvLen is null.");
        return -1;
    }
    if (*pRecvLen == 0) {
        LOGE("TransmitData RecvLen can not be zero, input para is incorrect.");
        return -1;
    }

    //begin op, lock on
    ulLockOpRet = SDSCBeginTransaction(hDevice);
    LOGD("Lock device (handler %d) result %d.", hDevice, ulLockOpRet);

    LOGD(">>>%d.", g_ulDebugLoopIndex);
    ulResult = SDSCTransmitEx(hDevice, (pSendData+2), (SendLen-2), SDSC_DEV_DEFAULT_TIME_OUT, pRecvData, pRecvLen);

    //end op, lock off
    ulLockOpRet = SDSCEndTransaction(hDevice);
    LOGD("UnLock device (handler %d) result %d.", hDevice, ulLockOpRet);

    if(ulResult){
        LOGE("SDSCTransmit return ulResult is incorrect, 0x%x.", ulResult);
        ret = -1;
        goto Finished;
    }
    LOGD("<<<.%d", g_ulDebugLoopIndex++);

    if (!(*pRecvLen)) {
        LOGE("SDSCTransmit return receive data length is incorrect, %d.", *pRecvLen);
        ret = -1;
        goto Finished;
    }

Finished:
    return ret;
}

#ifdef __cplusplus
}
#endif  /*__cplusplus*/
