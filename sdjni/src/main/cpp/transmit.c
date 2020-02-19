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

#define LIBS_VERSION ("00010000")
#define VERSION_NAME_LEN (9)


#define DATA_TRANSMIT_SECTION_LEN_SIZE (2)
#define DATA_TRANSMIT_SECTION_TYPE_SIZE (1)
#define DATA_TRANSMIT_SECTION_LRC_SIZE (1)

#define DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE (1024)
#define DATA_TRANSMIT_BUFFER_MAX_SIZE (512)
#define DATA_TRANSMIT_BLOCK_SIZE (480)
#define DATA_TRANSMIT_DATA_MAX_SIZE (DATA_TRANSMIT_BLOCK_SIZE - \
                                        DATA_TRANSMIT_SECTION_TYPE_SIZE - DATA_TRANSMIT_SECTION_LRC_SIZE)

typedef enum Transmit_Data_Type{
    DATA_TYPE_TOSIM = 0xAA,
    DATA_TYPE_TOSE = 0x55,
}TransmitDataType;

typedef enum To_Se_SubCmd{
    CMD_READ_KEY,
    CMD_WRITE_KEY,
    CMD_CLEAR_KEY,
    CMD_INVALID_CMD,
}enToSeSubCmd;

typedef struct Data_Transmit_Format{
    unsigned char DataType;
    unsigned char Data[DATA_TRANSMIT_DATA_MAX_SIZE];
    unsigned char LRC;
}stDataTransmitFormat;

typedef struct Data_Receive_Format{
    unsigned char DataType;
    unsigned char Data[DATA_TRANSMIT_DATA_MAX_SIZE];
    unsigned char LRC;
}stDataReceiveFormat;

typedef union Data_Raw{
    stDataTransmitFormat ft_snd;
    stDataReceiveFormat ft_rcv;
    unsigned char MsgRawData[DATA_TRANSMIT_BLOCK_SIZE];
}unDataRaw;

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
    if (Version == NULL) {
        LOGE("GetVersion Version with null.");
        return -1;
    }

    memcpy(Version, LIBS_VERSION, VERSION_NAME_LEN);
    LOGI("GetVersion name: %s\n", Version);
    return 0;
}

int ConvertToSectorIndex(int KeyOffset, int KeyLen, int * SectorIndexSt, int * SectorIndexEd, int * OffsetBegin, int * OffsetEnd){
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
    *SectorIndexSt = KeyOffset / DATA_TRANSMIT_BLOCK_SIZE + 1;
    *SectorIndexEd = (KeyOffset + KeyLen - 1) / DATA_TRANSMIT_BLOCK_SIZE + 1;

    *OffsetBegin = KeyOffset % DATA_TRANSMIT_BLOCK_SIZE;
    *OffsetEnd = (KeyOffset + KeyLen - 1) % DATA_TRANSMIT_BLOCK_SIZE;

    return 0;
}

int ReadKey(int fd, unsigned char* KeyData, int KeyOffset, int KeyLen) {
    unsigned long ulResult = 0;

    unsigned char * ucTempBuf = NULL;

    unsigned long ulTempLen = 0;
    unsigned long index = 0;
    int ret = 0;
    int SectorIndexSt = 1;
    int SectorIndexEd = 1;
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

int WriteKey(int fd, unsigned char* KeyData, int KeyOffset, int KeyLen) {
    unsigned long ulResult = 0;

    unsigned char * ucTempBuf = NULL;
    unsigned long ulTempLen = 0;

    int index = 0;
    int ret = 0;
    int SectorIndexSt = 1;
    int SectorIndexEd = 1;
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

int ClearKey(int fd, int KeyOffset, int KeyLen) {
    unsigned long ulResult = 0;

    unsigned char * ucTempBuf = NULL;
    unsigned long ulTempLen = 0;

    int index = 0;
    int ret = 0;
    int SectorIndexSt = 1;
    int SectorIndexEd = 1;
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

//test code, case: test write key data
int TransmitData_WriteKeyTest(int hDevice) {
    unsigned char DataTobeSend[] = {0xAA,0x80,0x90,0x00,0x00,0x1D,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}; //"AA809000001D00000000000000000000001000112233445566778899AABBCCDDEEFFFF";
    int send_len;
    unsigned char check_sum = 0;

    int ret;
    unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    send_len = sizeof(DataTobeSend);

    unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    unsigned long recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
    memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);

    //data prepare
    memcpy(tmpBuffer_wr, DataTobeSend, send_len);

    //fill the checksum byte
    check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

    //fill the data ...........................................
    *(tmpBuffer_wr+send_len) = check_sum;
    send_len = send_len + 1;

    ret = TransmitData(hDevice, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
    if (ret < 0) {
        LOGE("TransmitData return failed, ret %d.", ret);
        ret = -1;
    }

    free(tmpBuffer_wr);
    free(tmpBuffer_rd);

    return ret;
}

//test code, case: test clear key data
int TransmitData_ClearKeyTest(int hDevice) {
    unsigned char DataTobeSend[] = {0xAA,0x80,0x94,0x00,0x00,0x0C,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08}; //"AA809400000C000000000000000000000008FF";
    int send_len;
    unsigned char check_sum = 0;

    int ret;
    unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    send_len = sizeof(DataTobeSend);

    unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    unsigned long recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
    memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);

    //data prepare
    memcpy(tmpBuffer_wr, DataTobeSend, send_len);

    //fill the checksum byte
    check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

    //fill the data ...........................................
    *(tmpBuffer_wr+send_len) = check_sum;
    send_len = send_len + 1;

    ret = TransmitData(hDevice, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
    if (ret < 0) {
        LOGE("TransmitData return failed, ret %d.", ret);
        ret = -1;
    }

    free(tmpBuffer_wr);
    free(tmpBuffer_rd);

    return ret;
}

//test code, case: test write data to be encrypted
int TransmitData_EncryptTest(int hDevice) {
    unsigned char DataTobeEncrypted[] = {0xAA, 0x80, 0x92, 0x00, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}; //"AA80920000081122334455667788FF";
    unsigned long send_len = 0;
    unsigned char check_sum = 0;

    int ret;
    unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    send_len = sizeof(DataTobeEncrypted);

    unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    unsigned long recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
    memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);

    //copy the raw data
    memcpy(tmpBuffer_wr, (unsigned char *)DataTobeEncrypted, send_len);

    //fill the checksum byte
    check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

    //fill the data ...........................................
    *(tmpBuffer_wr+send_len) = check_sum;
    send_len = send_len + 1;

    int repeat_times = 100;
    for (int i = 0; i < repeat_times; i++) {
        if (repeat_times > 1)
            usleep(500 * 1000);  //gap between each cycle

        memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
        recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
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

enToSeSubCmd ToSeGetSubCmdType(unsigned char *ParaData){
    enToSeSubCmd ret = CMD_INVALID_CMD;
    const unsigned char ucReadKey[] = {0x80,0x12,0x00,0x00};
    const unsigned char ucWriteKey[] = {0x80,0xDB,0x00,0x00};
    const unsigned char ucClearKey[] = {0x80,0xDA,0x00,0x00};

    if(!strcmp(ParaData,ucReadKey)){
        ret = CMD_READ_KEY;
    }else if(!strcmp(ParaData,ucWriteKey)){
        ret = CMD_WRITE_KEY;
    }else if(!strcmp(ParaData,ucClearKey)){
        ret = CMD_CLEAR_KEY;
    }
    return ret;
}

unsigned long long GetOffSetValue(unsigned char * pPara){
    unsigned long long result = 0;
    unsigned int temp = 0;
    temp = big_bytesToInt(pPara, 4);
    result = temp;
    result = result << 32 + big_bytesToInt((unsigned char*)(pPara+4), 4);
    return result;
}

unsigned int GetLengthValue(unsigned char * pPara){
    unsigned int result = 0;
    result = big_bytesToInt((unsigned char*)(pPara), 4);
    return result;
}

int
TransmitData(int hDevice, unsigned char *pSendData, unsigned long SendLen, unsigned char *pRecvData,
             unsigned long *pRecvLen) {
    int ret = 0;
    unsigned long ulResult = 0;
    unsigned long ulCosState = 0;

    unsigned char ucCheckSumValue = 0;
    unsigned char ucTargetCheckSum = 0;

    unsigned char * pData_r_type = pRecvData;
    unsigned char pkt_r_type;

    unsigned char * ToWriteKeyFile = NULL;
    unsigned char * ToSeSendData = NULL;
    unsigned char * FromSeRecvData = NULL;

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

    ToWriteKeyFile = memalign(512, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);
    ToSeSendData = memalign(512, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);
    FromSeRecvData =memalign(512, DATA_TRANSMIT_BLOCK_SIZE);

    memset(ToWriteKeyFile, 0, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);
    memset(ToSeSendData, 0, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);
    memset(FromSeRecvData, 0, DATA_TRANSMIT_BLOCK_SIZE);

    ulResult = SDSCTransmit(hDevice, pSendData, SendLen, SDSC_DEV_DEFAULT_TIME_OUT, pRecvData, pRecvLen, &ulCosState);
    if(ulResult){
        LOGE("SDSCTransmit return ulResult is incorrect, 0x%x.", ulResult);
        ret = -1;
        goto Finished;
    }

    if (!(*pRecvLen)) {
        LOGE("SDSCTransmit return receive data length is incorrect, %d.", *pRecvLen);
        ret = -1;
        goto Finished;
    }else {
        //get the packet type
        pkt_r_type = *pData_r_type;
    }

    //append the received data with cos_state.
    unsigned short content_tofill;
    big_intToByte((unsigned short)ulCosState, 2, &content_tofill);

    *((unsigned short *)(pRecvData + *pRecvLen)) = content_tofill;
    *pRecvLen += 2;

    ucCheckSumValue = (unsigned char)ulCosState;
    ucTargetCheckSum = CalculateCheckSum((pRecvData+1), (*pRecvLen-2));
    if(ucCheckSumValue != ucTargetCheckSum){
        LOGE("Check sum value is incorrect.");
        ret = -1;
        goto Finished;
    }

    if (*pRecvLen) {
        if (pkt_r_type == DATA_TYPE_TOSIM) {//if the responding packet type is 0xaa
            //Nothing left to do, just return to caller.

            //Nothing left to do, just return to caller.
        } else if (pkt_r_type == DATA_TYPE_TOSE) {//if the responding packet type is 0x55
            unsigned char * pSubCmd = pRecvData + 1;
            unsigned char * pSubCmdParaLen = pRecvData + 1 + 4;
            unsigned char * pSubCmdParaValueOffset = pRecvData + 1 + 4 + 1;
            unsigned char * pSubCmdParaValueLen = pRecvData + 1 + 4 + 1 + 8;
            enToSeSubCmd subcmd_type = ToSeGetSubCmdType(pSubCmd);

            unsigned char subcmd_para_len = *pSubCmdParaLen;  //this value is fiexed as 0x0C

            unsigned long tose_send_len = 0;
            unsigned long tose_recv_len = 0;
            int tose_ret = 0;

            unsigned long long data_offset = 0;
            unsigned int data_length = 0;

            unsigned char * pTypeDataBuffer = ToSeSendData;
            unsigned char * pValueDataBuffer = ToSeSendData + 1;
            unsigned char check_sum_val = 0;

            switch(subcmd_type){
                case CMD_READ_KEY:
                    data_offset = GetOffSetValue(pSubCmdParaValueOffset);
                    data_length = GetLengthValue(pSubCmdParaValueLen);

                    //temp add for test random data_offset & data_length
                    {
                        data_offset = 480+470;
                        data_length = 10 + 480+ 22;
                    }
                    //fill the buffer with the keyfile , and to be sent to simse
                    ret = ReadKey(hDevice, pValueDataBuffer, data_offset, data_length);
                    if(ret){
                        LOGE("Error returned, ulResult 0x%x.", ret);

                        //construct the responding packet.  556504XX
                        *pTypeDataBuffer = DATA_TYPE_TOSE;
                        *((unsigned short *)pValueDataBuffer) = 0x0465;

                        //lastly append with checksum value
                        check_sum_val = CalculateCheckSum(pValueDataBuffer, data_length);
                        *((unsigned char *)(pValueDataBuffer + 2)) = check_sum_val;

                        tose_send_len = 4;
                    }else{
                        //fill the type segment
                        *pTypeDataBuffer = DATA_TYPE_TOSE;
                        check_sum_val = CalculateCheckSum(pValueDataBuffer, data_length);

                        //lastly append with checksum value
                        *(pValueDataBuffer + data_length) = check_sum_val;
                        tose_send_len = 1 + data_length +  1;
                    }
                    break;
                case CMD_WRITE_KEY:
                    data_offset = GetOffSetValue(pSubCmdParaValueOffset);
                    data_length = GetLengthValue(pSubCmdParaValueLen);

                    ret = WriteKey(hDevice, (pRecvData+1+5+8+4), data_offset, data_length);
                    if(ret){
                        LOGE("error returned, ulResult 0x%x.", ret);

                        //construct the responding packet.  556504XX
                        *pTypeDataBuffer = DATA_TYPE_TOSE;
                        *((unsigned short *)pValueDataBuffer) = 0x0465;

                        //lastly append with checksum value
                        check_sum_val = CalculateCheckSum(pValueDataBuffer, data_length);
                        *((unsigned char *)(pValueDataBuffer + 2)) = check_sum_val;

                        tose_send_len = 4;
                    }else{
                        //just for test, write key successfully
                        {
                            unsigned char tempBuffer[512];
                            ReadKey(hDevice, tempBuffer, data_offset, data_length);
                            LOGI("ok, just for wait for a min.");
                        }

                        //construct the responding packet.  559000XX
                        *pTypeDataBuffer = DATA_TYPE_TOSE;
                        *((unsigned short *)pValueDataBuffer) = 0x0090;

                        //lastly append with checksum value
                        check_sum_val = CalculateCheckSum(pValueDataBuffer, data_length);
                        *((unsigned char *)(pValueDataBuffer + 2)) = check_sum_val;

                        tose_send_len = 4;
                    }
                    break;
                case CMD_CLEAR_KEY:
                    data_offset = GetOffSetValue(pSubCmdParaValueOffset);
                    data_length = GetLengthValue(pSubCmdParaValueLen);

                    // memset(ToWriteKeyFile, 0, DATA_TRANSMIT_BLOCK_SIZE);  //NO USE ANYMORE
                    ret = ClearKey(hDevice, data_offset, data_length);
                    if(ret){
                        LOGE("error returned, ulResult 0x%x.", ret);

                        //construct the responding packet.  556504XX
                        *pTypeDataBuffer = DATA_TYPE_TOSE;
                        *((unsigned short *)pValueDataBuffer) = 0x0465;

                        //lastly append with checksum value
                        check_sum_val = CalculateCheckSum(pValueDataBuffer, data_length);
                        *((unsigned char *)(pValueDataBuffer + 2)) = check_sum_val;

                        tose_send_len = 4;
                    }else{
                        //just for test, write key successfully
                        {
                            unsigned char tempBuffer[512];
                            ReadKey(hDevice, tempBuffer, data_offset, data_length);
                            LOGI("ok, just for wait for a min.");
                        }

                        //construct the responding packet.  559000XX
                        *pTypeDataBuffer = DATA_TYPE_TOSE;
                        *((unsigned short *)pValueDataBuffer) = 0x0090;

                        //lastly append with checksum value
                        check_sum_val = CalculateCheckSum(pValueDataBuffer, data_length);
                        *((unsigned char *)(pValueDataBuffer + 2)) = check_sum_val;

                        tose_send_len = 4;
                    }
                    break;
                default:
                    break;
            }

            tose_ret = TransmitDataToSE(hDevice, ToSeSendData, tose_send_len, FromSeRecvData, &tose_recv_len);
            if(tose_ret < 0){
                LOGE("TransmitDataToSE return error, tose_ret %d.", tose_ret);
            } else{
                memcpy(pRecvData, FromSeRecvData, tose_recv_len);
                *pRecvLen = tose_recv_len;
            }

        } else {
            LOGE("TransmitData receive packet type is incorrect : 0x%x", pkt_r_type);
        }
    }

Finished:
    //free these staff.
    free(ToWriteKeyFile);
    free(ToSeSendData);
    free(FromSeRecvData);

    return ret;
}

int TransmitDataToSE(int hDevice, unsigned char* pSendData, unsigned long SendLen, unsigned char* pRecvData, unsigned long* pRecvLen) {
    int ret = 0;
    unsigned long ulResult = 0;
    unsigned char ucCheckSumValue = 0;
    unsigned char ucTargetCheckSum = 0;

    unsigned long ulCosState;
    unsigned char * data_out;
    unsigned long data_recv_len;
    unsigned char * data_in;

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
        LOGE("TransmitData RecvLen is smaller than 1.");
        return -1;
    }

    data_out = memalign(512, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);
    data_recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
    data_in = memalign(512, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);

    memset(data_in, 0, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);
    memset(data_out, 0, DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE);
    memcpy(data_in, pSendData, SendLen);

    ulResult = SDSCTransmit(hDevice, data_in, SendLen, SDSC_DEV_DEFAULT_TIME_OUT, data_out, &data_recv_len, &ulCosState);
    if(ulResult){
        LOGE("SDSCTransmit return ulResult is incorrect, 0x%x.", ulResult);
        ret = -1;
        goto Finished;
    }

    if (!data_recv_len) {
        LOGE("SDSCTransmit return receive data length is incorrect, %d.", *pRecvLen);
        ret = -1;
        goto Finished;
    }

    //append the received data with cos_state.
    unsigned short content_tofill;
    big_intToByte((unsigned short)ulCosState, 2, &content_tofill);

    *((unsigned short *)(data_out + data_recv_len)) = content_tofill;
    data_recv_len += 2;

    ucCheckSumValue = (unsigned char)ulCosState;
    ucTargetCheckSum = CalculateCheckSum((data_out+1), (data_recv_len-2));
    if(ucCheckSumValue != ucTargetCheckSum){
        LOGE("Check sum value is incorrect.");
        ret = -1;
        goto Finished;
    }

    memcpy(pRecvData, data_out, data_recv_len);
    *pRecvLen = data_recv_len;

Finished:
    //free these staff.
    free(data_out);
    free(data_in);

    return ret;
}

#ifdef __cplusplus
}
#endif  /*__cplusplus*/
