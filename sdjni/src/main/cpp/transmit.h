//
// Created by 00498 on 2019/12/16.
//

#ifndef SDJNIENCRYPT28_TRANSMIT_H
#define SDJNIENCRYPT28_TRANSMIT_H

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

unsigned char CalculateCheckSum(unsigned char * ucData, unsigned long ulByteNum);
int GetVersion(char* Version);
int WriteKey(int fd, unsigned char* KeyData, int KeyOffset, int KeyLen);
int ReadKey(int fd, unsigned char* KeyData, int KeyOffset, int KeyLen);
int ClearKey(int fd, int KeyOffset, int KeyLen);

int TransmitData(int hDevice, unsigned char* pSendData, unsigned long SendLen, unsigned char* pRecvData, unsigned long* pRecvLen);
int TransmitDataToSE(int hDevice, unsigned char* pSendData, unsigned long SendLen, unsigned char* pRecvData, unsigned long* pRecvLen);
int TransmitData_EncryptTest(int hDevice);
int TransmitData_WriteKeyTest(int hDevice);
int TransmitData_ClearKeyTest(int hDevice);

#endif //SDJNIENCRYPT28_TRANSMIT_H
