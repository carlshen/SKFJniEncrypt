//
// Created by 00498 on 2019/12/16.
//

#ifndef SDJNIENCRYPT28_TRANSMIT_H
#define SDJNIENCRYPT28_TRANSMIT_H

#define LIBS_VERSION ("00020000")
#define VERSION_NAME_LEN (9)

#define DATA_TRANSMIT_LENGTH_PER_TIME_MAX_SIZE (1024)
#define DATA_TRANSMIT_BUFFER_MAX_SIZE (512)
#define DATA_TRANSMIT_BLOCK_SIZE (480)

unsigned char device_path[256];
int trans_dev_id;

unsigned char CalculateCheckSum(unsigned char * ucData, unsigned long ulByteNum);
int GetVersion(char* Version);
int OpenDevice(char* pDeviceName, int* Result);
int CloseDevice(int DeviceHandler);
int TransmitData(int hDevice, unsigned char* pSendData, unsigned long SendLen, unsigned char* pRecvData, unsigned long* pRecvLen);
int ListDevice(unsigned char *DevList, unsigned long * DevListLen);

int WriteKey(int fd, unsigned char* KeyData, int64_t KeyOffset, int KeyLen);
int ReadKey(int fd, unsigned char* KeyData, int64_t KeyOffset, int KeyLen);
int ClearKey(int fd, int64_t KeyOffset, int KeyLen);

int TransmitDataToSE(int hDevice, unsigned char* pSendData, unsigned long SendLen, unsigned char* pRecvData, unsigned long* pRecvLen);
int TransmitData_WriteThroughTest(int hDevice);
int TransmitData_EncryptTest(int hDevice);
int TransmitData_WriteKeyTest(int hDevice);
int TransmitData_ClearKeyTest(int hDevice);
int TransmitData_CheckResponse(unsigned char * BufferInput, unsigned char * BufferOutput, unsigned long CheckLen);

#endif //SDJNIENCRYPT28_TRANSMIT_H
