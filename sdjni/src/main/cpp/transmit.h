//
// Created by 00498 on 2019/12/16.
//

#ifndef SDJNIENCRYPT28_TRANSMIT_H
#define SDJNIENCRYPT28_TRANSMIT_H

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
