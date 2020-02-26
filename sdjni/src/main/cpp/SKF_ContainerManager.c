// SKF_ContainerManager.cpp: implementation of the SKF_ContainerManager class.
//
//////////////////////////////////////////////////////////////////////

#include <string.h>
#include <zconf.h>
#include "SKF_TypeDef.h"
#include "Global_Def.h"
#include "Algorithms.h"
#include "transmit.h"
#include "SKF_ContainerManager.h"
#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif  /*__cplusplus*/

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_ImportCertificate
* �������ܣ���������֤��
* �����б�hContainer: [IN], ��Կ���
*           bSignFlag:  [IN], TRUE��ʾǩ��֤�飻FALSE��ʾ����֤��
*           pbCert:     [IN], ָ��֤�����ݻ�����
*           ulCertLen:  [IN], ֤�鳤��
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ:������
*/
ULONG SKF_ImportCertificate( HANDLE hDev, BOOL bSignFlag, BYTE* pbCert )
{
	CHAR* pszLog = "**********Start to execute SKF_ImportCertificate ********** \n";
	CHAR szLog[SIZE_BUFFER_1024];
	BYTE apdu[0x07];
	if( hDev < 0 ) {
		return SAR_INVALIDHANDLEERR;
	}
	if (pbCert == NULL) {
		LOGE("SKF_ImportCertificate param pbCert is null.");
		return -1;
	}

	WriteLogToFile( pszLog );
	sv_fEnd = FALSE;
	memset( apdu, 0x00, sizeof(apdu) );
	// set the certificate file
	memcpy( apdu, apdu_A5_00, 0x05 );
	if( !bSignFlag ) { //����֤��
		memcpy( apdu + 0x05, apdu_0002, 0x02 );
	} else {  //ǩ��֤��
		memcpy( apdu + 0x05, apdu_0001, 0x02 );
	}

	unsigned long send_len = strlen(apdu);
	unsigned char check_sum = 0;
	int ret;
	unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    //copy the raw data
    memcpy(tmpBuffer_wr, (unsigned char *)apdu, send_len);

    unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
	unsigned long recv_len = 0;

	//fill the checksum byte
	check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

	//fill the data ...........................................
	*(tmpBuffer_wr+send_len) = check_sum;
	send_len = send_len + 1;

	int repeat_times = 10;
	for (int i = 0; i < repeat_times; i++) {
		if (repeat_times > 1)
			usleep(500 * 1000);  //gap between each cycle

		memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
        recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
		ret = TransmitData(trans_dev_id, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
		if (ret < 0) {
            sprintf( szLog, "SKF_ImportCertificate failed, error code: %d \n", ret );
            WriteLogToFile( szLog );
			LOGE("SKF_ImportCertificate return failed, ret %d.", ret);
			ret = -1;
			continue;
		}
		if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
			// get data if need
			break;
        } else {
            sprintf( szLog, "SKF_ImportCertificate failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
            WriteLogToFile( szLog );
            LOGE("SKF_ImportCertificate failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
		}
	}
	if (ret < 0) {
        sprintf( szLog, "SKF_ImportCertificate Certificate failed, error code: %d \n", ret );
        WriteLogToFile( szLog );
		LOGE("SKF_ImportCertificate return failed, ret %d.", ret);
		free(tmpBuffer_wr);
		free(tmpBuffer_rd);
		return SAR_FAIL;
	}
	// next import Certificate
	int size = strlen(pbCert);
	if (size > SIZE_BUFFER_128) {
		int parts = size / SIZE_BUFFER_128;
		int i = 0;
		unsigned char DataTobeSend[0x85];
		for (i = 0; i < parts; i++) {
            send_len = 0x85;
			memset(DataTobeSend, '\0', 0x85);
			memcpy(DataTobeSend, apdu_D6_00, 0x04);
			memcpy(DataTobeSend + 0x04, '0x80', 0x01);
			memcpy(DataTobeSend + 0x05, pbCert + i * SIZE_BUFFER_128, 0x80);
			memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
			//copy the raw data
			memcpy(tmpBuffer_wr, (unsigned char *)DataTobeSend, send_len);

			//fill the checksum byte
			check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

			//fill the data ...........................................
			*(tmpBuffer_wr+send_len) = check_sum;
			send_len = send_len + 1;
			repeat_times = 10;
			for (int i = 0; i < repeat_times; i++) {
				if (repeat_times > 1)
					usleep(500 * 1000);  //gap between each cycle

				memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
				recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
				ret = TransmitData(trans_dev_id, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
				if (ret < 0) {
                    sprintf( szLog, "SKF_ImportCertificate failed, error code: %d \n", ret );
                    WriteLogToFile( szLog );
					LOGE("SKF_ImportCertificate return failed, ret %d.", ret);
					continue;
				}
				if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
					// get data if need
					break;
                } else {
                    sprintf( szLog, "SKF_ImportCertificate failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
                    WriteLogToFile( szLog );
                    LOGE("SKF_ImportCertificate failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
                }
			}
		}
		int last = size - i * SIZE_BUFFER_128;
        send_len = last + 5;
		unsigned char LastToBeSend[send_len];
        unsigned char len;
        sprintf(len, "%X", last);
		memset(LastToBeSend, '\0', send_len);
		memcpy(LastToBeSend, apdu_D6_00, 0x04);
		memcpy(LastToBeSend + 0x04, len, 0x01);
		memcpy(LastToBeSend + 0x05, pbCert + i * SIZE_BUFFER_128, last);
		memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
		//copy the raw data
		memcpy(tmpBuffer_wr, (unsigned char *)LastToBeSend, send_len);

		//fill the checksum byte
		check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

		//fill the data ...........................................
		*(tmpBuffer_wr+send_len) = check_sum;
		send_len = send_len + 1;

		repeat_times = 10;
		for (int i = 0; i < repeat_times; i++) {
			if (repeat_times > 1)
				usleep(500 * 1000);  //gap between each cycle

			memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
			recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
			ret = TransmitData(trans_dev_id, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
			if (ret < 0) {
				LOGE("SKF_ImportCertificate return failed, ret %d.", ret);
                sprintf( szLog, "SKF_ImportCertificate failed, error code: %d \n", ret );
                WriteLogToFile( szLog );
				continue;
			}
			if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
				// get data if need
				break;
            } else {
                sprintf( szLog, "SKF_ImportCertificate failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
                WriteLogToFile( szLog );
                LOGE("SKF_ImportCertificate failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
            }
		}
	} else { // should not go here, just for test
        send_len = size + 5;
        unsigned char LastToBeSend[send_len];
        unsigned char len;
        sprintf(len, "%X", size);
        memset(LastToBeSend, '\0', send_len);
        memcpy(LastToBeSend, apdu_D6_00, 0x04);
        memcpy(LastToBeSend + 0x04, len, 0x01);
        memcpy(LastToBeSend + 0x05, pbCert, size);
        memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
        //copy the raw data
        memcpy(tmpBuffer_wr, (unsigned char *)LastToBeSend, send_len);

        //fill the checksum byte
        check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

        //fill the data ...........................................
        *(tmpBuffer_wr+send_len) = check_sum;
        send_len = send_len + 1;

        repeat_times = 10;
        for (int i = 0; i < repeat_times; i++) {
            if (repeat_times > 1)
                usleep(500 * 1000);  //gap between each cycle

            memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
            recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
            ret = TransmitData(trans_dev_id, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
            if (ret < 0) {
                LOGE("SKF_ImportCertificate return failed, ret %d.", ret);
                sprintf( szLog, "SKF_ImportCertificate failed, error code: %d \n", ret );
                WriteLogToFile( szLog );
                continue;
            }
            if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
                // get data if need
                break;
            } else {
                sprintf( szLog, "SKF_ImportCertificate failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
                WriteLogToFile( szLog );
                LOGE("SKF_ImportCertificate failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
            }
        }
	}

	free(tmpBuffer_wr);
	free(tmpBuffer_rd);

	return SAR_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
* �������ƣ�SKF_ExportCertificate
* �������ܣ���������֤��
* �����б�hContainer: [IN], �������
*           bSignFlag:  [IN], TRUE��ʾǩ��֤�飻FALSE��ʾ����֤��
*           pbCert:     [IN], ָ��֤�����ݻ�������ΪNULLʱ��pulCerLen��ʾ������������Ҫ�������ĳ��ȣ���֮��������֤������
*           pulCerLen:  [IN/OUT], ����ʱ��ʾpbCert���������ȣ����ʱ��ʾ֤�����ݵĳ���
* �� �� ֵ��SAR_OK: �ɹ�
            ����ֵ:������
*/

ULONG SKF_ExportCertificate( HANDLE hDev, BOOL bSignFlag, BYTE* pbCert, ULONG* pulCertLen )
{
	CHAR* pszLog = "**********Start to execute SKF_ExportCertificate ********** \n";
    CHAR szLog[SIZE_BUFFER_1024];
	BYTE apdu[0x07];
	INT nIndex = 0;
	sv_fEnd = FALSE;
	memset( apdu, 0x00, sizeof(apdu) );
	memset( szLog, 0x0, sizeof(szLog) );

	WriteLogToFile( pszLog );
	sv_fEnd = FALSE;
    if( hDev < 0 ) {
        return SAR_INVALIDHANDLEERR;
    }
    if (pbCert == NULL) {
        LOGE("SKF_ExportCertificate param pbCert is null.");
        return SAR_FAIL;
    }
	int size = strlen(pbCert);
	if (size != SIZE_BUFFER_1024) {
		LOGE("SKF_ExportCertificate param pbCert size is error.");
		return SAR_FAIL;
	}

    memset( apdu, 0x00, sizeof(apdu) );
    // set the certificate file
    memcpy( apdu, apdu_A5_00, 0x05 );
    if( !bSignFlag ) { //����֤��
        memcpy( apdu + 0x05, apdu_0002, 0x02 );
    } else {  //ǩ��֤��
        memcpy( apdu + 0x05, apdu_0001, 0x02 );
    }

    unsigned long send_len = strlen(apdu);
    unsigned char check_sum = 0;
    int ret;
    unsigned char * tmpBuffer_wr = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    //copy the raw data
    memcpy(tmpBuffer_wr, (unsigned char *)apdu, send_len);

    unsigned char *tmpBuffer_rd = memalign(512, DATA_TRANSMIT_BUFFER_MAX_SIZE);
    unsigned long recv_len = 0;

    //fill the checksum byte
    check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

    //fill the data ...........................................
    *(tmpBuffer_wr+send_len) = check_sum;
    send_len = send_len + 1;

    int repeat_times = 10;
    for (int i = 0; i < repeat_times; i++) {
        if (repeat_times > 1)
            usleep(500 * 1000);  //gap between each cycle

        memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
        recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
        ret = TransmitData(trans_dev_id, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
        if (ret < 0) {
            sprintf( szLog, "SKF_ExportCertificate failed, error code: %d \n", ret );
            WriteLogToFile( szLog );
            LOGE("SKF_ExportCertificate return failed, ret %d.", ret);
            ret = -1;
            continue;
        }
        if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
            // get data if need
            break;
        } else {
            sprintf( szLog, "SKF_ExportCertificate failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
            WriteLogToFile( szLog );
            LOGE("SKF_ExportCertificate failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
        }
    }
    if (ret < 0) {
        sprintf( szLog, "SKF_ExportCertificate failed, error code: %d \n", ret );
        WriteLogToFile( szLog );
        LOGE("SKF_ExportCertificate return failed, ret %d.", ret);
        free(tmpBuffer_wr);
        free(tmpBuffer_rd);
        return SAR_FAIL;
    }

	// next export Certificate
	int parts = size / SIZE_BUFFER_128;
	int i = 0;
	unsigned char DataTobeSend[0x85];
	for (i = 0; i < parts; i++) {
		send_len = 0x85;
		memset(DataTobeSend, '\0', 0x85);
		memcpy(DataTobeSend, apdu_B0_00, 0x04);
		memcpy(DataTobeSend + 0x04, '0x80', 0x01);
		memcpy(DataTobeSend + 0x05, pbCert + i * SIZE_BUFFER_128, 0x80);
		memset(tmpBuffer_wr, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
		//copy the raw data
		memcpy(tmpBuffer_wr, (unsigned char *)DataTobeSend, send_len);

		//fill the checksum byte
		check_sum = CalculateCheckSum((tmpBuffer_wr+1), (send_len-1));

		//fill the data ...........................................
		*(tmpBuffer_wr+send_len) = check_sum;
		send_len = send_len + 1;
		repeat_times = 10;
		for (int i = 0; i < repeat_times; i++) {
			if (repeat_times > 1)
				usleep(500 * 1000);  //gap between each cycle

			memset(tmpBuffer_rd, 0, DATA_TRANSMIT_BUFFER_MAX_SIZE);
			recv_len = DATA_TRANSMIT_BUFFER_MAX_SIZE;
			ret = TransmitData(trans_dev_id, tmpBuffer_wr, send_len, tmpBuffer_rd, &recv_len);
			if (ret < 0) {
				sprintf( szLog, "SKF_ExportCertificate failed, error code: %d \n", ret );
				WriteLogToFile( szLog );
				LOGE("SKF_ExportCertificate return failed, ret %d.", ret);
				continue;
			}
			if( (tmpBuffer_rd[recv_len-2] == 0x90) && (tmpBuffer_rd[recv_len-1] == 0x00 ) ) {
				// get data if need
				memcpy(pbCert + nIndex, tmpBuffer_rd, recv_len - 2);
				nIndex = nIndex + recv_len - 2;
				break;
			} else {
				sprintf( szLog, "SKF_ExportCertificate failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1] );
				WriteLogToFile( szLog );
				LOGE("SKF_ExportCertificate failed, status code: %02X%02X \n", tmpBuffer_rd[recv_len-2], tmpBuffer_rd[recv_len-1]);
			}
		}
	}

	*pulCertLen = nIndex;
	free(tmpBuffer_wr);
	free(tmpBuffer_rd);

	return SAR_OK;
}

#ifdef __cplusplus
}
#endif  /*__cplusplus*/
