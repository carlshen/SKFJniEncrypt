#ifndef SKF_STATUS_H
#define SKF_STATUS_H


#define SAR_OK                           0x00000000  //�ɹ�
#define SAR_FAIL                         0x0A000001  //ʧ��
#define SAR_UNKNOWNERR                   0x0A000002  //�쳣����
#define SAR_NOTSUPPORTYETERR             0x0A000003  //��֧�ֵķ���
#define SAR_FILEERR                      0x0A000004  //�ļ���������
#define SAR_INVALIDHANDLEERR             0x0A000005  //��Ч�ľ��

#define SAR_READFILEERR                  0x0A000007  //���ļ�����
#define SAR_WRITEFILEERR                 0x0A000008  //д�ļ�����

#define SAR_INDATALENERR                 0x0A000010  //�������ݳ��ȴ���
#define SAR_INDATAERR                    0x0A000011  //�������ݴ���
#define SAR_GENRANDERR                   0x0A000012  //�������������

#define SAR_APPLICATION_EXISTS           0x0A00002C  //Ӧ���Ѿ�����
#define SAR_APPLICATION_NOT_EXISTS       0x0A00002E  //Ӧ�ò�����


#define SAR_BUFFER_TOO_SMALL             0x0A000020  //����������
#define SAR_PIN_INCORRECT                0x0A000024  //PIN����ȷ
#define SAR_PIN_LOCKED                   0x0A000025  //PIN������
#define SAR_PIN_INVALID                  0x0A000026  //PIN��Ч
#define SAR_PIN_LEN_RANGE                0x0A000027  //PIN���ȴ���
#define SAR_USER_TYPE_INVALID            0x0A00002A  //PIN���ʹ���
#define SAR_APPLICATION_NAME_INVALID     0x0A00002B  //Ӧ��������Ч
#define SAR_FILE_ALREADY_EXIST           0x0A00002F  //�ļ��Ѿ�����
#define SAR_NO_ROOM                      0x0A000030  //�ռ䲻��
#define SAR_FILE_NOT_EXIST               0x0A000031  //�ļ�������


#define SECURE_NEVER_ACCOUNT             0x00000000  //������
#define SECURE_ADM_ACCOUNT               0x00000001  //����ԱȨ��
#define SECURE_USER_ACCOUNT              0x00000010  //�û�Ȩ��
#define SECURE_ANYONE_ACCOUNT            0x000000FF  //�κ���Ȩ��

#endif //SKF_STATUS_H
