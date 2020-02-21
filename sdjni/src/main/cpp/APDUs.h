
#ifndef SKF_APDU_H
#define SKF_APDU_H

#include "SKF_TypeDef.h"

//CA����FID
BYTE APDU_CA_FID[2];
BYTE APDU_MF_FID[2];
BYTE APDU_EF01_FID[2];
BYTE APDU_EF02_FID[2];
//�豸����

//Ӧ�ù���
//�豸�� 0x10
BYTE apdu_deviceKey[0x10];
//��֤TK��0x0D
BYTE apdu_verifyTK[0x40];
//������Կ��0x10������MFʱʹ��
BYTE apdu_TK[0x10];
//ѡ��MF��0x07
BYTE apdu_selectMF[0x07];
//ѡ��DF��0x07
BYTE apdu_selectDF[0x07];
//����MF��0x21
BYTE apdu_createMF[0x21];
//����DF��0x21
BYTE apdu_createDF[0x21];
//�������0x05
BYTE apdu_random[0x05];
//�ⲿ��֤��0x0D
BYTE apdu_externalAuth[0x05] ;
//ɾ��MF��0x07
BYTE apdu_deleteMF[0x07];
//�ⲿ��֤��Կ��0x10��ɾ��MFʱʹ��
BYTE apdu_TK2[0x10];

//����KEY�ļ���0x19
BYTE apdu_createKey[0x19];
//KEYMK��Կ��0x10
BYTE apdu_KEYMK[0x10];
//DAMK��Կ��0x10
BYTE apdu_DAMK[0x10];
//DCCK��Կ��0x10
BYTE apdu_DCCK[0x10];
//DUPK��Կ��0x10
BYTE apdu_DUPK[0x10];
//����KEY�ļ���0x1C
BYTE apdu_writeKey[0x1C];
//KEYMK��Կ��0x10
BYTE apdu_KEY_KEYMK[0x17];
//DAMK��Կ��0x10
BYTE apdu_KEY_DAMK[0x17];
//DCCK��Կ��0x10
BYTE apdu_KEY_DCCK[0x17];
//����MF����
BYTE apdu_createDFEnd[0x05];
//ɾ��DF
BYTE apdu_deleteDF[0x05];

//�ļ�����
//���������ƣ�0x19
BYTE apdu_createBinary[0x19];
//���¶������ļ�
BYTE apdu_updateBinary[0x05];
//���������ļ�
BYTE apdu_readBinary[0x05];

//��������

//�������
//�������0x05
BYTE apdu_random2[5];
//��ȡ��Ӧ��0x05
BYTE apdu_getResponse[5];

//ECCǩ����Կ��
BYTE apdu_GenEccKeyPair[0x05];
BYTE apdu_eccGenKeyPair[0x05];
BYTE apdu_eccSignData[0x05];
BYTE apdu_eccSignVerify[0x05];
BYTE apdu_genDataKeyEcc[0x05];
BYTE apdu_eccEncrypt[0x05];
BYTE apdu_eccDecrypt[0x05];
BYTE apdu_84_00[0x04];
BYTE apdu_A4_04[0x04];
BYTE apdu_A5_00[0x04];
BYTE apdu_B0_00[0x04];
BYTE apdu_C8_00[0x04];
BYTE apdu_C6_00[0x04];
BYTE apdu_CA_05[0x05];
BYTE apdu_CC_00[0x04];
BYTE apdu_CE_00[0x04];
BYTE apdu_D6_00[0x04];
BYTE apdu_E1_00[0x05];
BYTE apdu_F1_00[0x04];
BYTE apdu_F4_00[0x04];
BYTE apdu_F8_01[0x04];
BYTE apdu_F8_02[0x04];
BYTE apdu_F8_03[0x04];
BYTE apdu_FA_00[0x04];
BYTE apdu_FA_01[0x04];
BYTE apdu_FA_02[0x04];
BYTE apdu_FA_03[0x04];
BYTE apdu_FC_01[0x06];
BYTE apdu_FC_02[0x04];
BYTE apdu_FC_03[0x04];

//SM1�����ܣ�ECBģʽ��0x05
BYTE apdu_encrypt_sm1_ecb[0x05];
//SM1�����ܣ�ECBģʽ��0x05
BYTE apdu_decrypt_sm1_ecb[0x05];
//SM1�����ܣ�CBCģʽ��0x05
BYTE apdu_encrypt_sm1_cbc[0x05];
//SM1�����ܣ�CBCģʽ��0x05
BYTE apdu_decrypt_sm1_cbc[0x05];
//SM1�����ܣ�CFBģʽ��0x05
BYTE apdu_encrypt_sm1_cfb[0x05];
//SM1�����ܣ�CFBģʽ��0x05
BYTE apdu_decrypt_sm1_cfb[0x05];
//SM1�����ܣ�OFBģʽ��0x05
BYTE apdu_encrypt_sm1_ofb[0x05];
//SM1�����ܣ�OFBģʽ��0x05
BYTE apdu_decrypt_sm1_ofb[0x05];

//SSF33�����ܣ�ECBģʽ��0x05
BYTE apdu_encrypt_ssf33_ecb[0x05];
//SSF33�����ܣ�ECBģʽ��0x05
BYTE apdu_decrypt_ssf33_ecb[0x05];
//SSF33�����ܣ�CBCģʽ��0x05
BYTE apdu_encrypt_ssf33_cbc[0x05];
//SSF33�����ܣ�CBCģʽ��0x05
BYTE apdu_decrypt_ssf33_cbc[0x05];
//SSF33�����ܣ�CFBģʽ��0x05
BYTE apdu_encrypt_ssf33_cfb[0x05];
//SSF33�����ܣ�CFBģʽ��0x05
BYTE apdu_decrypt_ssf33_cfb[0x05];
//SSF33�����ܣ�OFBģʽ��0x05
BYTE apdu_encrypt_ssf33_ofb[0x05];
//SSF33�����ܣ�OFBģʽ��0x05
BYTE apdu_decrypt_ssf33_ofb[0x05];

//SM4�����ܣ�ECBģʽ��0x05
BYTE apdu_encrypt_sm4_ecb[0x05];
//SM4�����ܣ�ECBģʽ��0x05
BYTE apdu_decrypt_sm4_ecb[0x05];
//SM4�����ܣ�CBCģʽ��0x05
BYTE apdu_encrypt_sm4_cbc[0x05];
//SM4�����ܣ�CBCģʽ��0x05
BYTE apdu_decrypt_sm4_cbc[0x05];
//SM4�����ܣ�CFBģʽ��0x05
BYTE apdu_encrypt_sm4_cfb[0x05];
//SM4�����ܣ�CFBģʽ��0x05
BYTE apdu_decrypt_sm4_cfb[0x05];
//SM4�����ܣ�OFBģʽ��0x05
BYTE apdu_encrypt_sm4_ofb[0x05];
//SM4�����ܣ�OFBģʽ��0x05
BYTE apdu_decrypt_sm4_ofb[0x05];

//�����㷨SM1��SSF33��SM4��CBCģʽʹ�ã�0x05
BYTE apdu_cbc_sendIV[0x05];
//SM3�Ӵ�
BYTE apdu_sm3_digest[0x05];

//����SM2ǩ����Կ��
BYTE apdu_import_sm2_keypair[0x05];
//��˼�����
BYTE apdu_point_multadd[0x05];
//ģ�˼�����
BYTE apdu_mod_multadd[0x05];

#endif //SKF_APDU_H
