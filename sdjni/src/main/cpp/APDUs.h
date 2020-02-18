
#pragma once

#include <base_type.h>

//��������
#define  APDU_ENCRYPT_SFI  0x16
#define  APDU_SIGN_SFI     0x19

//CA����FID
extern const BYTE APDU_CA_FID[2];
extern const BYTE APDU_MF_FID[2];
extern const BYTE APDU_EF01_FID[2];
extern const BYTE APDU_EF02_FID[2];
//�豸����


//���ʿ���
//��֤PIN�룬0x05����������ԱPIN���û�PIN
extern BYTE apdu_verifyPIN[0x05];
//����PIN��0x05���ڹ���Ա��֤����û�PIN���н���
extern BYTE apdu_unblockPIN[0x05];
//�޸�PIN�룬0x05����������ԱPIN���û�PIN
extern BYTE apdu_changePIN[0x05];
//��װPIN��0x05����������ԱPIN���û�PIN
extern BYTE apdu_reloadPIN[0x05];
//��װPINʱ����MAC�ĳ�ʼֵ��x08
extern BYTE reload_initV[0x08];
//��װPINʱ����MAC����Կ��0x08
extern BYTE reload_key[0x10];

//Ӧ�ù���
//�豸�� 0x10
extern BYTE apdu_deviceKey[0x10];
//��֤TK��0x0D
extern BYTE apdu_verifyTK[0x40];
//������Կ��0x10������MFʱʹ��
extern BYTE apdu_TK[0x10];
//ѡ��MF��0x07
extern BYTE apdu_selectMF[0x07];
//ѡ��DF��0x07
extern BYTE apdu_selectDF[0x07];
//����MF��0x21
extern BYTE apdu_createMF[0x21];
//����DF��0x21
extern BYTE apdu_createDF[0x21];
//�������0x05
extern BYTE apdu_random[0x05];
//�ⲿ��֤��0x0D
extern BYTE apdu_externalAuth[0x05] ;
//ɾ��MF��0x07
extern BYTE apdu_deleteMF[0x07];
//�ⲿ��֤��Կ��0x10��ɾ��MFʱʹ��
extern BYTE apdu_TK2[0x10];

//����KEY�ļ���0x19
extern BYTE apdu_createKey[0x19];
//KEYMK��Կ��0x10
extern BYTE apdu_KEYMK[0x10];
//DAMK��Կ��0x10
extern BYTE apdu_DAMK[0x10];
//DCCK��Կ��0x10
extern BYTE apdu_DCCK[0x10];
//DUPK��Կ��0x10
extern BYTE apdu_DUPK[0x10];
//����KEY�ļ���0x1C
extern BYTE apdu_writeKey[0x1C];
//KEYMK��Կ��0x10
extern BYTE apdu_KEY_KEYMK[0x17];
//DAMK��Կ��0x10
extern BYTE apdu_KEY_DAMK[0x17];
//DCCK��Կ��0x10
extern BYTE apdu_KEY_DCCK[0x17];
//����MF����
extern BYTE apdu_createDFEnd[0x05];
//ɾ��DF
extern BYTE apdu_deleteDF[0x05];

//�ļ�����
//���������ƣ�0x19
extern BYTE apdu_createBinary[0x19];
//���¶������ļ�
extern BYTE apdu_updateBinary[0x05];
//���������ļ�
extern BYTE apdu_readBinary[0x05];

//��������

//�������
//�������0x05
extern BYTE apdu_random2[5];
//��ȡ��Ӧ��0x05
extern BYTE apdu_getResponse[5];

//ECCǩ����Կ��
extern BYTE apdu_eccGenKeyPair[0x05];
extern BYTE apdu_eccSignData[0x05];
extern BYTE apdu_eccSignVerify[0x05];
extern BYTE apdu_eccEncrypt[0x05];
extern BYTE apdu_eccDecrypt[0x05];
//
extern BYTE apdu_personalization[0x05];

//SM1�����ܣ�ECBģʽ��0x05
extern BYTE apdu_encrypt_sm1_ecb[0x05];
//SM1�����ܣ�ECBģʽ��0x05
extern BYTE apdu_decrypt_sm1_ecb[0x05];
//SM1�����ܣ�CBCģʽ��0x05
extern BYTE apdu_encrypt_sm1_cbc[0x05];
//SM1�����ܣ�CBCģʽ��0x05
extern BYTE apdu_decrypt_sm1_cbc[0x05];
//SM1�����ܣ�CFBģʽ��0x05
extern BYTE apdu_encrypt_sm1_cfb[0x05];
//SM1�����ܣ�CFBģʽ��0x05
extern BYTE apdu_decrypt_sm1_cfb[0x05];
//SM1�����ܣ�OFBģʽ��0x05
extern BYTE apdu_encrypt_sm1_ofb[0x05];
//SM1�����ܣ�OFBģʽ��0x05
extern BYTE apdu_decrypt_sm1_ofb[0x05];

//SSF33�����ܣ�ECBģʽ��0x05
extern BYTE apdu_encrypt_ssf33_ecb[0x05];
//SSF33�����ܣ�ECBģʽ��0x05
extern BYTE apdu_decrypt_ssf33_ecb[0x05];
//SSF33�����ܣ�CBCģʽ��0x05
extern BYTE apdu_encrypt_ssf33_cbc[0x05];
//SSF33�����ܣ�CBCģʽ��0x05
extern BYTE apdu_decrypt_ssf33_cbc[0x05];
//SSF33�����ܣ�CFBģʽ��0x05
extern BYTE apdu_encrypt_ssf33_cfb[0x05];
//SSF33�����ܣ�CFBģʽ��0x05
extern BYTE apdu_decrypt_ssf33_cfb[0x05];
//SSF33�����ܣ�OFBģʽ��0x05
extern BYTE apdu_encrypt_ssf33_ofb[0x05];
//SSF33�����ܣ�OFBģʽ��0x05
extern BYTE apdu_decrypt_ssf33_ofb[0x05];

//SM4�����ܣ�ECBģʽ��0x05
extern BYTE apdu_encrypt_sm4_ecb[0x05];
//SM4�����ܣ�ECBģʽ��0x05
extern BYTE apdu_decrypt_sm4_ecb[0x05];
//SM4�����ܣ�CBCģʽ��0x05
extern BYTE apdu_encrypt_sm4_cbc[0x05];
//SM4�����ܣ�CBCģʽ��0x05
extern BYTE apdu_decrypt_sm4_cbc[0x05];
//SM4�����ܣ�CFBģʽ��0x05
extern BYTE apdu_encrypt_sm4_cfb[0x05];
//SM4�����ܣ�CFBģʽ��0x05
extern BYTE apdu_decrypt_sm4_cfb[0x05];
//SM4�����ܣ�OFBģʽ��0x05
extern BYTE apdu_encrypt_sm4_ofb[0x05];
//SM4�����ܣ�OFBģʽ��0x05
extern BYTE apdu_decrypt_sm4_ofb[0x05];

//�����㷨SM1��SSF33��SM4��CBCģʽʹ�ã�0x05
extern BYTE apdu_cbc_sendIV[0x05];
//SM3�Ӵ�
extern BYTE apdu_sm3_digest[0x05];

//����SM2ǩ����Կ��
extern BYTE apdu_import_sm2_keypair[0x05];
//��˼�����
extern BYTE apdu_point_multadd[0x05];
//ģ�˼�����
extern BYTE apdu_mod_multadd[0x05];

