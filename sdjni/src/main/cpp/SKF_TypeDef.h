#ifndef SKF_BASE_H
#define SKF_BASE_H

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif

typedef char CHAR;
typedef short SHORT;
typedef long LONG;
typedef unsigned long ULONG;
typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef int                 INT;
typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef int BOOL;
typedef UINT8 BYTE;
typedef CHAR * LPSTR;
typedef int HANDLE;
typedef HANDLE DEVHANDLE;
typedef HANDLE HAPPLICATION;
typedef HANDLE HCONTAINER;

//�㷨��ʶ
//���������㷨��ʶ
//#define  SGD_SM1          0x00000100
//#define  SGD_SSF33        0x00000200
//#define  SGD_SM4          0x00000400
//#define  SGD_ECB          0x00000001
#define  SGD_SM1_ECB	  0x00000101	//SM1�㷨ECB����ģʽ
#define  SGD_SM1_CBC	  0x00000102	//SM1�㷨CBC����ģʽ
#define  SGD_SM1_CFB	  0x00000104	//SM1�㷨CFB����ģʽ
#define  SGD_SM1_OFB	  0x00000108	//SM1�㷨OFB����ģʽ
#define  SGD_SM1_MAC	  0x00000110	//SM1�㷨MAC����
#define  SGD_SSF33_ECB	  0x00000201	//SSF33�㷨ECB����ģʽ
#define  SGD_SSF33_CBC	  0x00000202	//SSF33�㷨CBC����ģʽ
#define  SGD_SSF33_CFB	  0x00000204	//SSF33�㷨CFB����ģʽ
#define  SGD_SSF33_OFB	  0x00000208	//SSF33�㷨OFB����ģʽ
#define  SGD_SSF33_MAC	  0x00000210	//SSF33�㷨MAC����
#define  SGD_SM4_ECB	  0x00000401	//SMS4�㷨ECB����ģʽ
#define  SGD_SM4_CBC	  0x00000402	//SMS4�㷨CBC����ģʽ
#define  SGD_SM4_CFB	  0x00000404	//SMS4�㷨CFB����ģʽ
#define  SGD_SM4_OFB	  0x00000408	//SMS4�㷨OFB����ģʽ
#define  SGD_SM4_MAC	  0x00000410    //SMS4�㷨MAC����
//0x00000400-0x800000xx	Ϊ�������������㷨Ԥ��


//�ǶԳ������㷨��ʶ
#define  SGD_RSA	      0x00010000	//RSA�㷨
#define  SGD_SM2          0x00020000    //��Բ���������㷨
#define  SGD_SM2_1	      0x00020100	//��Բ����ǩ���㷨
#define  SGD_SM2_2	      0x00020200	//��Բ������Կ����Э��
#define  SGD_SM2_3	      0x00020400	//��Բ���߼����㷨
//0x00000400��0x800000xx	Ϊ�����ǶԳ������㷨Ԥ��

//�����Ӵ��㷨��ʶ
#define  SGD_SM3	     0x00000001	    //SM3�Ӵ��㷨
#define  SGD_SHA1	     0x00000002	    //SHA1�Ӵ��㷨
#define  SGD_SHA256	     0x00000004	    //SHA256�Ӵ��㷨
//0x00000010��0x000000FF	Ϊ���������Ӵ��㷨Ԥ��


#define  MAX_IV_LEN            32
#define  MAX_RSA_MODULUS_LEN   256
#define  MAX_RSA_EXPONENT_LEN  4

#define  ECC_MAX_XCOORDINATE_BITS_LEN  512
#define  ECC_MAX_YCOORDINATE_BITS_LEN  512
#define  ECC_MAX_MODULUS_BITS_LEN      512




//�ļ�����
typedef struct Struct_FILEATTRIBUTE {
	CHAR FileName[32];
	ULONG FileSize;
	ULONG ReadRights;
	ULONG WriteRights;
} FILEATTRIBUTE, *PFILEATTRIBUTE;

//Ӧ����Ϣ
typedef struct Struct_APPLICATIONINFO {

	DEVHANDLE hDev;
	ULONG CreateRights[1];
	BYTE ApplicationFID[2];
	CHAR ApplicationName[32];
} APPLICATIONINFO, *PAPPLICATIONINFO;

//������Ϣ
typedef struct Struct_CONTAINERINFO {

	HAPPLICATION hApplication;
	ULONG  ulContainerType;
	BYTE bSFI[6];

} CONTAINERINFO, *PCONTAINERINFO;
//�汾��
typedef struct Struct_Version {
    BYTE major;
	BYTE minor;
} VERSION;

//�豸��Ϣ
//ע�⣬2�ֽڶ��뷽ʽ
typedef struct Struct_DEVINFO {
//#pragma pack(2)
    VERSION Version;
	CHAR    Manufacturer[64];
	CHAR    Issuer[64];
	CHAR Label[32];
	CHAR SerialNumber[32];
	VERSION HWVersion;
	VERSION FirmwareVersion;
	ULONG AlgSymCap;
	ULONG AlgAsymCap;
	ULONG AlgHashCap;
	ULONG DevAuthAlgId;
	ULONG TotalSpace;
	ULONG FreeSpace;
	ULONG MaxECCBufferSize;
	ULONG MaxBufferSize;
	BYTE Reserved[64];
} DEVINFO, *PDEVINFO;

//��ϣ����
typedef struct Struct_HASHINFO {
	DEVHANDLE hDev;
	ULONG AlgID;
	ULONG ZValueLen;
	BYTE  ZValue[32];
    
} HASHINFO, *PHASHINFO;

//RSA��Կ���ݽṹ
typedef struct Struct_RSAPUBLICKEYBLOB {
	ULONG AlgID;
	ULONG BitLen;
	BYTE Modulus[MAX_RSA_MODULUS_LEN];
	BYTE PublicExponent[MAX_RSA_EXPONENT_LEN];
} RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

//RSA˽Կ���ݽṹ
typedef struct Struct_RSAPRIVATEKEYBLOB {
    ULONG AlgID;
    ULONG BitLen;
    BYTE  Modulus[MAX_RSA_MODULUS_LEN];
    BYTE  PublicExponent[MAX_RSA_EXPONENT_LEN];
    BYTE  PrivateExponent[MAX_RSA_MODULUS_LEN];
    BYTE  Prime1[MAX_RSA_MODULUS_LEN/2];
    BYTE  Prime2[MAX_RSA_MODULUS_LEN/2];
    BYTE  Prime1Exponent[MAX_RSA_MODULUS_LEN/2];
    BYTE  Prime2Exponent[MAX_RSA_MODULUS_LEN/2];
    BYTE  Coefficient[MAX_RSA_MODULUS_LEN/2];
} RSAPRIVATEKEYBLOB, *PRSAPRIVATEKEYBLOB;

//ECC��Կ���ݽṹ
typedef struct Struct_ECCPUBLICKEYBLOB {
    ULONG BitLen;
    BYTE  XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
    BYTE  YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];
} ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;


//ECC˽Կ���ݽṹ
typedef struct Struct_ECCPRIVATEKEYBLOB {
    ULONG BitLen;
    BYTE  PrivateKey[ECC_MAX_MODULUS_BITS_LEN/8];
} ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;

//ECC�������ݽṹ
typedef struct Struct_ECCCIPHERBLOB {
    BYTE  XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
    BYTE  YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
    BYTE  HASH[32]; 
    ULONG CipherLen;
    BYTE  Cipher[128]; 
} ECCCIPHERBLOB, *PECCCIPHERBLOB;

//ECCǩ�����ݽṹ
typedef struct Struct_ECCSIGNATUREBLOB {
    BYTE r[ECC_MAX_XCOORDINATE_BITS_LEN/8];
    BYTE s[ECC_MAX_XCOORDINATE_BITS_LEN/8];
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;


//�����������
typedef struct Struct_BLOCKCIPHERPARAM {
    BYTE IV[MAX_IV_LEN];
    ULONG IVLen;
    ULONG PaddingType;
    ULONG FeedBitLen;
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

//�Ự��Կ���ݽṹ
typedef struct Struct_SESSIONKEY {
    DEVHANDLE hDev;
	ULONG AlgID;
	BYTE  KeyLen;
	BYTE  KeyVal[128];
	BLOCKCIPHERPARAM Params;
	ULONG MsgLen;
} SESSIONKEY, *PSESSIONKEY;


//ECC������Կ�Ա����ṹ
typedef struct SKF_ENVELOPEDKEYBLOB {
    ULONG Version;                  // ��ǰ�汾Ϊ 1
    ULONG ulSymmAlgID;              // �Գ��㷨��ʶ���޶�ECBģʽ
    ULONG ulBits;					// ������Կ�Ե���Կλ����
    BYTE cbEncryptedPriKey[64];     // ������Կ��˽Կ������
    ECCPUBLICKEYBLOB PubKey;        // ������Կ�ԵĹ�Կ
    ECCCIPHERBLOB ECCCipherBlob;    // �ñ�����Կ���ܵĶԳ���Կ���ġ�
} ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

#endif //SKF_BASE_H
