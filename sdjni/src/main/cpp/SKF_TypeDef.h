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

//算法标识
//分组密码算法标识
//#define  SGD_SM1          0x00000100
//#define  SGD_SSF33        0x00000200
//#define  SGD_SM4          0x00000400
//#define  SGD_ECB          0x00000001
#define  SGD_SM1_ECB	  0x00000101	//SM1算法ECB加密模式
#define  SGD_SM1_CBC	  0x00000102	//SM1算法CBC加密模式
#define  SGD_SM1_CFB	  0x00000104	//SM1算法CFB加密模式
#define  SGD_SM1_OFB	  0x00000108	//SM1算法OFB加密模式
#define  SGD_SM1_MAC	  0x00000110	//SM1算法MAC运算
#define  SGD_SSF33_ECB	  0x00000201	//SSF33算法ECB加密模式
#define  SGD_SSF33_CBC	  0x00000202	//SSF33算法CBC加密模式
#define  SGD_SSF33_CFB	  0x00000204	//SSF33算法CFB加密模式
#define  SGD_SSF33_OFB	  0x00000208	//SSF33算法OFB加密模式
#define  SGD_SSF33_MAC	  0x00000210	//SSF33算法MAC运算
#define  SGD_SM4_ECB	  0x00000401	//SMS4算法ECB加密模式
#define  SGD_SM4_CBC	  0x00000402	//SMS4算法CBC加密模式
#define  SGD_SM4_CFB	  0x00000404	//SMS4算法CFB加密模式
#define  SGD_SM4_OFB	  0x00000408	//SMS4算法OFB加密模式
#define  SGD_SM4_MAC	  0x00000410    //SMS4算法MAC运算
//0x00000400-0x800000xx	为其它分组密码算法预留


//非对称密码算法标识
#define  SGD_RSA	      0x00010000	//RSA算法
#define  SGD_SM2          0x00020000    //椭圆曲线密码算法
#define  SGD_SM2_1	      0x00020100	//椭圆曲线签名算法
#define  SGD_SM2_2	      0x00020200	//椭圆曲线密钥交换协议
#define  SGD_SM2_3	      0x00020400	//椭圆曲线加密算法
//0x00000400～0x800000xx	为其它非对称密码算法预留

//密码杂凑算法标识
#define  SGD_SM3	     0x00000001	    //SM3杂凑算法
#define  SGD_SHA1	     0x00000002	    //SHA1杂凑算法
#define  SGD_SHA256	     0x00000004	    //SHA256杂凑算法
//0x00000010～0x000000FF	为其它密码杂凑算法预留


#define  MAX_IV_LEN            32
#define  MAX_RSA_MODULUS_LEN   256
#define  MAX_RSA_EXPONENT_LEN  4

#define  ECC_MAX_XCOORDINATE_BITS_LEN  512
#define  ECC_MAX_YCOORDINATE_BITS_LEN  512
#define  ECC_MAX_MODULUS_BITS_LEN      512




//文件属性
typedef struct Struct_FILEATTRIBUTE {
	CHAR FileName[32];
	ULONG FileSize;
	ULONG ReadRights;
	ULONG WriteRights;
} FILEATTRIBUTE, *PFILEATTRIBUTE;

//应用信息
typedef struct Struct_APPLICATIONINFO {

	DEVHANDLE hDev;
	ULONG CreateRights[1];
	BYTE ApplicationFID[2];
	CHAR ApplicationName[32];
} APPLICATIONINFO, *PAPPLICATIONINFO;

//容器信息
typedef struct Struct_CONTAINERINFO {

	HAPPLICATION hApplication;
	ULONG  ulContainerType;
	BYTE bSFI[6];

} CONTAINERINFO, *PCONTAINERINFO;
//版本号
typedef struct Struct_Version {
    BYTE major;
	BYTE minor;
} VERSION;

//设备信息
//注意，2字节对齐方式
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

//哈希对象
typedef struct Struct_HASHINFO {
	DEVHANDLE hDev;
	ULONG AlgID;
	ULONG ZValueLen;
	BYTE  ZValue[32];
    
} HASHINFO, *PHASHINFO;

//RSA公钥数据结构
typedef struct Struct_RSAPUBLICKEYBLOB {
	ULONG AlgID;
	ULONG BitLen;
	BYTE Modulus[MAX_RSA_MODULUS_LEN];
	BYTE PublicExponent[MAX_RSA_EXPONENT_LEN];
} RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

//RSA私钥数据结构
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

//ECC公钥数据结构
typedef struct Struct_ECCPUBLICKEYBLOB {
    ULONG BitLen;
    BYTE  XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
    BYTE  YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];
} ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;


//ECC私钥数据结构
typedef struct Struct_ECCPRIVATEKEYBLOB {
    ULONG BitLen;
    BYTE  PrivateKey[ECC_MAX_MODULUS_BITS_LEN/8];
} ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;

//ECC密文数据结构
typedef struct Struct_ECCCIPHERBLOB {
    BYTE  XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
    BYTE  YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
    BYTE  HASH[32]; 
    ULONG CipherLen;
    BYTE  Cipher[128]; 
} ECCCIPHERBLOB, *PECCCIPHERBLOB;

//ECC签名数据结构
typedef struct Struct_ECCSIGNATUREBLOB {
    BYTE r[ECC_MAX_XCOORDINATE_BITS_LEN/8];
    BYTE s[ECC_MAX_XCOORDINATE_BITS_LEN/8];
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;


//分组密码参数
typedef struct Struct_BLOCKCIPHERPARAM {
    BYTE IV[MAX_IV_LEN];
    ULONG IVLen;
    ULONG PaddingType;
    ULONG FeedBitLen;
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

//会话密钥数据结构
typedef struct Struct_SESSIONKEY {
    DEVHANDLE hDev;
	ULONG AlgID;
	BYTE  KeyLen;
	BYTE  KeyVal[128];
	BLOCKCIPHERPARAM Params;
	ULONG MsgLen;
} SESSIONKEY, *PSESSIONKEY;


//ECC加密密钥对保护结构
typedef struct SKF_ENVELOPEDKEYBLOB {
    ULONG Version;                  // 当前版本为 1
    ULONG ulSymmAlgID;              // 对称算法标识，限定ECB模式
    ULONG ulBits;					// 加密密钥对的密钥位长度
    BYTE cbEncryptedPriKey[64];     // 加密密钥对私钥的密文
    ECCPUBLICKEYBLOB PubKey;        // 加密密钥对的公钥
    ECCCIPHERBLOB ECCCipherBlob;    // 用保护公钥加密的对称密钥密文。
} ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

#endif //SKF_BASE_H
