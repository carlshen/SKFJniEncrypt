//
// Created by Administrator on 2018/7/30.
//

#ifndef TMC_PKCS11_TYPES_H
#define TMC_PKCS11_TYPES_H

#include <stdio.h>
#include <unistd.h>
#include <base_type.h>


#ifdef __cplusplus
extern "C" {
#endif

//typedef unsigned short u16;
//typedef unsigned long u32;

//typedef uint8_t u8;
//typedef uint8_t uint8_t;
//typedef uint16_t uint16_t;
//typedef uint32_t uint32_t;
//typedef uint64_t uint64_t;

/* various maximum values */
#define SC_MAX_CARD_DRIVERS		48
#define SC_MAX_CARD_DRIVER_SNAME_SIZE	16
#define SC_MAX_CARD_APPS		8

#define SC_MAX_APDU_HEADER_SIZE		5
#define SC_MAX_APDU_BODY_SIZE		255
#define SC_MAX_APDU_LE_SIZE			1
#define SC_MAX_APDU_BUFFER_SIZE		(SC_MAX_APDU_HEADER_SIZE+SC_MAX_APDU_BODY_SIZE+SC_MAX_APDU_LE_SIZE)

#define SC_MAX_SEND_BUFF_CFG_SIZE	SC_MAX_APDU_BODY_SIZE


#define SC_MAX_EXT_APDU_BUFFER_SIZE	65538
#define SC_MAX_PIN_SIZE			32 
#define SC_MAX_ATR_SIZE			33
#define SC_MAX_UID_SIZE			10
#define SC_MAX_AID_SIZE			16
#define SC_MAX_AID_STRING_SIZE		(SC_MAX_AID_SIZE * 2 + 3)
#define SC_MAX_IIN_SIZE			10
#define SC_MAX_OBJECT_ID_OCTETS		16
#define SC_MAX_PATH_SIZE		16
#define SC_MAX_PATH_STRING_SIZE		(SC_MAX_PATH_SIZE * 2 + 3)
#define SC_MAX_SDO_ACLS			8
#define SC_MAX_CRTS_IN_SE		12
#define SC_MAX_SE_NUM			8
#define SC_MAX_LENGTH_SIZE			32767
#define SC_MAX_LENGTH_SIZE_SFI		255
#define SC_MAX_CACHE_SIZE			2048
#define SC_MAX_ID_SIZE			128

#define CLA_OFFSET 0
#define INS_OFFSET 1
#define P1_OFFSET 2
#define P2_OFFSET 3
#define LC_OFFSET 4
#define DATA_OFFSET 5

/* When changing this value, pay attention to the initialization of the ASN1
 * static variables that use this macro, like, for example,
 * 'c_asn1_supported_algorithms' in src/libopensc/pkcs15.c
 */
#define SC_MAX_SUPPORTED_ALGORITHMS	8

/* Access Control flags */
#define SC_AC_NONE			0x00000000
#define SC_AC_CHV			0x00000001 /* Card Holder Verif. */
#define SC_AC_TERM			0x00000002 /* Terminal auth. */
#define SC_AC_PRO			0x00000004 /* Secure Messaging */
#define SC_AC_AUT			0x00000008 /* Key auth. */
#define SC_AC_SYMBOLIC			0x00000010 /* internal use only */
#define SC_AC_SEN                       0x00000020 /* Security Environment. */
#define SC_AC_SCB                       0x00000040 /* IAS/ECC SCB byte. */
#define SC_AC_IDA                       0x00000080 /* PKCS#15 authentication ID */
#define SC_AC_SESSION			0x00000100 /* Session PIN */
#define SC_AC_CONTEXT_SPECIFIC		0x00000200 /* Context specific login */

#define SC_AC_UNKNOWN			0xFFFFFFFE
#define SC_AC_NEVER			0xFFFFFFFF

/* Operations relating to access control */
#define SC_AC_OP_SELECT			0
#define SC_AC_OP_LOCK			1
#define SC_AC_OP_DELETE			2
#define SC_AC_OP_CREATE			3
#define SC_AC_OP_REHABILITATE		4
#define SC_AC_OP_INVALIDATE		5
#define SC_AC_OP_LIST_FILES		6
#define SC_AC_OP_CRYPTO			7
#define SC_AC_OP_DELETE_SELF		8
#define SC_AC_OP_PSO_DECRYPT		9
#define SC_AC_OP_PSO_ENCRYPT		10
#define SC_AC_OP_PSO_COMPUTE_SIGNATURE	11
#define SC_AC_OP_PSO_VERIFY_SIGNATURE	12
#define SC_AC_OP_PSO_COMPUTE_CHECKSUM	13
#define SC_AC_OP_PSO_VERIFY_CHECKSUM	14
#define SC_AC_OP_INTERNAL_AUTHENTICATE	15
#define SC_AC_OP_EXTERNAL_AUTHENTICATE	16
#define SC_AC_OP_PIN_DEFINE		17
#define SC_AC_OP_PIN_CHANGE		18
#define SC_AC_OP_PIN_RESET		19
#define SC_AC_OP_ACTIVATE		20
#define SC_AC_OP_DEACTIVATE		21
#define SC_AC_OP_READ			22
#define SC_AC_OP_UPDATE			23
#define SC_AC_OP_WRITE			24
#define SC_AC_OP_RESIZE			25
#define SC_AC_OP_GENERATE		26
#define SC_AC_OP_CREATE_EF		27
#define SC_AC_OP_CREATE_DF		28
#define SC_AC_OP_ADMIN			29
#define SC_AC_OP_PIN_USE		30
/* If you add more OPs here, make sure you increase SC_MAX_AC_OPS*/
#define SC_MAX_AC_OPS			31

/* the use of SC_AC_OP_ERASE is deprecated, SC_AC_OP_DELETE should be used
 * instead  */
#define SC_AC_OP_ERASE			SC_AC_OP_DELETE

#define SC_AC_KEY_REF_NONE	0xFFFFFFFF

 /* Different APDU cases */
#define SC_APDU_CASE_NONE		0x00
#define SC_APDU_CASE_1			0x01
#define SC_APDU_CASE_2_SHORT		0x02
#define SC_APDU_CASE_3_SHORT		0x03
#define SC_APDU_CASE_4_SHORT		0x04
#define SC_APDU_SHORT_MASK		0x0f
//#define SC_APDU_EXT			0x10
//#define SC_APDU_CASE_2_EXT		SC_APDU_CASE_2_SHORT | SC_APDU_EXT
//#define SC_APDU_CASE_3_EXT		SC_APDU_CASE_3_SHORT | SC_APDU_EXT
//#define SC_APDU_CASE_4_EXT		SC_APDU_CASE_4_SHORT | SC_APDU_EXT
 /* following types let OpenSC decides whether to use short or extended APDUs */
#define SC_APDU_CASE_2			0x22
#define SC_APDU_CASE_3			0x23
#define SC_APDU_CASE_4			0x24

 /* use command chaining if the Lc value is greater than normally allowed */
#define SC_APDU_FLAGS_CHAINING		0x00000001UL
 /* do not automatically call GET RESPONSE to read all available data */
#define SC_APDU_FLAGS_NO_GET_RESP	0x00000002UL
 /* do not automatically try a re-transmit with a new length if the card
 * returns 0x6Cxx (wrong length)
 */
#define SC_APDU_FLAGS_NO_RETRY_WL	0x00000004UL
 /* APDU is from Secure Messaging  */
#define SC_APDU_FLAGS_NO_SM		0x00000008UL

#define SC_APDU_ALLOCATE_FLAG		0x01
#define SC_APDU_ALLOCATE_FLAG_DATA	0x02
#define SC_APDU_ALLOCATE_FLAG_RESP	0x04

enum
{
    TMC_CARDCTL_PKCS11_INIT_TOKEN = 0
};


/* Control reference template */
struct tmc_crt {
    unsigned tag;
    unsigned usage;		/* Usage Qualifier Byte */
    unsigned algo;		/* Algorithm ID */
    unsigned refs[8];	/* Security Object References */
};

typedef struct tmc_acl_entry {
    unsigned int method;	/* See SC_AC_* */
    unsigned int key_ref;	/* SC_AC_KEY_REF_NONE or an integer */

    struct tmc_crt crts[SC_MAX_CRTS_IN_SE];

    struct tmc_acl_entry *next;
} sc_acl_entry_t;

struct tmc_lv_data {
    unsigned char *value;
    int len;
};

struct tmc_tlv_data {
    unsigned tag;
    unsigned char *value;
    int len;
};

struct tmc_object_id {
    int value[SC_MAX_OBJECT_ID_OCTETS];
};


typedef struct tmc_aid {
    unsigned char value[SC_MAX_AID_SIZE];
    int len;
}tmc_aid_t;

/* Issuer ID */
struct tmc_iid {
    unsigned char value[SC_MAX_IIN_SIZE];
    int len;
};


typedef struct tmc_path {
    u8 value[SC_MAX_PATH_SIZE];
    size_t len;

    /* The next two fields are used in PKCS15, where
     * a Path object can reference a portion of a file -
     * count octets starting at offset index.
     */
    int index;
    int count;

    int type;

    struct tmc_aid aid;
} tmc_path_t;

#define TMC_MAX_DF_NUM 16
enum
{
    TMC_FILE_MF = 0,
    TMC_FILE_DDF,
    TMC_FILE_ADF,
};
//待确定SE上文件系统
struct tmc_file_info{
	int type;
	tmc_aid_t aid;
    void * tmc_ef;
	int ef_num;
    struct tmc_file_info * file_list[TMC_MAX_DF_NUM];
    int df_num;
    struct tmc_file_info * parent;
};

typedef struct tmc_file {
    struct tmc_path path;
    unsigned int flag;
} tmc_file_t;

//会参考如下文件系统
typedef struct sc_file {
    struct tmc_path path;
    unsigned char name[16];	/* DF name */
    int namelen; /* length of DF name */

    unsigned int type, ef_structure, status; /* See constant values defined above */
    unsigned int shareable;                  /* true(1), false(0) according to ISO 7816-4:2005 Table 14 */
    int size;	/* Size of file (in bytes) */
    int id;		/* file identifier (2 bytes) */
    int sid;	/* short EF identifier (1 byte) */
    struct sc_acl_entry *acl[SC_MAX_AC_OPS]; /* Access Control List */

    int record_length; /* In case of fixed-length or cyclic EF */
    int record_count;  /* Valid, if not transparent EF or DF */

    unsigned char *sec_attr;	/* security data in proprietary format. tag '86' */
    int sec_attr_len;

    unsigned char *prop_attr;	/* proprietary information. tag '85'*/
    int prop_attr_len;

    unsigned char *type_attr;	/* file descriptor data. tag '82'.
					   replaces the file's type information (DF, EF, ...) */
    int type_attr_len;

    unsigned char *encoded_content;	/* file's content encoded to be used in the file creation command */
    int encoded_content_len;	/* size of file's encoded content in bytes */

    unsigned int magic;
} sc_file_t;
//
typedef struct tmc_apdu {
    int cse;			/* APDU case */
    unsigned char cla, ins, p1, p2;	/* CLA, INS, P1 and P2 bytes */
    int lc, le;			/* Lc and Le bytes */
    const unsigned char *data;	/* S-APDU data */
    unsigned int datalen;			/* length of data in S-APDU */
    unsigned char *resp;		/* R-APDU data buffer */
    unsigned int resplen;			/* in: size of R-APDU buffer,
					 * out: length of data returned in R-APDU */
    unsigned char control;		/* Set if APDU should go to the reader */
    unsigned allocation_flags;	/* APDU allocation flags */

    unsigned int sw1, sw2;		/* Status words returned in R-APDU */
    unsigned char mac[8];
    int mac_len;

    unsigned long flags;

    struct tmc_apdu *next;
} tmc_apdu_t;


struct tmc_ec_parameters {
    char *named_curve;
    struct tmc_object_id id;
    struct tmc_lv_data der;

    int type;
    int field_length;
};

struct tmc_sm2_parameters {
    char *named_curve;
    struct tmc_object_id id;
    struct tmc_lv_data der;

    int type;
    int field_length;
};


typedef struct tmc_algorithm_info {
    unsigned int algorithm;
    unsigned int key_length;
    unsigned int flags;

    union {
        struct tmc_rsa_info {
            unsigned long exponent;
        } _rsa;
        struct tmc_ec_info {
            unsigned ext_flags;
                struct tmc_ec_parameters params;
        } _ec;
	 struct tmc_sm2_info {
            unsigned ext_flags;
                struct tmc_sm2_parameters params;
        } _sm2;
    } u;
} tmc_algorithm_info_t;

/* Discretionary ASN.1 data object */
struct tmc_ddo {
    struct tmc_aid aid;
    struct tmc_iid iid;
    struct tmc_object_id oid;

    int len;
    unsigned char *value;
};


typedef struct tmc_app_info {
    char *label;

    struct tmc_aid aid;
    struct tmc_ddo ddo;

    struct tmc_path path;

    int rec_nr;		/* -1, if EF(DIR) is transparent */
} tmc_app_info_t;

struct tmc_ef_atr {
    unsigned char card_service;
    unsigned char df_selection;
    int unit_size;
    unsigned char card_capabilities;
    int max_command_apdu;
    int max_response_apdu;

    struct tmc_aid aid;

    unsigned char pre_issuing[6];
    int pre_issuing_len;

    unsigned char issuer_data[16];
    int issuer_data_len;

    struct tmc_object_id allocation_oid;

    unsigned status;
};


#ifdef __cplusplus
}
#endif

#endif //TMC_PKCS11_TYPES_H

