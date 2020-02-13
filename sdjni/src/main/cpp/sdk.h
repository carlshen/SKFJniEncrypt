/*
 * Copyright (C) 2018 TMC
 */

#ifndef UNTITLED_SDK_H
#define UNTITLED_SDK_H

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#include "simclist.h"
#include "errors.h"
#include "types.h"
#include "flag.h"
#include "pkcs11.h"


#define CRYPTOKI_EXPORTS

#ifndef TMC_SDK_VERSION_MAJOR
#define TMC_SDK_VERSION_MAJOR 0
#endif

#ifndef TMC_SDK_VERSION_MINOR
#define TMC_SDK_VERSION_MINOR 1
#endif

#ifndef TMC_SDK_VS_FF_COMPANY_NAME
#define TMC_SDK_VS_FF_COMPANY_NAME  "TMC SDK Project"
#endif

#ifndef TMC_SDK_VS_FF_PRODUCT_NAME
#define TMC_SDK_VS_FF_PRODUCT_NAME  "TMC SE framework"
#endif


//#define ENABLE_PCSC
//#define ENABLE_IIC

#define RAS_PI
#define APDU_PRINT

#ifndef ENABLE_PCSC
#ifndef ENABLE_IIC
#define ENABLE_SPI
#endif
#endif

#define SIZE_CKA_TYPE sizeof(CK_ATTRIBUTE_TYPE)
#define SIZE_CK_ULONG sizeof(CK_ULONG)
#define RSA_KEY_TYPE_ND 1UL
#define RSA_KEY_TYPE_CRT 2UL
#define ENC_KEY_BLOCK_SIZE 16UL
#define RSA_PUB_EXP_LEN 4UL
#define SM2_PAD_LEN 96UL

typedef struct tmc_thread_context {
    /** the version number of this structure (0 for this version) */
    unsigned int ver;
    /** creates a mutex object */
    int (*create_mutex)(void **);
    /** locks a mutex object (blocks until the lock has been acquired) */
    int (*lock_mutex)(void *);
    /** unlocks a mutex object  */
    int (*unlock_mutex)(void *);
    /** destroys a mutex object */
    int (*destroy_mutex)(void *);
    /** returns unique identifier for the thread (can be NULL) */
    unsigned long (*thread_id)(void);
} tmc_thread_context_t;

typedef struct tmc_context {
    char *app_name;
    unsigned long flags;

    struct tmc_driver *driver;
    void *drv_data;

    struct tmc_thread_context *thread_ctx;
    void *mutex;
}tmc_context_t;

typedef struct {
    /** version number of this structure (0 for this version) */
    unsigned int  ver;
    /** name of the application (used for finding application
     *  dependent configuration data). If NULL the name "default"
     *  will be used. */
    const char    *app_name;
    /** context flags */
    unsigned long flags;
    /** mutex functions to use (optional) */
    tmc_thread_context_t *thread_ctx;
} tmc_context_param_t;

struct tmc_pkcs11_login {
    CK_USER_TYPE userType;
    CK_CHAR_PTR pPin;
    CK_ULONG ulPinLen;
};

/* If the slot did already show with `C_GetSlotList`, then we need to keep this
 * slot alive. PKCS#11 2.30 allows allows adding but not removing slots until
 * the application calls `C_GetSlotList` with `NULL`. This flag tracks the
 * visibility to the application */
//#define SC_PKCS11_SLOT_FLAG_SEEN 1

typedef struct tmc_pkcs11_slot {
    CK_SLOT_ID id;			/* ID of the slot */
    int login_user;			/* Currently logged in user */
    CK_SLOT_INFO slot_info;		/* Slot specific information (information about reader) */
    CK_TOKEN_INFO token_info;	/* Token specific information (information about card) */
    struct tmc_pkcs11_card *p11card;	/* The card associated with this slot */
    unsigned int events;		/* Card events SC_EVENT_CARD_{INSERTED,REMOVED} */
    void *fw_data;			/* Framework specific data, for TMC_SE, contain auth object*/  /* TODO: get know how it used */
    list_t objects;			/* Objects in this slot */
    unsigned int nsessions;		/* Number of sessions using this slot */
    int64_t slot_state_expires;

    //int fw_data_idx;		/* Index of framework data */
    struct tmc_app_info *app_info;	/* Application associated to slot */
    list_t logins;			/* tracks all calls to C_Login if atomic operations are requested */
    int flags;
} tmc_pkcs11_slot_t;

#define SC_PKCS11_FRAMEWORK_DATA_MAX_NUM	4
typedef struct tmc_pkcs11_card {
    struct tmc_card *card;
    struct tmc_pkcs11_framework_ops *framework;
    struct tmc_fw_data *fws_data; /*Framework data, for TMC_SE, contain internal card structure*/

    /* List of supported mechanisms */
    struct tmc_pkcs11_mechanism_type **mechanisms;
    unsigned int nmechanisms;
}tmc_pkcs11_card_t;

/*
 * PKCS#11 smart card Framework abstraction
 */

struct tmc_pkcs11_framework_ops {
    /* Detect and bind card to framework */
    /*for TMC_SE, there is only one type token,
     if you want to extend, change bind & create token
     method --- add a parameter contain applet info*/
    CK_RV (*bind)(struct tmc_pkcs11_card *);
    /* Unbind and release allocated resources */
    CK_RV (*unbind)(struct tmc_pkcs11_card *);

    /* Create tokens to virtual slots and
     * objects in tokens; called after bind */
    CK_RV (*create_tokens)(struct tmc_pkcs11_card *);
    CK_RV (*release_token)(struct tmc_pkcs11_card *, void *);

    /* Login and logout */
    CK_RV (*login)(struct tmc_pkcs11_slot *,
                   CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG);
    CK_RV (*logout)(struct tmc_pkcs11_slot *);
    CK_RV (*change_pin)(struct tmc_pkcs11_slot *,
						CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG);
    /*
     * In future: functions to create new objects (i.e. certificates, private keys)
     */
    CK_RV (*init_token)(struct tmc_pkcs11_slot *,
                        CK_UTF8CHAR_PTR, CK_ULONG,
                        CK_UTF8CHAR_PTR);
    CK_RV (*init_pin)(struct tmc_pkcs11_slot *,
                      CK_UTF8CHAR_PTR, CK_ULONG);
    CK_RV (*create_object)(CK_SESSION_HANDLE,
                           CK_ATTRIBUTE_PTR, CK_ULONG,
                           CK_OBJECT_HANDLE_PTR);
    CK_RV (*gen_keypair)(CK_SESSION_HANDLE,
                         CK_MECHANISM_PTR,
                         CK_ATTRIBUTE_PTR, CK_ULONG,
                         CK_ATTRIBUTE_PTR, CK_ULONG,
                         CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR);
    CK_RV (*gen_key)(CK_SESSION_HANDLE,
                           CK_MECHANISM_PTR,
                           CK_ATTRIBUTE_PTR, CK_ULONG,
                           CK_OBJECT_HANDLE_PTR);
    CK_RV (*read_objects)(struct tmc_pkcs11_slot *);};

struct tmc_pkcs11_operation;
struct tmc_pkcs11_object;

/* This describes a PKCS11 mechanism */
typedef struct tmc_pkcs11_mechanism_type {
    CK_MECHANISM_TYPE mech;		/* algorithm: md5, sha1, ... */
    CK_MECHANISM_INFO mech_info;	/* mechanism info */
    CK_MECHANISM_TYPE key_type;	/* for sign/decipher ops */
    unsigned int	  obj_size;

    /* General management */
    void		  (*release)(struct tmc_pkcs11_operation *);

    /* Digest/sign Operations */
    CK_RV		  (*md_init)(struct tmc_pkcs11_operation *);
    CK_RV		  (*md_update)(struct tmc_pkcs11_operation *,
                                CK_BYTE_PTR, CK_ULONG);
    CK_RV		  (*md_final)(struct tmc_pkcs11_operation *,
                               CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV		  (*sign_init)(struct tmc_pkcs11_operation *,
                                struct tmc_pkcs11_object *);
    CK_RV		  (*sign_update)(struct tmc_pkcs11_operation *,
                                  CK_BYTE_PTR, CK_ULONG);
    CK_RV		  (*sign_final)(struct tmc_pkcs11_operation *, CK_ULONG ulModLen,
                                 CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV		  (*sign_size)(struct tmc_pkcs11_operation *,
                                CK_ULONG_PTR);
    CK_RV		  (*verif_init)(struct tmc_pkcs11_operation *,
                                 struct tmc_pkcs11_object *);
    CK_RV		  (*verif_update)(struct tmc_pkcs11_operation *,
                                   CK_BYTE_PTR, CK_ULONG);
    CK_RV		  (*verif_final)(struct tmc_pkcs11_operation *,
                                  CK_BYTE_PTR, CK_ULONG);
    CK_RV		  (*decrypt_init)(struct tmc_pkcs11_operation *,
                                   struct tmc_pkcs11_object *);
    CK_RV		  (*decrypt)(struct tmc_pkcs11_operation *,
                              CK_BYTE_PTR, CK_ULONG,
                              CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV		  (*decryptUpdate)(struct tmc_pkcs11_operation *,
                                    CK_BYTE_PTR, CK_ULONG,
                                    CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV		  (*decryptFinal)(struct tmc_pkcs11_operation *,
                                   CK_BYTE_PTR, CK_ULONG_PTR);
     CK_RV		  (*encrypt_init)(struct tmc_pkcs11_operation *,
                                   struct tmc_pkcs11_object *);
    CK_RV		  (*encrypt)(struct tmc_pkcs11_operation *,
                              CK_BYTE_PTR, CK_ULONG,
                              CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV		  (*encryptUpdate)(struct tmc_pkcs11_operation *,
                                    CK_BYTE_PTR, CK_ULONG,
                                    CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV		  (*encryptFinal)(struct tmc_pkcs11_operation *,
                                   CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV		  (*derive)(struct tmc_pkcs11_operation *,
                             struct tmc_pkcs11_object *,
                             CK_OBJECT_HANDLE_PTR);
    /* mechanism specific data */
    const void *  mech_data;
    /* free mechanism specific data */
    void		  (*free_mech_data)(const void *mech_data);
}tmc_pkcs11_mechanism_type_t;

/* This describes a PKCS11 operation */
typedef struct tmc_pkcs11_operation {
    struct tmc_pkcs11_mechanism_type *type; /*contain mech methods and attribute*/
    CK_MECHANISM	  mechanism; /*contain mech type*/
    struct tmc_pkcs11_session *session; /*session which contain this mech*/
    void *		  priv_data;
}tmc_pkcs11_operation_t;

static struct ec_curve_info {
    const char *name;
    const char *oid;
    const char *oid_encoded;
    size_t size;
} ec_curve_infos[] = {
        {"secp256k1",		"1.3.132.0.10", "\x06\x05\x2B\x81\x04\x00\x0A", 256},
};

typedef struct tmc_object {
	CK_OBJECT_CLASS objClass;
	CK_KEY_TYPE keyType;
	CK_BBOOL isPriv;
	CK_ULONG attrsLen;
	CK_BYTE_PTR pValue;
	CK_ULONG valueLen;
	CK_BYTE_PTR pKeyParam;
	CK_ULONG keyParamLen;
}tmc_object_t;

/*
 * Generic operation
 */

enum {
    SC_PKCS11_OPERATION_FIND = 0,
    SC_PKCS11_OPERATION_SIGN,
    SC_PKCS11_OPERATION_VERIFY,
    SC_PKCS11_OPERATION_DIGEST,
    SC_PKCS11_OPERATION_ENCRYPT,
    SC_PKCS11_OPERATION_DECRYPT,
    SC_PKCS11_OPERATION_DERIVE,
    SC_PKCS11_OPERATION_MAX
};

/* Find Operation */
#define SC_PKCS11_FIND_INC_HANDLES	32
struct tmc_pkcs11_find_operation {
    struct tmc_pkcs11_operation operation;
    int num_handles, current_handle, allocated_handles;
    CK_OBJECT_HANDLE *handles;
};

struct tmc_pkcs11_session {
    CK_SESSION_HANDLE handle;
    /* Session to this slot */
    struct tmc_pkcs11_slot *slot;
    CK_FLAGS flags;
    int id; // DDF id for this session
    /* Notifications */
    CK_NOTIFY notify_callback;
    CK_VOID_PTR notify_data;
    /* Active operations - one per type */
    struct tmc_pkcs11_operation *operation[SC_PKCS11_OPERATION_MAX];
};

struct tmc_pin_cmd_pin {
    const char *prompt;	/* Prompt to display */

    const unsigned char *data;		/* PIN, if given by the application */
    int len;		/* set to -1 to get pin from pin pad */

    size_t min_length;	/* min length of PIN */
    size_t max_length;	/* max length of PIN */
    size_t stored_length;	/* stored length of PIN */

    unsigned int encoding;	/* ASCII-numeric, BCD, etc */

    size_t pad_length;	/* filled in by the card driver */
    unsigned char pad_char;

    size_t offset;		/* PIN offset in the APDU */
    size_t length_offset;	/* Effective PIN length offset in the APDU */

    int max_tries;	/* Used for signaling back from SC_PIN_CMD_GET_INFO */
    int tries_left;	/* Used for signaling back from SC_PIN_CMD_GET_INFO */
    int logged_in;	/* Used for signaling back from SC_PIN_CMD_GET_INFO */

    struct tmc_acl_entry acls[SC_MAX_SDO_ACLS];
};
struct tmc_int_fw_data{
    CK_BBOOL pin;
    struct tmc_aid * aid;
};

struct tmc_pin_cmd_data {
    unsigned int cmd;
    unsigned int flags;

    unsigned int pin_type;		/* usually SC_AC_CHV */
    int pin_reference;

    struct tmc_pin_cmd_pin pin1, pin2;

    struct tmc_apdu *apdu;		/* APDU of the PIN command */
};

struct tmc_driver {
    const char *name;
    const char *short_name;
    struct tmc_driver_operations *ops;

    void *dll;
};

struct tmc_driver_operations{

    /* Called during sc_establish_context(), when the driver
	 * is loaded */
    int (*init)(struct tmc_context *ctx);
    /* Called when the driver is being unloaded.  finish() has to
     * release any resources. */
    int (*finish)(struct tmc_context *ctx);
    /* Called when library wish to detect new readers
     * should add only new readers. */
    int (*detect_cards)(struct tmc_context *ctx);
    int (*cancel)(struct tmc_context *ctx);
    /* Called when releasing a reader.  release() has to
     * deallocate the private data.  Other fields will be
     * freed by OpenSC. */
    int (*release)(struct tmc_context *ctx);

    int (*detect_card_presence)(struct tmc_context *ctx);
    int (*connect)(void);
    int (*disconnect)(struct tmc_context *ctx);
    int (*transmit)(struct tmc_context *ctx, tmc_apdu_t *apdu);
    int (*lock)(struct tmc_context *ctx);
    int (*unlock)(struct tmc_context *ctx);
    int (*set_protocol)(struct tmc_context *ctx, unsigned int proto);
    /* Pin pad functions */
    int (*display_message)(struct tmc_context *, const char *);
    int (*perform_verify)(struct tmc_context *, struct tmc_pin_cmd_data *);
    int (*perform_pace)(struct tmc_context *reader,
                        void *establish_pace_channel_input,
                        void *establish_pace_channel_output);

    /* Wait for an event */
    int (*wait_for_event)(struct tmc_context *ctx, unsigned int event_mask,
                          unsigned int *event,
                          int timeout);
    /* Reset a reader */
    int (*reset)(struct tmc_context *);
    /* Used to pass in PC/SC handles to minidriver */
    int (*use_reader)(struct tmc_context *ctx, void *pcsc_context_handle, void *pcsc_card_handle);
};

/*
 * PKCS#11 card abstraction layer
 */

typedef struct tmc_object_attr {
    u16 fid;
    u8 type;
    u8 ac;
    u32 size_attri;
    u32 size_data;
} tmc_object_attr_t;

typedef struct tmc_bin_attr {
    u16 fid;
    u8 type;
    u8 ac;
    u32 size_attri;
    u32 size_data;
} tmc_bin_attr_t;

typedef struct tmc_val {
    u8 *data;
    CK_ULONG length;
} tmc_val_t;

typedef union tmc_key {
	u16 fid;
	tmc_val_t value;
} tmc_key_t;

typedef struct tmcse_key{
	CK_BBOOL isToken;
	union tmc_key key;
} tmcse_key_t;

typedef struct tmcse_gcm_param {
    u8 *iv;
    CK_ULONG ivlen;
    u8 *aad;
    CK_ULONG aadlen;
}tmcse_gcm_param_t;

typedef struct tmcse_pin_info{
	u8 maxTryCounter;
	u8 curTryCounter;
	u8 isDefault;
} tmcse_pin_info_t;

struct tmc_card_operations {
	CK_RV (*init)(struct tmc_card *card);
	CK_RV (*create_alg)(struct tmc_card *card, u16 alg_id);
	CK_RV (*create_df)(struct tmc_card *card, u16 fid, u8 *aid, CK_ULONG length);
	CK_RV (*create_pin)(struct tmc_card *card, u16 fid);
	CK_RV (*create_bin)(struct tmc_card *card, u16 fid, CK_ULONG size);
	CK_RV (*create_object)(struct tmc_card *card, u16 fid, u8 objtype, u8 ac, CK_ULONG attr_size, CK_ULONG data_size);
	CK_RV (*delete_file)(struct tmc_card *card, u16 fid);
	CK_RV (*select_MF)(struct tmc_card *card);
	CK_RV (*select_fid)(struct tmc_card *card, u16 fid);
	CK_RV (*select_file)(struct tmc_card *card, u8 *aid, CK_ULONG length, u8 *resp, CK_ULONG *resp_len);
	CK_RV (*write_pin)(struct tmc_card *card, CK_ULONG pintype, u8 trylimit, u8 *pin, CK_ULONG length);
	CK_RV (*read_binary)(struct tmc_card *card, u16 fid, CK_ULONG offset, CK_ULONG length, u8 *bin);
	CK_RV (*update_binary)(struct tmc_card *card, u16 fid, CK_ULONG offset, u8 *bin, CK_ULONG length);
	CK_RV (*read_binary_sfi)(struct tmc_card *card, u8 sfi, CK_ULONG offset, CK_ULONG length, u8 *bin);
	CK_RV (*update_binary_sfi)(struct tmc_card *card, u8 sfi, CK_ULONG offset, u8 *bin, CK_ULONG length);
	CK_RV (*read_object)(struct tmc_card *card, u16 fid, u8 zone, u8 *value, CK_ULONG *length);
	CK_RV (*update_object)(struct tmc_card *card, u16 fid, u8 zone, CK_ULONG offset, CK_ULONG length, u8 *value);
	CK_RV (*end_personal)(struct tmc_card *card);

	//pin operation
	CK_RV (*verify_pin)(struct tmc_card *card, CK_ULONG pintype, u8 *pin, CK_ULONG length);
	CK_RV (*change_pin)(struct tmc_card *card, CK_ULONG pintype, u8 *pin, CK_ULONG length);
	CK_RV (*verify_tk)(struct tmc_card *card, u8 *pin, CK_ULONG length);
	CK_RV (*change_tk)(struct tmc_card *card, u8 *pin, CK_ULONG length);
	CK_RV (*get_pin_info)(struct tmc_card *card, CK_ULONG pintype, struct tmcse_pin_info *info);
	CK_RV (*clear_pin_state)(struct tmc_card *card);

	//key operation
	CK_RV (*generate_key)(struct tmc_card *card, CK_ULONG mechanism, CK_ULONG bitlengh, u16 fid);
	CK_RV (*generate_key_ex)(struct tmc_card *card, CK_ULONG mechanism, CK_ULONG bitlengh, u8 *key, CK_ULONG *key_len);
	CK_RV (*generate_keypair)(struct tmc_card *card, CK_ULONG mechanism, CK_ULONG bitlengh, CK_ULONG keytype, u8* param, CK_ULONG param_len, u16 pub_fid, u16 pri_fid);
	CK_RV (*generate_keypair_ex)(struct tmc_card *card, CK_ULONG mechanism, CK_ULONG bitlengh, CK_ULONG keytype, u8* param, CK_ULONG param_len, u8 *pubkey, CK_ULONG *pubkey_len, u8 *prikey, CK_ULONG *prikey_len);
	CK_RV (*import_key)(struct tmc_card *card, CK_ULONG algtype, u8 *key, CK_ULONG key_len, u16 fid);
	CK_RV (*import_pubkey)(struct tmc_card *card, CK_ULONG algtype, u8* param, CK_ULONG param_len, u8 *key, CK_ULONG key_len, u16 fid);
	CK_RV (*import_prikey)(struct tmc_card *card, CK_ULONG algtype, CK_ULONG keytype, u8* param, CK_ULONG param_len, u8 *key, CK_ULONG key_len, u16 fid);
	CK_RV (*enc_key)(struct tmc_card *card, u8 *key, CK_ULONG key_len, u8 *cipherkey, CK_ULONG *cipherkey_len);
	CK_RV (*export_pubkey)(struct tmc_card *card, u16 fid, u8 *key, CK_ULONG *key_len);
	CK_RV (*wrap_key)(struct tmc_card *card, tmcse_key_t *key, u8 *wrapkey, CK_ULONG wrapkey_len, u8 * wrappedkey, CK_ULONG * wrappedkey_len);
	CK_RV (*unwrap_key)(struct tmc_card *card, u8 *wrappedkey, CK_ULONG wrappedkey_len, tmcse_key_t *prikey, u16 fid);
	CK_RV (*unwrap_key_ex)(struct tmc_card *card, u8 * wrappedkey, CK_ULONG * wrappedkey_len, tmcse_key_t *prikey, u8 *key, CK_ULONG *key_len);
	CK_RV (*ecc_exchangekey)(struct tmc_card *card, CK_ULONG algtype, u16 pri_fid, u8 *pubkey, CK_ULONG pub_len, u16 fid);
	CK_RV (*ecc_exchangekey_ex)(struct tmc_card *card, CK_ULONG algtype, u16 pri_fid, u8 *pubkey, CK_ULONG pub_len, u8 *key, CK_ULONG *key_len);
	CK_RV (*sm2_exchangekey)(struct tmc_card *card, CK_ULONG algtype, u16 pub_fid, u16 pri_fid, u8 *idA, CK_ULONG lenA, u8 *pubkey, CK_ULONG pub_len, u8 *idB, CK_ULONG lenB, u16 fid);
	CK_RV (*sm2_exchangekey_ex)(struct tmc_card *card, CK_ULONG algtype, u16 pub_fid, u16 pri_fid, u8 *idA, CK_ULONG lenA, u8 *pubkey, CK_ULONG pub_len, u8 *idB, CK_ULONG lenB, u8 *key, CK_ULONG *key_len);
	CK_RV (*dh_exchangekey)(struct tmc_card *card, CK_ULONG algtype, u16 pri_fid, u8 *pubkey, CK_ULONG pub_len, u16 fid);
	CK_RV (*dh_exchangekey_ex)(struct tmc_card *card, CK_ULONG algtype, u16 pri_fid, u8 *pubkey, CK_ULONG pub_len, u8 *key, CK_ULONG *key_len);

	//alg operation
	CK_RV (*enc_data)(struct tmc_card *card, CK_ULONG mechanism, tmcse_key_t *key, u8 *plain, CK_ULONG length, u8 *iv, CK_ULONG ivlen, u8 *cipher, CK_ULONG *cipher_len);
	CK_RV (*dec_data)(struct tmc_card *card, CK_ULONG mechanism, tmcse_key_t *key, u8 *cipher, CK_ULONG length, u8 *iv, CK_ULONG ivlen, u8 *plain, CK_ULONG *plain_len);
	CK_RV (*encrypt)(struct tmc_card *card, CK_ULONG mechanism, CK_ULONG keytype, tmcse_key_t *key, u8 *plain, CK_ULONG length, u8 *cipher, CK_ULONG *cipher_len);
	CK_RV (*decrypt)(struct tmc_card *card, CK_ULONG mechanism, CK_ULONG keytype, tmcse_key_t *key, u8 *cipher, CK_ULONG length, u8 *plain, CK_ULONG *plain_len);
	CK_RV (*sign_data)(struct tmc_card *card, CK_ULONG mechanism, CK_ULONG keytype, tmcse_key_t *key, u8 *hash, CK_ULONG length, u8 *signature, CK_ULONG *sign_len);
	CK_RV (*verify_sign)(struct tmc_card *card, CK_ULONG mechanism, tmcse_key_t *key, u8 *hash, CK_ULONG length, u8 *signature, CK_ULONG sign_len);
	CK_RV (*hash_data)(struct tmc_card *card, CK_ULONG mechanism, u8 *data, CK_ULONG length, u8 *hash, CK_ULONG *hash_len);

	//other operation
	CK_RV (*get_challenge)(struct tmc_card *card, CK_ULONG length, u8 *random);
	CK_RV (*get_uid)(struct tmc_card *card, u8 *uid, CK_ULONG *length);
	CK_RV (*get_card_state)(struct tmc_card *card, u8 *state);

	CK_RV (*self)(struct tmc_card *card, u8* cmd, u8 cse, CK_BBOOL isReset);

	CK_RV (*finish)(struct tmc_card *card);
};


typedef struct tmc_card {
    struct tmc_context *ctx;

    struct tmc_driver *driver;
    struct tmc_card_operations *ops;
    void *drv_data;
    char *name;

    int cla;
    size_t max_send_size; /* Max Lc supported by the card */
    size_t max_recv_size; /* Max Le supported by the card */

    uint16_t manage_fid;

    //stand for algotithms supported by SE, register when initialization
    struct tmc_algorithm_info *algorithms;
    int algorithm_count;

    int lock_count;

    void *mutex;

} tmc_card_t;

struct tmc_card_error {
    unsigned int SWs;
    CK_RV errorno;
    const char *errorstr;
};

typedef struct tmc_internal_card {
    struct tmc_file_info* file_app;
    tmc_card_t* card;
}tmc_internal_card_t;

#define MAX_OBJECTS	128
#define SE_OBJ_FLAG_ATTR 0x0
#define SE_OBJ_FLAG_VALUE 0x01
#define SE_OBJ_SIZE_RESERVE 0x20//预留空间

typedef struct tmc_fw_data {
    tmc_internal_card_t * 		inter_card;
    unsigned int			num_objects;
    unsigned int			locked;
}tmc_fw_data_t;

/*
 * PKCS#11 Object abstraction layer
 */

struct tmc_pkcs11_object_ops {
    /* Generic operations */
    void (*release)(void *);

    /* Management methods */
    CK_RV (*set_attribute)(struct tmc_pkcs11_session *, void *, CK_ATTRIBUTE_PTR);
    CK_RV (*get_attribute)(struct tmc_pkcs11_session *, void *, CK_ATTRIBUTE_PTR);
    CK_RV (*cmp_attribute)(struct tmc_pkcs11_session *, void *, CK_ATTRIBUTE_PTR);

    CK_RV (*destroy_object)(struct tmc_pkcs11_session *, void *);
    CK_RV (*get_size)(struct tmc_pkcs11_session *, void *);

    /* Cryptographic methods */
    CK_RV (*sign)(struct tmc_pkcs11_session *, void *,
                  CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                  CK_BYTE_PTR pSignature);
    CK_RV (*unwrap_key)(struct tmc_pkcs11_session *, void *,
                        CK_MECHANISM_PTR,
                        CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                        CK_ATTRIBUTE_PTR, CK_ULONG,
                        void **);
    CK_RV (*decrypt)(struct tmc_pkcs11_session *, struct tmc_pkcs11_object *, CK_MECHANISM_PTR, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                     CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);

   CK_RV (*encrypt)(struct tmc_pkcs11_session *, struct tmc_pkcs11_object *,CK_MECHANISM_PTR,CK_BYTE_PTR pData, CK_ULONG pulDataLen,
                      CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR ulEncryptedDataLen);
    CK_RV (*derive)(struct tmc_pkcs11_session *, void *,
                    CK_MECHANISM_TYPE ,CK_MECHANISM_TYPE,
                    CK_BYTE_PTR, CK_ULONG,
                    CK_OBJECT_HANDLE_PTR);

    /* Check compatibility of PKCS#15 object usage and an asked PKCS#11 mechanism. */
    CK_RV (*can_do)(struct tmc_pkcs11_session *, void *, CK_MECHANISM_TYPE, unsigned int);

    /* Others to be added when implemented */
    CK_RV (*signVerify)(struct tmc_pkcs11_session *, struct tmc_pkcs11_object *, CK_BYTE_PTR , CK_ULONG ,
                     CK_BYTE_PTR , CK_ULONG );

    CK_RV(*export_pub)(struct tmc_pkcs11_session *, struct tmc_pkcs11_object *, CK_BYTE_PTR *, CK_ULONG_PTR);
};

typedef struct tmc_pkcs11_object {
    CK_OBJECT_HANDLE handle;
    int flags;
    struct tmc_pkcs11_object_ops *ops;
    list_t attrs;
    uint16_t fid;
    CK_SESSION_HANDLE hSession;
    CK_ULONG keyType;
}tmc_pkcs11_object_t;

#define MAX_ALG_CACHE_SIZE 4096/8

struct signature_data {
    struct tmc_pkcs11_object *key;
    struct hash_signature_info *info;
    tmc_pkcs11_operation_t *	md;
    CK_BYTE			buffer[MAX_ALG_CACHE_SIZE];
    unsigned int		buffer_len;
};



struct agreement_data
{
    struct tmc_pkcs11_object *key;
    //void * domain;
    CK_ATTRIBUTE_PTR pTemplate;
    CK_ULONG ulAttrbuteCount;
    CK_BYTE			buffer[2048/8];
    unsigned int		buffer_len;
};

extern list_t virtual_slots;

#define SHA1_HASH_SIZE 20

/* Hash size in 32-bit words */
#define SHA1_HASH_WORDS 5

struct _SHA1Context {
    uint64_t totalLength;
    uint32_t hash[SHA1_HASH_WORDS];
    uint32_t bufferLength;
    union {
        uint32_t words[16];
        unsigned char bytes[64];
    } buffer;
};

typedef struct _SHA1Context SHA1Context;


#define SHA224_HASH_SIZE 28
#define SHA256_HASH_SIZE 32



/* Hash size in 32-bit words */
#define SHA256_HASH_WORDS 8
#define SHA224_HASH_WORDS 7

struct _SHA256Context {
    uint64_t totalLength;
    uint32_t hash[SHA256_HASH_WORDS];
    uint32_t bufferLength;
    union {
        uint32_t words[16];
        uint8_t bytes[64];
    } buffer;
};

typedef struct _SHA256Context SHA256Context;


#define SHA384_HASH_SIZE 48

/* Hash size in 64-bit words */
#define SHA384_HASH_WORDS 6

struct _SHA384Context {
    uint64_t totalLength[2];
    uint64_t hash[SHA384_HASH_WORDS + 2];
    uint32_t bufferLength;
    union {
        uint64_t words[16];
        uint8_t bytes[128];
    } buffer;
};

typedef struct _SHA384Context SHA384Context;

#define SHA512_HASH_SIZE 64

/* Hash size in 64-bit words */
#define SHA512_HASH_WORDS 8

struct _SHA512Context {
    uint64_t totalLength[2];
    uint64_t hash[SHA512_HASH_WORDS];
    uint32_t bufferLength;
    union {
        uint64_t words[16];
        uint8_t bytes[128];
    } buffer;
};

typedef struct _SHA512Context SHA512Context;

#define SM3_HASH_SIZE 32

typedef struct sm3_state
{
    u_int32_t state[8], len, curlen;
    u_int8_t buf[64];
}SM3_CTX;

/** framework layer **/
extern struct tmc_pkcs11_mechanism_type find_mechanism;

/* context functions */
CK_RV tmc_pkcs11_init_lock(CK_C_INITIALIZE_ARGS_PTR args);
void tmc_pkcs11_free_lock(void);
CK_RV tmc_pkcs11_lock(void);
void tmc_pkcs11_unlock(void);
CK_RV tmc_context_create(tmc_context_t** ctx_out, tmc_context_param_t* ctx_param);
int tmc_release_context(tmc_context_t *ctx);

/* mutex functions */
int tmc_mutex_create(const tmc_context_t *ctx, void **mutex);

/* slot functions */
CK_RV push_login_state(struct tmc_pkcs11_slot *slot,
                       CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV slot_get_token(CK_SLOT_ID id, struct tmc_pkcs11_slot ** slot);
CK_RV create_slot(void);
CK_RV slot_allocate(struct tmc_pkcs11_slot ** slot, struct tmc_pkcs11_card * p11card);
CK_RV get_slot_from_session(CK_SESSION_HANDLE hSession, struct tmc_pkcs11_slot **slot);
/* session functions */
CK_RV create_user_df(struct tmc_pkcs11_slot * slot);
CK_RV tmc_pkcs11_close_all_sessions(CK_SLOT_ID slotID);
CK_RV session_create_DF(struct tmc_pkcs11_session * session,
                        struct tmc_file_info ** file_out);
CK_RV get_session(CK_SESSION_HANDLE hSession, struct tmc_pkcs11_session **session);
CK_RV get_card_by_session(CK_SESSION_HANDLE hSession, struct tmc_card **card);

/* object functions */
CK_RV
get_object_from_session(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                        struct tmc_pkcs11_session **session, struct tmc_pkcs11_object **object);


/* seeker functions */
int session_list_seeker(const void *el, const void *key);
int slot_list_seeker(const void *el, const void *key);
int object_list_seeker(const void *el, const void *key);
int attribute_list_seeker(const void *el, const void *key);

/* driver functions */
int tmc_detect_card_presence(tmc_context_t *ctx);

/*se functions*/
CK_RV se_detect(tmc_context_t *ctx);
CK_RV se_removed(void);

/*process lock functions*/
int tmc_lock(tmc_card_t *card);
int tmc_unlock(tmc_card_t *card);

/*cipher functions*/
CK_RV
rsa_pkcs1_v15_padding(CK_BYTE_PTR pDigest,
					CK_ULONG ulDigestLen,
					CK_ULONG ulRSAModLen,
					CK_BYTE_PTR pDest,
					CK_ULONG_PTR pulDestLen);

CK_RV
tmc_pkcs11_decr_init(struct tmc_pkcs11_session *session,
                     CK_MECHANISM_PTR pMechanism,
                     struct tmc_pkcs11_object *key,
                     CK_MECHANISM_TYPE key_type);
CK_RV 
tmc_pkcs11_decr(struct tmc_pkcs11_session *session,
                CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
CK_RV
tmc_pkcs11_decr_update(struct tmc_pkcs11_session *session,
                       CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                       CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);

CK_RV
tmc_pkcs11_decr_final(struct tmc_pkcs11_session *session,
                      CK_BYTE_PTR pData, CK_ULONG_PTR ulDataLen);

CK_RV
tmc_pkcs11_encr_init(struct tmc_pkcs11_session *session,
                     CK_MECHANISM_PTR pMechanism,
                     struct tmc_pkcs11_object *key,
                     CK_MECHANISM_TYPE key_type);
CK_RV
tmc_pkcs11_encr(struct tmc_pkcs11_session *session,
                CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
CK_RV
tmc_pkcs11_encr_update(struct tmc_pkcs11_session *session,
			CK_BYTE_PTR pData, CK_ULONG ulDataLen,
			CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR ulEncryptedDataLen);
CK_RV
tmc_pkcs11_encr_final(struct tmc_pkcs11_session *session,
			CK_BYTE_PTR pData, CK_ULONG_PTR ulDataLen);

CK_RV
tmc_pkcs11_sign_init(struct tmc_pkcs11_session *session, CK_MECHANISM_PTR pMechanism,
                     struct tmc_pkcs11_object *key, CK_MECHANISM_TYPE key_type);
CK_RV
tmc_pkcs11_sign_size(struct tmc_pkcs11_session *session, CK_ULONG_PTR pLength);
CK_RV
tmc_pkcs11_sign(struct tmc_pkcs11_session *session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_ULONG ulRsaModLen,
                CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
CK_RV
tmc_pkcs11_sign_update(struct tmc_pkcs11_session *session,
                       CK_BYTE_PTR pData, CK_ULONG ulDataLen);
CK_RV
tmc_pkcs11_sign_final(struct tmc_pkcs11_session *session, CK_ULONG ulModLen,
                      CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
CK_RV
tmc_pkcs11_ver_update(struct tmc_pkcs11_session *session,
                      CK_BYTE_PTR pData, CK_ULONG ulDataLen);
CK_RV
tmc_pkcs11_ver_final(struct tmc_pkcs11_session *session,
                     CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);

CK_RV
tmc_pkcs11_ver_init(struct tmc_pkcs11_session *session, CK_MECHANISM_PTR pMechanism,
                    struct tmc_pkcs11_object *key, CK_MECHANISM_TYPE key_type);
CK_RV
tmc_pkcs11_ver(struct tmc_pkcs11_session *session, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
        CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);

CK_RV
tmc_pkcs11_ver_update(struct tmc_pkcs11_session *session,
		      CK_BYTE_PTR pData, CK_ULONG ulDataLen);

CK_RV
tmc_pkcs11_ver_final(struct tmc_pkcs11_session *session,
		     CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);

CK_RV
tmc_pkcs11_digest_init(struct tmc_pkcs11_session *session,
                   CK_MECHANISM_PTR pMechanism);
CK_RV
tmc_pkcs11_digest_update(struct tmc_pkcs11_session *session,
                         CK_BYTE_PTR pData, CK_ULONG ulDataLen);
CK_RV
tmc_pkcs11_digest_final(struct tmc_pkcs11_session *session,
                        CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
CK_RV
tmc_pkcs11_deri(struct tmc_pkcs11_session *session,
                  CK_MECHANISM_PTR pMechanism,
                  struct tmc_pkcs11_object * baseKey,
                  CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount,
                  CK_OBJECT_HANDLE_PTR phKey);
/** operation layer **/
CK_RV session_get_operation(struct tmc_pkcs11_session * session, int type, tmc_pkcs11_operation_t ** operation);

CK_RV tmc_create_head_object(struct tmc_pkcs11_object ** obj);
CK_RV transASN1(CK_BYTE_PTR in, CK_BYTE_PTR out, CK_BBOOL isWrap,
                CK_ULONG_PTR psigLength);

tmc_pkcs11_mechanism_type_t *
tmc_pkcs11_find_mechanism(struct tmc_pkcs11_card *p11card, CK_MECHANISM_TYPE mech, unsigned int flags);

struct tmc_pkcs11_framework_ops* tmc_get_framework_ops(void);
tmc_pkcs11_mechanism_type_t *
tmc_pkcs11_new_fw_mechanism(CK_MECHANISM_TYPE mech,
                            CK_MECHANISM_INFO_PTR pInfo,
                            CK_KEY_TYPE key_type,
                            const void *priv_data,
                            void (*free_priv_data)(const void *priv_data));
CK_RV
tmc_pkcs11_register_mechanism(struct tmc_pkcs11_card *p11card,
                              tmc_pkcs11_mechanism_type_t *mt);


CK_RV tmc_verify_pin(struct tmc_pkcs11_slot * slot,
                     CK_UTF8CHAR_PTR pin, CK_ULONG pLen);

CK_RV session_start_operation(struct tmc_pkcs11_session * session,
                              int type, tmc_pkcs11_mechanism_type_t * mech, struct tmc_pkcs11_operation ** operation);
CK_RV session_stop_operation(struct tmc_pkcs11_session * session, int type);


CK_RV tmc_create_object_int(CK_SESSION_HANDLE hSession,	/* the session's handle */
                            CK_ATTRIBUTE_PTR pTemplate,		/* the object's template */
                            CK_ULONG ulCount,			/* attributes in template */
                            CK_OBJECT_HANDLE_PTR phObject,		/* receives new object's handle. */
                            int use_lock);

CK_RV tmc_pkcs11_get_mechanism_list(struct tmc_pkcs11_card *p11card,
                                    CK_MECHANISM_TYPE_PTR pList,
                                    CK_ULONG_PTR pulCount);
CK_RV tmc_pkcs11_get_mechanism_info(struct tmc_pkcs11_card *p11card,
                                    CK_MECHANISM_TYPE mechanism,
                                    CK_MECHANISM_INFO_PTR pInfo);
void strcpy_bp(u8 * dst, const char *src, size_t dstsize);

void SHA1Init (SHA1Context *sc);
void SHA1Update (SHA1Context *sc, const void *data, uint32_t len);
void SHA1Final (SHA1Context *sc, unsigned char *hash);
void SHA256Init (SHA256Context *sc);
void SHA224Init(SHA256Context *sc);
void SHA256Update (SHA256Context *sc, const void *data, uint32_t len);
void SHA256Final (SHA256Context *sc, unsigned char * hash, int words);
void SHA384Init (SHA384Context *sc);
void SHA384Update (SHA384Context *sc, const void *data, uint32_t len);
void SHA384Final (SHA384Context *sc, unsigned char * hash);
void SHA512Init (SHA512Context *sc);
void SHA512Update (SHA512Context *sc, const void *data, uint32_t len);
void SHA512Final (SHA512Context *sc, unsigned char * hash);
void SM3_Init(void **ctx);
void SM3_Update(void *ctx, const u_int8_t *pInBuf, u_int32_t inLen);
void SM3_Final(void *ctx, u_int8_t *pOutBuf);
/** command layer **/
struct tmc_card_operations* tmc_get_card_driver(void);
int tmc_apdu_to_buf(tmc_apdu_t * apdu, u8 *out);
int tmc_spi_open(void);
int tmc_spi_close(void);
int tmc_spi_send(uint8_t *TxBuf, int len);
int tmc_spi_receive(uint8_t *RxBuf, int* len);
int tmc_spi_wakeup(void);
int tmc_spi_sleep(void);
int tmc_apdu_set_resp(tmc_context_t *ctx, tmc_apdu_t *apdu, const u8 *buf,
                      CK_ULONG len);

int tmc_i2c_open(void);
int tmc_i2c_close(void);
int tmc_i2c_wakeup(void);
int tmc_i2c_sleep(void);
int tmc_i2c_send(uint8_t *TxBuf, int len);
int tmc_i2c_receive(uint8_t *RxBuf, int* len);
void debugPrt(u8* buf, size_t length);
/** driver layer **/
#ifdef ENABLE_PCSC
struct tmc_driver * tmc_get_pcsc_driver(void);
#else
struct tmc_driver * tmc_get_spi_driver(void);
#endif

void tmc_printf_init(void);
void tmc_printf_t(const char *fmt,...);
void tmc_printf(const char *fmt,...);

#define FILE_TYPE_CERT 1
#define FILE_TYPE_PUB 2
#define FILE_TYPE_PRI 3
#define FILE_TYPE_SECRET 4

#define FLAG_UNUSED 0
#define FLAG_USED 1
#define STORE_SESSION 0
#define STORE_TOKEN 1
#define OFF_FILE_TYPE 0
#define OFF_USED_FLAG 1
#define OFF_STORE_TYPE 2
#define OFF_LENGTH 3
#define OFF_VALUE 4
#define TMC_VS_FF_COMPANY_NAME  "Tongxin Microelectronics Company"
#define TMC_VS_FF_PRODUCT_NAME  "TMC PKCS11 SDK"
#define TMC_VERSION_MAJOR  1
#define TMC_VERSION_MINOR  0
#define TMC_SLOT_DESCRIPTION   "TMC Slot"
#define TMC_SLOT_MANUFACTURER_ID  "Tongxin Microelectronics Company"
#define TMC_SLOT_HARDWARE_VERSION_MAJOR 8
#define TMC_SLOT_HARDWARE_VERSION_MINOR 9
#define TMC_SLOT_FIRMWARE_VERSION_MAJOR  1
#define TMC_SLOT_FIRMWARE_VERSION_MINOR  0
#define TMC_TOKEN_LABEL   "T9 Secure Element"
#define TMC_TOKEN_MANUFACTURER_ID   "Tongxin Microelectronics Company"
#define TMC_TOKEN_DEVICE_MODE   "T9"
#define TMC_TOKEN_MAXSESSION_COUNTER   16
#define TMC_TOKEN_SESSION_COUNTER   1
#define TMC_TOKEN_MAXRWSESSION_COUNTER   16
#define TMC_TOKEN_RWSESSION_COUNTER   1
#define TMC_TOKEN_MAX_PIN_LEN     32767
#define TMC_TOKEN_MIN_PIN_LEN     1
#define TMC_TOKEN_TOTAL_PUBLIC_MEMORY   131072
#define TMC_TOKEN_FREE_PUBLIC_MEMORY    131072
#define TMC_TOKEN_TOTAL_PVIVATE_MEMORY   131072
#define TMC_TOKEN_FREE_PVIVATE_MEMORY   131072
#define TMC_TOKEN_HARDWARE_VERSION_MAJOR 8
#define TMC_TOKEN_HARDWARE_VERSION_MINOR 9
#define TMC_TOKEN_FIRMWARE_VERSION_MAJOR 91
#define TMC_TOKEN_FIRMWARE_VERSION_MINOR 40

#endif //UNTITLED_SDK_H
