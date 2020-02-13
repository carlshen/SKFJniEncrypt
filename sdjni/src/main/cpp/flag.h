//
// Created by aoe on 18-8-23.
//

#ifndef SDK_FLAG_H
#define SDK_FLAG_H
/** Stop modifying or using external resources
 *
 * Currently this is used to avoid freeing duplicated external resources for a
 * process that has been forked. For example, a child process may want to leave
 * the duplicated card handles for the parent process. With this flag the child
 * process indicates that shall the reader shall ignore those resources when
 * calling sc_disconnect_card.
 */
#define SC_CTX_FLAG_TERMINATE				0x00000001

/* Event masks for sc_wait_for_event() */
#define SE_EVENT_CARD_INSERTED		0x0001
#define SE_EVENT_CARD_REMOVED		0x0002
#define SE_EVENT_CARD_EVENTS		SE_EVENT_CARD_INSERTED|SE_EVENT_CARD_REMOVED


/**
 * ALGORITHMS
 * */

/* PK algorithms */
#define SC_ALGORITHM_RSA		0
#define SC_ALGORITHM_DSA		1
#define SC_ALGORITHM_EC			2
#define SC_ALGORITHM_GOSTR3410		3
#define SC_ALGORITHM_SM2		3


/* Symmetric algorithms */
#define SC_ALGORITHM_DES		64
#define SC_ALGORITHM_3DES		65
#define SC_ALGORITHM_GOST		66
#define SC_ALGORITHM_AES		67
#define SC_ALGORITHM_SM1		68
#define SC_ALGORITHM_SM4		69



/* Hash algorithms */
#define SC_ALGORITHM_MD5		128
#define SC_ALGORITHM_SHA1		129
#define SC_ALGORITHM_GOSTR3411		130
#define SC_ALGORITHM_SM3		131


/* Key derivation algorithms */
#define SC_ALGORITHM_PBKDF2		192

/* Key encryption algorithms */
#define SC_ALGORITHM_PBES2		256

#define SC_ALGORITHM_ONBOARD_KEY_GEN	0x80000000
/* need usage = either sign or decrypt. keys with both? decrypt, emulate sign */
#define SC_ALGORITHM_NEED_USAGE		0x40000000
#define SC_ALGORITHM_SPECIFIC_FLAGS	0x0001FFFF

#define SC_ALGORITHM_RSA_RAW		0x00000001
/* If the card is willing to produce a cryptogram padded with the following
 * methods, set these flags accordingly. */
#define SC_ALGORITHM_RSA_PADS		0x0000000E
#define SC_ALGORITHM_RSA_PAD_NONE	0x00000000
#define SC_ALGORITHM_RSA_PAD_PKCS1	0x00000002
#define SC_ALGORITHM_RSA_PAD_ANSI	0x00000004
#define SC_ALGORITHM_RSA_PAD_ISO9796	0x00000008

/* If the card is willing to produce a cryptogram with the following
 * hash values, set these flags accordingly. */
#define SC_ALGORITHM_RSA_HASH_NONE	0x00000010
#define SC_ALGORITHM_RSA_HASH_SHA1	0x00000020
#define SC_ALGORITHM_RSA_HASH_MD5	0x00000040
#define SC_ALGORITHM_RSA_HASH_MD5_SHA1	0x00000080
#define SC_ALGORITHM_RSA_HASH_RIPEMD160	0x00000100
#define SC_ALGORITHM_RSA_HASH_SHA256	0x00000200
#define SC_ALGORITHM_RSA_HASH_SHA384	0x00000400
#define SC_ALGORITHM_RSA_HASH_SHA512	0x00000800
#define SC_ALGORITHM_RSA_HASH_SHA224	0x00001000
#define SC_ALGORITHM_RSA_HASHES		0x00001FE0

#define SC_ALGORITHM_GOSTR3410_RAW		0x00002000
#define SC_ALGORITHM_GOSTR3410_HASH_NONE	0x00004000
#define SC_ALGORITHM_GOSTR3410_HASH_GOSTR3411	0x00008000
#define SC_ALGORITHM_GOSTR3410_HASHES		0x00008000
/*TODO: -DEE Should the above be 0x0000E000 */
/* Or should the HASH_NONE be 0x00000010  and HASHES be 0x00008010 */

/* May need more bits if card can do more hashes */
/* TODO: -DEE Will overload RSA_HASHES with EC_HASHES */
/* Not clear if these need their own bits or not */
/* The PIV card does not support and hashes */
#define SC_ALGORITHM_ECDSA_RAW		0x00010000
#define SC_ALGORITHM_ECDH_CDH_RAW	0x00020000
#define SC_ALGORITHM_ECDSA_HASH_NONE		SC_ALGORITHM_RSA_HASH_NONE
#define SC_ALGORITHM_ECDSA_HASH_SHA1		SC_ALGORITHM_RSA_HASH_SHA1
#define SC_ALGORITHM_ECDSA_HASH_SHA224		SC_ALGORITHM_RSA_HASH_SHA224
#define SC_ALGORITHM_ECDSA_HASH_SHA256		SC_ALGORITHM_RSA_HASH_SHA256
#define SC_ALGORITHM_ECDSA_HASH_SHA384		SC_ALGORITHM_RSA_HASH_SHA384
#define SC_ALGORITHM_ECDSA_HASH_SHA512		SC_ALGORITHM_RSA_HASH_SHA512
#define SC_ALGORITHM_ECDSA_HASHES		(SC_ALGORITHM_ECDSA_HASH_SHA1 | \
							SC_ALGORITHM_ECDSA_HASH_SHA224 | \
							SC_ALGORITHM_ECDSA_HASH_SHA256 | \
							SC_ALGORITHM_ECDSA_HASH_SHA384 | \
							SC_ALGORITHM_ECDSA_HASH_SHA512)

#define SC_ALGORITHM_SM2_HASH_SM3_256_E		0x00100000
#define SC_ALGORITHM_SM2_HASH_SM3_256  	       0x00200000

							

/* extended algorithm bits for selected mechs */
#define SC_ALGORITHM_EXT_EC_F_P          0x00000001
#define SC_ALGORITHM_EXT_EC_F_2M         0x00000002
#define SC_ALGORITHM_EXT_EC_ECPARAMETERS 0x00000004
#define SC_ALGORITHM_EXT_EC_NAMEDCURVE   0x00000008
#define SC_ALGORITHM_EXT_EC_UNCOMPRESES  0x00000010
#define SC_ALGORITHM_EXT_EC_COMPRESS     0x00000020

/**
 * APDU
 * */

#define TMC_APDU_MAX 300 //modify by zhangzch 190131 : fix hirain spi received return stack smashing detected

#define TMC_APDU_CASE_1 1
#define TMC_APDU_CASE_2 2
#define TMC_APDU_CASE_3 3
#define TMC_APDU_CASE_4 4

/* If the slot did already show with `C_GetSlotList`, then we need to keep this
 * slot alive. PKCS#11 2.30 allows allows adding but not removing slots until
 * the application calls `C_GetSlotList` with `NULL`. This flag tracks the
 * visibility to the application */
#define SC_PKCS11_SLOT_FLAG_SEEN 1

#endif //SDK_FLAG_H
