/*
 * Copyright (C) 2018 TMC
 */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "sdk.h"
#include "../../../../distribution/tongfang/include/skf_type.h"


#ifndef MODULE_APP_NAME
#define MODULE_APP_NAME "tmc-sdk"
#endif

tmc_context_t *context = NULL;
list_t sessions;
list_t virtual_slots;
pid_t initialized_pid = (pid_t)-1;

static int in_finalize = 0;
CK_FUNCTION_LIST pkcs11_function_list;
/*defined in framework.c*/
extern tmc_thread_context_t tmc_thread_ctx;

//GENERAL FUNCTION
CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	CK_RV rv;
	CK_RV rc;
	pid_t current_pid = getpid();
	tmc_context_param_t ctx_opts;
	struct tmc_pkcs11_session * p_session =	calloc(1, sizeof(struct tmc_pkcs11_session));

	tmc_printf_t("[libsdk]: C_Initialize pInitArgs = %p\n", pInitArgs);

	if(!p_session)
		return CKR_HOST_MEMORY;

	/* Handle fork() exception */
	if (current_pid != initialized_pid) {
		if (context)
			context->flags |= SC_CTX_FLAG_TERMINATE;
	}
	initialized_pid = current_pid;
	in_finalize = 0;

	if (context != NULL) {
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;
	}

	rv = tmc_pkcs11_init_lock((CK_C_INITIALIZE_ARGS_PTR) pInitArgs);
	if (rv != CKR_OK)
		goto out;

	/* set context options */
	memset(&ctx_opts, 0, sizeof(tmc_context_param_t));
	ctx_opts.ver        = 0;
	ctx_opts.app_name   = MODULE_APP_NAME;
	ctx_opts.thread_ctx = &tmc_thread_ctx;

	rc = tmc_context_create(&context, &ctx_opts);
	if (rc != SC_SUCCESS) {
		rv = CKR_GENERAL_ERROR;
		goto out;
	}

	/* List of sessions */
	if (0 != list_init(&sessions)) {
		rv = CKR_HOST_MEMORY;
		goto out;
	}
	list_attributes_seeker(&sessions, session_list_seeker);
	p_session->flags |= CKF_RW_SESSION;
	list_prepend(&sessions, p_session);

	/* List of slots */
	if (0 != list_init(&virtual_slots)) {
		rv = CKR_HOST_MEMORY;
		goto out;
	}
	list_attributes_seeker(&virtual_slots, slot_list_seeker);

	rv = create_slot();
	if (rv != CKR_OK)
		goto out;

	if (!tmc_detect_card_presence(context)) {
		rv = se_detect(context);
		if (rv != CKR_OK)
			goto out;
	}

	out:
	if (rv != CKR_OK) {
		if (context != NULL) {
			tmc_release_context(context);
			context = NULL;
		}
		/* Release and destroy the mutex */
		tmc_pkcs11_free_lock();
	}

	return rv;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{

	void *p;
	tmc_pkcs11_slot_t *slot;
	tmc_pkcs11_object_t *obj;
	CK_ATTRIBUTE_PTR attr;
	CK_RV rv;

	tmc_printf_t("[libsdk]: C_Finalize pReserved = %p\n", pReserved);

	if (pReserved != NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	if (context == NULL)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	/* cancel pending calls */
	in_finalize = 1;

	/* remove card from readers */
	se_removed();

	while ((p = list_fetch(&sessions)))
		free(p);
	
	list_destroy(&sessions);

	while ((slot = list_fetch(&virtual_slots))) {
		while ((obj = list_fetch(&slot->objects))) {
			while ((attr = list_fetch(&obj->attrs))) 
			{
				if(attr->pValue)
				{
					free(attr->pValue);
				}
				free(attr);
			}
			list_destroy(&obj->attrs);
		}
		list_destroy(&slot->objects);
		list_destroy(&slot->logins);
		free(slot);
	}
	list_destroy(&virtual_slots);

	tmc_release_context(context);
	context = NULL;

	/* Release and destroy the mutex */
	tmc_pkcs11_free_lock();

	return rv;
}

CK_RV C_GetSlotList(CK_BBOOL       tokenPresent,  /* only slots with token present */
                    CK_SLOT_ID_PTR pSlotList,     /* receives the array of slot IDs */
                    CK_ULONG_PTR   pulCount)      /* receives the number of slots */
{
	CK_SLOT_ID_PTR found = NULL;
	unsigned int i;
	CK_ULONG numMatches;
	tmc_pkcs11_slot_t *slot;
	CK_RV rv;

	tmc_printf_t("[libsdk]: C_GetSlotList\n");

	if (pulCount == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	/* Slot list can only change in v2.20 */
	if (pSlotList == NULL_PTR)
	{
		rv = se_detect(context);
		if (rv != CKR_OK)
			return rv;
	}

	found = calloc(list_size(&virtual_slots), sizeof(CK_SLOT_ID));

	if (found == NULL) {
		rv = CKR_HOST_MEMORY;
		goto out;
	}

	numMatches = 0;
	for (i=0; i<list_size(&virtual_slots); i++) {
		slot = (tmc_pkcs11_slot_t *) list_get_at(&virtual_slots, i);
		/* the list of available slots contains:
		* - if present, virtual hotplug slot;
		* - any slot with token;
		* - without token(s), one empty slot per reader;
		* - any slot that has already been seen;
		*/
		if ((!tokenPresent && !slot->p11card)
		|| (slot->slot_info.flags & CKF_TOKEN_PRESENT)
		/* If the slot did already show with `C_GetSlotList`, then we need to keep this
		* slot alive. PKCS#11 2.30 allows allows adding but not removing slots until
		* the application calls `C_GetSlotList` with `NULL`. This flag tracks the
		* visibility to the application */
		|| (slot->flags & SC_PKCS11_SLOT_FLAG_SEEN)) {
			found[numMatches++] = slot->id;
			slot->flags |= SC_PKCS11_SLOT_FLAG_SEEN;
		}
	}
	if (pSlotList == NULL_PTR) {
		*pulCount = numMatches;
		rv = CKR_OK;
		goto out;
	}

	if (*pulCount < numMatches) {
		*pulCount = numMatches;
		rv = CKR_BUFFER_TOO_SMALL;
		goto out;
	}

	memcpy(pSlotList, found, numMatches * sizeof(CK_SLOT_ID));
	*pulCount = numMatches;
	rv = CKR_OK;

	out:
	if (found != NULL) {
		free (found);
	}
	tmc_pkcs11_unlock();

	return rv;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID,	/* the slot's ID */
                    CK_FLAGS flags,	/* defined in CK_SESSION_INFO */
                    CK_VOID_PTR pApplication,	/* pointer passed to callback */
                    CK_NOTIFY Notify,	/* notification callback function */
                    CK_SESSION_HANDLE_PTR phSession)
{				/* receives new session handle */
	CK_RV rv;
	struct tmc_pkcs11_slot *slot;
	struct tmc_pkcs11_session *session;
	struct tmc_file_info * file;

	tmc_printf_t("[libsdk]: C_OpenSession slotID = %d\n", slotID);

	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	if (flags & ~(CKF_SERIAL_SESSION | CKF_RW_SESSION))
		return CKR_ARGUMENTS_BAD;

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = slot_get_token(slotID, &slot);
	if (rv != CKR_OK)
		goto out;

	/* Check that no conflicting sessions exist */
	if (!(flags & CKF_RW_SESSION) && (slot->login_user == CKU_SO)) {
		rv = CKR_SESSION_READ_WRITE_SO_EXISTS;
		goto out;
	}

	session = (struct tmc_pkcs11_session *)calloc(1, sizeof(struct tmc_pkcs11_session));
	if (session == NULL) {
		rv = CKR_HOST_MEMORY;
		goto out;
	}

	/* make session handle from pointer and check its uniqueness */
	session->handle = (CK_SESSION_HANDLE)(uintptr_t)session;
	if (list_seek(&sessions, &session->handle) != NULL) {
		free(session);
		rv = CKR_HOST_MEMORY;
		goto out;
	}

	session->slot = slot;
	session->notify_callback = Notify;
	session->notify_data = pApplication;
	session->flags = flags;
	slot->nsessions++;
	list_append(&sessions, session);
	*phSession = session->handle;

	out:
	tmc_pkcs11_unlock();
	return rv;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{				/* receives new session handle */
	CK_RV rv;
	struct tmc_pkcs11_slot *slot;
	struct tmc_pkcs11_session *session;
	struct tmc_fw_data * fw_data;
	struct tmc_file_info * file;
	struct tmc_pkcs11_object *obj;
	CK_ATTRIBUTE_PTR attr;
	int j;

	tmc_printf_t("[libsdk]: C_CloseSession hSession = %d\n", hSession);

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	session = (struct tmc_pkcs11_session *)list_seek(&sessions, &hSession);
	if(session == NULL)
		return CKR_SESSION_HANDLE_INVALID;
	slot = session->slot;


	slot->nsessions--;
	if (slot->nsessions == 0 && slot->login_user >= 0) {
		slot->login_user = -1;
		slot->p11card->framework->logout(slot);
	}

	//delete session objects and their attributes ,reduce space

	if(list_iterator_start(&slot->objects) == 1)
	{
		do {
			obj = list_iterator_next(&slot->objects);
			if(!obj) {
				break;
			}

			if(obj->hSession != hSession)
				continue;

			if(list_iterator_start(&obj->attrs) == 1)
			{
				do {
					attr = list_iterator_next(&obj->attrs);
					if(attr->pValue)
					{
						free(attr->pValue);
					}
					free(attr);  
				}while (list_iterator_hasnext(&obj->attrs));
				list_iterator_stop(&obj->attrs);
			}

			list_destroy(&obj->attrs);
			if(list_delete(&slot->objects, obj) == 0 )
			{
				free(obj);
			}
		} while (list_iterator_hasnext(&slot->objects));
		
		list_iterator_stop(&slot->objects);
	}
	rv = list_delete(&sessions, session);
	free(session);
	return rv == 0 ? CKR_OK : CKR_FUNCTION_FAILED;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{				/* the token's slot */
	CK_RV rv;
	struct tmc_pkcs11_slot *slot;

	tmc_printf_t("[libsdk]: C_CloseAllSessions slotID = %d\n", slotID);

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = slot_get_token(slotID, &slot);
	if (rv != CKR_OK)
		goto out;

	rv = tmc_pkcs11_close_all_sessions(slotID);

out:
	tmc_pkcs11_unlock();
	return rv;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession,	/* the session's handle */
              CK_USER_TYPE userType,	/* the user type */
              CK_CHAR_PTR pPin,	/* the user's PIN */
              CK_ULONG ulPinLen)
{				/* the length of the PIN */
	CK_RV rv;
	struct tmc_pkcs11_session *session = NULL;
	struct tmc_pkcs11_slot *slot;
	//struct tmc_file_info * file;

	tmc_printf("[libsdk]: C_Login userType = %d, pPin = ", userType);
	for (int i = 0; i < ulPinLen; i++) {
		tmc_printf("0x%02X ", pPin[i]);
	}
	tmc_printf("\n");


	if (pPin == NULL_PTR && ulPinLen > 0)
		return CKR_ARGUMENTS_BAD;


	rv = tmc_pkcs11_lock();
		if (rv != CKR_OK)
	return rv;

	if (userType != CKU_USER && userType != CKU_SO && userType != CKU_CONTEXT_SPECIFIC) {
		rv = CKR_USER_TYPE_INVALID;
		goto out;
	}



	if(list_iterator_start(&sessions) == 1)
	{
		do {
			session = list_iterator_next(&sessions);
			if(!session)
			{
				break;
			}

			if(!(session->flags & CKF_RW_SESSION) && userType == CKU_SO)
			{
				rv = CKR_SESSION_READ_ONLY_EXISTS;
				list_iterator_stop(&sessions);
				goto out;
			}
		} while (list_iterator_hasnext(&sessions));
		list_iterator_stop(&sessions);
	}

	session = list_seek(&sessions, &hSession);
	if (!session) {
		rv = CKR_SESSION_HANDLE_INVALID;
		goto out;
	}

	slot = session->slot;

	if (!(slot->token_info.flags & CKF_USER_PIN_INITIALIZED) && userType == CKU_USER) {
		rv = CKR_USER_PIN_NOT_INITIALIZED;
		goto out;
	}

	if (slot->login_user >= 0) {
		if ((CK_USER_TYPE) slot->login_user == userType)
			rv = CKR_USER_ALREADY_LOGGED_IN;
		else
			rv = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
		goto out;
	}
	if(userType == CKU_USER)
	{
//		rv = create_user_df(slot);
//		if(rv != SC_SUCCESS)
//			return rv;
	}

	rv = slot->p11card->framework->login(slot, userType, pPin, ulPinLen);

	if (rv == CKR_OK)
		rv = push_login_state(slot, userType, pPin, ulPinLen);
	else
		return rv;

	slot->login_user = userType;
	if(userType == CKU_USER)
	{
		list_iterator_start(&sessions);
		while (list_iterator_hasnext(&sessions))
		{
			session = list_iterator_next(&sessions);
			if(rv != SC_SUCCESS)
				goto out;
			if(rv != SC_SUCCESS)
				goto out;
		}
		list_iterator_stop(&sessions);
	}

	out:
	tmc_pkcs11_unlock();
	return rv;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv;
	struct tmc_pkcs11_session *session;
	struct tmc_pkcs11_slot *slot;

	tmc_printf("[libsdk]: C_InitPIN pPin = ");
	for (int i = 0; i < ulPinLen; i++) {
		tmc_printf("0x%02X ", pPin[i]);
	}
	tmc_printf("\n");


	if (pPin == NULL_PTR && ulPinLen > 0)
		return CKR_ARGUMENTS_BAD;

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	session = list_seek(&sessions, &hSession);
	if (!session) {
		rv = CKR_SESSION_HANDLE_INVALID;
		goto out;
	}

	if (!(session->flags & CKF_RW_SESSION)) {
		rv = CKR_SESSION_READ_ONLY;
		goto out;
	}

	slot = session->slot;
	if (slot->login_user != CKU_SO) {
		rv = CKR_USER_NOT_LOGGED_IN;
	} else if (slot->p11card->framework->init_pin == NULL) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	} else {
		rv = slot->p11card->framework->init_pin(slot, pPin, ulPinLen);
	}

	out:
	tmc_pkcs11_unlock();
	return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{				/* the session's handle */
	CK_RV rv;
	struct tmc_pkcs11_session *session;
	struct tmc_pkcs11_slot *slot;

	tmc_printf_t("[libsdk]: C_Logout hSession = %d\n", hSession);

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	if(hSession == 0) {
		tmc_printf_t("list_seek fail \n");
		rv = CKR_SESSION_HANDLE_INVALID;
		goto out;
	}

	session = list_seek(&sessions, &hSession);
	if (!session) {
		tmc_printf_t("list_seek fail \n");
		rv = CKR_SESSION_HANDLE_INVALID;
		goto out;
	}

	slot = session->slot;

	if (slot->login_user >= 0) {
		slot->login_user = -1;
		rv = slot->p11card->framework->logout(slot);
	} else
		rv = CKR_USER_NOT_LOGGED_IN;

	out:
	tmc_pkcs11_unlock();
	return rv;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,	/* the session's handle */
                    CK_MECHANISM_PTR pMechanism,	/* the key generation mechanism */
                    CK_ATTRIBUTE_PTR pTemplate,	/* template for the new key */
                    CK_ULONG ulCount,	/* number of attributes in template */
                    CK_OBJECT_HANDLE_PTR phKey)
{				/* receives handle of new key */
	tmc_printf_t("[libsdk]: C_GenerateKey\n");
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,	/* the session's handle */
                    CK_MECHANISM_PTR pMechanism,	/* the decryption mechanism */
                    CK_OBJECT_HANDLE hKey)
{				/* handle of the decryption key */
	CK_BBOOL can_decrypt, can_unwrap;
	CK_KEY_TYPE key_type;
	CK_ATTRIBUTE decrypt_attribute = { CKA_DECRYPT,	&can_decrypt,	sizeof(can_decrypt) };
	CK_ATTRIBUTE key_type_attr = { CKA_KEY_TYPE,	&key_type,	sizeof(key_type) };
	CK_ATTRIBUTE unwrap_attribute = { CKA_UNWRAP,	&can_unwrap,	sizeof(can_unwrap) };
	struct tmc_pkcs11_session *session;
	struct tmc_pkcs11_object *object;
	CK_RV rv;

	tmc_printf_t("[libsdk]: C_DecryptInit\n");

	if (pMechanism == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;
	rv = get_object_from_session(hSession, hKey, &session, &object);
	if (rv != CKR_OK) {
		if (rv == CKR_OBJECT_HANDLE_INVALID)
			rv = CKR_KEY_HANDLE_INVALID;
		goto out;
	}

	if (object->ops->decrypt == NULL_PTR) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	rv = object->ops->get_attribute(session, object, &key_type_attr);
	if (rv != CKR_OK) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	rv = tmc_pkcs11_decr_init(session, pMechanism, object, key_type);

	out:
	tmc_pkcs11_unlock();

	return rv;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,	/* the session's handle */
                CK_BYTE_PTR pEncryptedData,	/* input encrypted data */
                CK_ULONG ulEncryptedDataLen,	/* count of bytes of input */
                CK_BYTE_PTR pData,	/* receives decrypted output */
                CK_ULONG_PTR pulDataLen)
{				/* receives decrypted byte count */
	CK_RV rv;
	struct tmc_pkcs11_session *session;
	struct tmc_pkcs11_operation *op;

	tmc_printf_t("[libsdk]: C_Decrypt\n");

	if(ulEncryptedDataLen > MAX_ALG_CACHE_SIZE)
		return CKR_HOST_MEMORY;

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK) {
		rv = tmc_pkcs11_decr(session, pEncryptedData,
		ulEncryptedDataLen, pData, pulDataLen);
	}

	tmc_pkcs11_unlock();
	return rv;
}

CK_RV
C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG  ulEncryptedPartLen,
		CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;
	struct tmc_pkcs11_session *session;

	tmc_printf_t("[libsdk]: C_DecryptUpdate\n");

	if(ulEncryptedPartLen > MAX_ALG_CACHE_SIZE)
		return CKR_HOST_MEMORY;
	
	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK)
		rv = tmc_pkcs11_decr_update(session, pEncryptedPart, ulEncryptedPartLen,pPart,pulPartLen);
	
	tmc_pkcs11_unlock();
	return rv;
}

CK_RV
C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR  pLastPart, CK_ULONG_PTR  pulLastPartLen)
{
    CK_RV rv;
	struct tmc_pkcs11_session *session;

	tmc_printf_t("[libsdk]: C_DecryptFinal\n");

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK)
		rv = tmc_pkcs11_decr_final(session, pLastPart, pulLastPartLen);
	
	tmc_pkcs11_unlock();
	return rv;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,	/* the session's handle */
                        CK_MECHANISM_PTR pMechanism,	/* the key gen. mech. */
                        CK_ATTRIBUTE_PTR pPublicKeyTemplate,	/* pub. attr. template */
                        CK_ULONG ulPublicKeyAttributeCount,	/* # of pub. attrs. */
                        CK_ATTRIBUTE_PTR pPrivateKeyTemplate,	/* priv. attr. template */
                        CK_ULONG ulPrivateKeyAttributeCount,	/* # of priv. attrs. */
                        CK_OBJECT_HANDLE_PTR phPublicKey,	/* gets pub. key handle */
                        CK_OBJECT_HANDLE_PTR phPrivateKey)
{				/* gets priv. key handle */
    CK_RV rv;
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_slot *slot;

    tmc_printf_t("[libsdk]: C_GenerateKeyPair\n");

    if (pMechanism == NULL_PTR
        || (pPublicKeyTemplate == NULL_PTR && ulPublicKeyAttributeCount > 0)
        || (pPrivateKeyTemplate == NULL_PTR && ulPrivateKeyAttributeCount > 0))
        return CKR_ARGUMENTS_BAD;

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;


    rv = get_session(hSession, &session);
    if (rv != CKR_OK)
        goto out;

    if (!(session->flags & CKF_RW_SESSION)) {
        rv = CKR_SESSION_READ_ONLY;
        goto out;
    }

    slot = session->slot;
    if (slot->p11card->framework->gen_keypair == NULL)
        rv = CKR_FUNCTION_NOT_SUPPORTED;
    else
        rv = slot->p11card->framework->gen_keypair(hSession, pMechanism,
                                                       pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount,phPublicKey, phPrivateKey);
    out:
    tmc_pkcs11_unlock();
    return rv;
}
CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,	/* the session's handle */
                    CK_MECHANISM_PTR pMechanism,	/* the decryption mechanism */
                    CK_OBJECT_HANDLE hKey)
{				/* handle of the decryption key */
    CK_BBOOL can_encrypt, can_wrap;
    CK_KEY_TYPE key_type;
    CK_ATTRIBUTE encrypt_attribute = { CKA_DECRYPT,	&can_encrypt,	sizeof(can_encrypt) };
    CK_ATTRIBUTE key_type_attr = { CKA_KEY_TYPE,	&key_type,	sizeof(key_type) };
    CK_ATTRIBUTE wrap_attribute = { CKA_WRAP,	&can_wrap,	sizeof(can_wrap) };
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_object *object;
    CK_RV rv;

    tmc_printf_t("[libsdk]: C_EncryptInit\n");

    if (pMechanism == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;
    rv = get_object_from_session(hSession, hKey, &session, &object);
    if (rv != CKR_OK) {
        if (rv == CKR_OBJECT_HANDLE_INVALID)
            rv = CKR_KEY_HANDLE_INVALID;
        goto out;
    }

    if (object->ops->encrypt == NULL_PTR) {
        rv = CKR_KEY_TYPE_INCONSISTENT;
        goto out;
    }

    rv = object->ops->get_attribute(session, object, &key_type_attr);
    if (rv != CKR_OK) {
        rv = CKR_KEY_TYPE_INCONSISTENT;
        goto out;
    }

    rv = tmc_pkcs11_encr_init(session, pMechanism, object, key_type);

    out:
    tmc_pkcs11_unlock();

    return rv;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,	/* the session's handle */
                CK_BYTE_PTR pData,	/* receives decrypted output */
                CK_ULONG pulDataLen,
                CK_BYTE_PTR pEncryptedData,	/* input encrypted data */
                CK_ULONG_PTR ulEncryptedDataLen	/* count of bytes of input */
                )
{				/* receives decrypted byte count */
    CK_RV rv;
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_operation *op;

    tmc_printf_t("[libsdk]: C_Encrypt\n");

    if(pulDataLen > MAX_ALG_CACHE_SIZE)
        return CKR_HOST_MEMORY;
    
    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;

    rv = get_session(hSession, &session);
    if (rv == CKR_OK) {

      rv = tmc_pkcs11_encr(session, pData, pulDataLen, pEncryptedData,
                                 ulEncryptedDataLen);

    }

    tmc_pkcs11_unlock();
    return rv;
}

CK_RV
C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG  ulPartLen,
		CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;
	struct tmc_pkcs11_session *session;

	tmc_printf_t("[libsdk]: C_EncryptUpdate\n");
	
	if(ulPartLen > MAX_ALG_CACHE_SIZE)
		return CKR_HOST_MEMORY;

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK)
		rv = tmc_pkcs11_encr_update(session, pPart, ulPartLen,pEncryptedPart,pulEncryptedPartLen);
	
	tmc_pkcs11_unlock();
	return rv;
}

CK_RV
C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	CK_RV rv;
	struct tmc_pkcs11_session *session;

	tmc_printf_t("[libsdk]: C_EncryptFinal\n");
	
	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK)
		rv = tmc_pkcs11_encr_final(session, pLastEncryptedPart, pulLastEncryptedPartLen);
	
	tmc_pkcs11_unlock();
	return rv;
}
/*
 * Below here all functions are wrappers to pass all object attribute and method
 * handling to appropriate object layer.
 */
CK_RV
C_DigestInit(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_MECHANISM_PTR pMechanism)	/* the digesting mechanism */
{
	CK_RV rv;
	struct tmc_pkcs11_session *session;

	tmc_printf_t("[libsdk]: C_DigestInit\n");

	if (pMechanism == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK)
		rv = tmc_pkcs11_digest_init(session, pMechanism);
	
	tmc_pkcs11_unlock();
	return rv;
}

CK_RV
C_DeriveKey(CK_SESSION_HANDLE hSession,		/* the session's handle */
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hBaseKey,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulAttributeCount,
        CK_OBJECT_HANDLE_PTR phKey)
{
    CK_RV rv;
    CK_BBOOL can_derive;
    CK_ATTRIBUTE attr = {CKA_DERIVE, &can_derive, sizeof(can_derive)};
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_object *key;

    tmc_printf_t("[libsdk]: C_DeriveKey\n");
	
    if (pMechanism == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;

    rv = get_object_from_session(hSession, hBaseKey, &session, &key);
    if (rv != CKR_OK)
        goto out;

    if (key->ops->derive == NULL_PTR) {
        rv = CKR_KEY_TYPE_INCONSISTENT;
        goto out;
    }

    rv = key->ops->get_attribute(session, key, &attr);
    if(rv != CKR_OK)
    {
        rv = CKR_KEY_TYPE_INCONSISTENT;
        goto out;
    }


    rv = tmc_pkcs11_deri(session, pMechanism, key, pTemplate, ulAttributeCount,
            phKey);

    out:
    tmc_pkcs11_unlock();
    return rv;
}

CK_RV
C_Digest(CK_SESSION_HANDLE hSession,		/* the session's handle */
		CK_BYTE_PTR pData,		/* data to be digested */
		CK_ULONG ulDataLen,		/* bytes of data to be digested */
		CK_BYTE_PTR pDigest,		/* receives the message digest */
		CK_ULONG_PTR pulDigestLen)	/* receives byte length of digest */
{
	CK_RV rv;
	struct tmc_pkcs11_session *session;
	CK_ULONG  ulBuflen = 0;
	
	tmc_printf_t("[libsdk]: C_Digest\n");
	
	if(ulDataLen > MAX_ALG_CACHE_SIZE)
        return CKR_HOST_MEMORY;

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv != CKR_OK)
		goto out;

	/* if pDigest == NULL, buffer size request */
	if (pDigest) {
	    /* As per PKCS#11 2.24 we need to check if buffer too small before update */
	    rv = tmc_pkcs11_digest_final(session, NULL, &ulBuflen);
	    if (rv != CKR_OK)
		goto out;

	    if (ulBuflen > *pulDigestLen) {
	        *pulDigestLen = ulBuflen;
		rv = CKR_BUFFER_TOO_SMALL;
		goto out;
	    }

	    rv = tmc_pkcs11_digest_update(session, pData, ulDataLen);
	}
	if (rv == CKR_OK)
		rv = tmc_pkcs11_digest_final(session, pDigest, pulDigestLen);

out:
	tmc_pkcs11_unlock();
	return rv;
}


CK_RV
C_DigestUpdate(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_BYTE_PTR pPart,		/* data to be digested */
		CK_ULONG ulPartLen)		/* bytes of data to be digested */
{
	CK_RV rv;
	struct tmc_pkcs11_session *session;

	tmc_printf_t("[libsdk]: C_DigestUpdate\n");
	
	if(ulPartLen > MAX_ALG_CACHE_SIZE)
		return CKR_HOST_MEMORY;

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK)
		rv = tmc_pkcs11_digest_update(session, pPart, ulPartLen);
	
	tmc_pkcs11_unlock();
	return rv;
}

CK_RV
C_DigestFinal(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_BYTE_PTR pDigest,		/* receives the message digest */
		CK_ULONG_PTR pulDigestLen)	/* receives byte count of digest */
{
	CK_RV rv;
	struct tmc_pkcs11_session *session;

	tmc_printf_t("[libsdk]: C_DigestFinal\n");
	
	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK)
		rv = tmc_pkcs11_digest_final(session, pDigest, pulDigestLen);

	tmc_pkcs11_unlock();
	return rv;
}


CK_RV
C_SignInit(CK_SESSION_HANDLE hSession,		/* the session's handle */
           CK_MECHANISM_PTR pMechanism,	/* the signature mechanism */
           CK_OBJECT_HANDLE hKey)		/* handle of the signature key */
{
    CK_BBOOL can_sign;
    CK_KEY_TYPE key_type;
    CK_ATTRIBUTE sign_attribute = { CKA_SIGN, &can_sign, sizeof(can_sign) };
    CK_ATTRIBUTE key_type_attr = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_object *object;
    CK_RV rv;

    tmc_printf_t("[libsdk]: C_SignInit\n");

    if (pMechanism == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;

    rv = get_object_from_session(hSession, hKey, &session, &object);
    if (rv != CKR_OK) {
        if (rv == CKR_OBJECT_HANDLE_INVALID)
            rv = CKR_KEY_HANDLE_INVALID;
        goto out;
    }

    tmc_printf_t("[libsdk]: C_SignInit->signature key's fid = 0x%04X\n",object->fid);

    if (object->ops->sign == NULL_PTR) {
        rv = CKR_KEY_TYPE_INCONSISTENT;

        goto out;
    }

    rv = object->ops->get_attribute(session, object, &sign_attribute);
    if (rv != CKR_OK || !can_sign) {

        rv = CKR_KEY_TYPE_INCONSISTENT;
        goto out;
    }

    rv = object->ops->get_attribute(session, object, &key_type_attr);
    if (rv != CKR_OK) {
        rv = CKR_KEY_TYPE_INCONSISTENT;
        goto out;
    }
    rv = tmc_pkcs11_sign_init(session, pMechanism, object, key_type);

    out:
    tmc_pkcs11_unlock();
    return rv;
}

CK_RV
C_Sign(CK_SESSION_HANDLE hSession,		/* the session's handle */
       CK_BYTE_PTR pData,		/* the data (digest) to be signed */
       CK_ULONG ulDataLen,		/* count of bytes to be signed */
       CK_BYTE_PTR pSignature,		/* receives the signature */
       CK_ULONG_PTR pulSignatureLen)	/* receives byte count of signature */
{
    CK_RV rv;
    struct tmc_pkcs11_session *session;
    struct tmc_card *card;
    CK_ULONG length;

    tmc_printf("[libsdk]: C_Sign tobeSign [%ld]", ulDataLen);
    for (int i = 0; i < ulDataLen; i++) {
        if (i%16 == 0) {
            tmc_printf("\n\t");
        }
        tmc_printf("%02X",pData[i]);
    }
    tmc_printf("\n");

    if(ulDataLen > MAX_ALG_CACHE_SIZE)
        return CKR_HOST_MEMORY;
    
    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;

    rv = get_session(hSession, &session);
    if (rv != CKR_OK)
        goto out;

    /* According to the pkcs11 specs, we must not do any calls that
     * change our crypto state if the caller is just asking for the
     * signature buffer size, or if the result would be
     * CKR_BUFFER_TOO_SMALL. Thus we cannot do the sign_update call
     * below. */
    if ((rv = tmc_pkcs11_sign_size(session, &length)) != CKR_OK)
        goto out;

    if (pSignature == NULL || length > *pulSignatureLen) {
        *pulSignatureLen = length;
        rv = pSignature ? CKR_BUFFER_TOO_SMALL : CKR_OK;
        goto out;
    }
    else {
        *pulSignatureLen = length;
    }

    rv = tmc_pkcs11_sign(session, pData, ulDataLen, length, pSignature, pulSignatureLen);

    out:
    tmc_pkcs11_unlock();
    return rv;
}

CK_RV
C_SignUpdate(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_BYTE_PTR pPart,		/* the data (digest) to be signed */
		CK_ULONG ulPartLen)		/* count of bytes to be signed */
{
	CK_RV rv;
	struct tmc_pkcs11_session *session;

	tmc_printf_t("[libsdk]: C_SignUpdate\n");
	
	if(ulPartLen > MAX_ALG_CACHE_SIZE)
		return CKR_HOST_MEMORY;
	
	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK)
		rv = tmc_pkcs11_sign_update(session, pPart, ulPartLen);

	tmc_pkcs11_unlock();
	return rv;
}


CK_RV
C_SignFinal(CK_SESSION_HANDLE hSession,		/* the session's handle */
		CK_BYTE_PTR pSignature,		/* receives the signature */
		CK_ULONG_PTR pulSignatureLen)	/* receives byte count of signature */
{
	struct tmc_pkcs11_session *session;
	CK_ULONG length;
	CK_RV rv;

	tmc_printf_t("[libsdk]: C_SignFinal\n");

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv != CKR_OK)
		goto out;

	/* According to the pkcs11 specs, we must not do any calls that
	 * change our crypto state if the caller is just asking for the
	 * signature buffer size, or if the result would be
	 * CKR_BUFFER_TOO_SMALL.
	 */
	if ((rv = tmc_pkcs11_sign_size(session, &length)) != CKR_OK)
		goto out;

	if (pSignature == NULL || length > *pulSignatureLen) {
		*pulSignatureLen = length;
		rv = pSignature ? CKR_BUFFER_TOO_SMALL : CKR_OK;
	} else {
		if (rv == CKR_OK)
			rv = tmc_pkcs11_sign_final(session, length, pSignature, pulSignatureLen);
	}

out:
	tmc_pkcs11_unlock();
	return rv;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,	/* the session's handle */
                   CK_MECHANISM_PTR pMechanism,	/* the verification mechanism */
                   CK_OBJECT_HANDLE hKey)
{				/* handle of the verification key */

    CK_KEY_TYPE key_type;
    CK_ATTRIBUTE key_type_attr = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };
    CK_RV rv;
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_object *object;

    tmc_printf_t("[libsdk]: C_VerifyInit\n");
	
    if (pMechanism == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;


    rv = get_object_from_session(hSession, hKey, &session, &object);
    if (rv != CKR_OK) {
        if (rv == CKR_OBJECT_HANDLE_INVALID)
            rv = CKR_KEY_HANDLE_INVALID;
        goto out;
    }
    rv = object->ops->get_attribute(session, object, &key_type_attr);
    if (rv != CKR_OK) {
        rv = CKR_KEY_TYPE_INCONSISTENT;
        goto out;
    }

    rv = tmc_pkcs11_ver_init(session, pMechanism, object, key_type);

    out:
    tmc_pkcs11_unlock();
    return rv;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession,	/* the session's handle */
               CK_BYTE_PTR pData,	/* plaintext data (digest) to compare */
               CK_ULONG ulDataLen,	/* length of data (digest) in bytes */
               CK_BYTE_PTR pSignature,	/* the signature to be verified */
               CK_ULONG ulSignatureLen)
{				/* count of bytes of signature */

    CK_RV rv;
    struct tmc_pkcs11_session *session;
    struct tmc_card *card;
    CK_ULONG length;

    tmc_printf_t("[libsdk]: C_Verify\n");
	
    if(ulDataLen > MAX_ALG_CACHE_SIZE)
        return CKR_HOST_MEMORY;

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;

    rv = get_session(hSession, &session);
    if (rv != CKR_OK)
        goto out;

    /* According to the pkcs11 specs, we must not do any calls that
    * change our crypto state if the caller is just asking for the
    * signature buffer size, or if the result would be
    * CKR_BUFFER_TOO_SMALL. Thus we cannot do the sign_update call
    * below. */

    rv = tmc_pkcs11_ver(session, pData, ulDataLen, pSignature, ulSignatureLen);
    out:
    tmc_pkcs11_unlock();
    return rv;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession,	/* the session's handle */
		     CK_BYTE_PTR pPart,	/* plaintext data (digest) to compare */
		     CK_ULONG ulPartLen)
{				/* length of data (digest) in bytes */
	CK_RV rv;
	struct tmc_pkcs11_session *session;

	tmc_printf_t("[libsdk]: C_VerifyUpdate\n");

	if(ulPartLen > MAX_ALG_CACHE_SIZE)
		return CKR_HOST_MEMORY;

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK)
		rv = tmc_pkcs11_ver_update(session, pPart, ulPartLen);
	tmc_pkcs11_unlock();
	return rv;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession,	/* the session's handle */
		    CK_BYTE_PTR pSignature,	/* the signature to be verified */
		    CK_ULONG ulSignatureLen)
{				/* count of bytes of signature */
	CK_RV rv;
	struct tmc_pkcs11_session *session;

	tmc_printf_t("[libsdk]: C_VerifyFinal\n");

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK) {
	    rv = tmc_pkcs11_ver_final(session, pSignature, ulSignatureLen);
	}
	tmc_pkcs11_unlock();
	return rv;
}

CK_RV
C_CreateObject(CK_SESSION_HANDLE hSession,	/* the session's handle */
               CK_ATTRIBUTE_PTR pTemplate,	/* the object's template */
               CK_ULONG ulCount,		/* attributes in template */
               CK_OBJECT_HANDLE_PTR phObject)
{
    tmc_printf_t("[libsdk]: C_CreateObject\n");
    return tmc_create_object_int(hSession, pTemplate, ulCount, phObject,1);
}


CK_RV C_InitToken(CK_SLOT_ID slotID,
                  CK_CHAR_PTR pPin,
                  CK_ULONG ulPinLen,
                  CK_CHAR_PTR pLabel)
{
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_slot *slot;
    CK_RV rv;
    unsigned int i;

    tmc_printf_t("[libsdk]: C_InitToken\n");

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;

    rv = slot_get_token(slotID, &slot);
    if (rv != CKR_OK)   {
        goto out;
    }

    if (!slot->p11card || !slot->p11card->framework
        || !slot->p11card->framework->init_token) {
        rv = CKR_FUNCTION_NOT_SUPPORTED;
        goto out;
    }

    /* Make sure there's no open session for this token */
    for (i=0; i<list_size(&sessions); i++) {
        session = (struct tmc_pkcs11_session*)list_get_at(&sessions, i);
        if (session->slot == slot) {
            rv = CKR_SESSION_EXISTS;
            goto out;
        }
    }

    rv = slot->p11card->framework->init_token(slot, pPin, ulPinLen, pLabel);
    if (rv == CKR_OK) {
        /* Now we should re-bind all tokens so they get the
         * corresponding function vector and flags */
        rv = C_Finalize(NULL);
        if(rv != CKR_OK)
            return rv;
        rv = C_Initialize(NULL);
        if(rv != CKR_OK)
            return rv;
    }

    out:
    tmc_pkcs11_unlock();
    return rv;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
               CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    CK_RV rv;
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_slot *slot;
    CK_USER_TYPE pin_type;

    tmc_printf_t("[libsdk]: C_SetPIN\n");
	
    if ((pOldPin == NULL_PTR && ulOldLen > 0) || (pNewPin == NULL_PTR && ulNewLen > 0))
        return CKR_ARGUMENTS_BAD;

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;

    session = list_seek(&sessions, &hSession);
    if (!session) {
        rv = CKR_SESSION_HANDLE_INVALID;
        goto out;
    }

    slot = session->slot;

    if (!(session->flags & CKF_RW_SESSION)) {
        rv = CKR_SESSION_READ_ONLY;
        goto out;
    }

    if (rv == CKR_OK)
    {
        if(slot->login_user == -1) {
            pin_type = CKU_USER;
        } else {
            pin_type = (CK_USER_TYPE)slot->login_user;
        }

        rv = slot->p11card->framework->login(slot, pin_type, pOldPin, ulOldLen);
        if(rv != CKR_OK)
        {
            rv = CKR_PIN_INCORRECT;
            goto out;
        }

        rv = slot->p11card->framework->change_pin(slot, pin_type, pNewPin, ulNewLen);
        if(rv != CKR_OK)
        {
            rv = CKR_PIN_INCORRECT;
            goto out;
        }
    }

    out:
    tmc_pkcs11_unlock();
    return rv;
}

CK_RV C_SelfCMD(u8* cmd, u8 cse, CK_BBOOL *isReset)
{
    CK_RV rv;
    struct tmc_pkcs11_slot *slot;
    struct tmc_card_operations *ops;
    struct tmc_card* card = NULL;

    card = malloc(sizeof *card);
#ifdef ENABLE_PCSC
    card->driver = tmc_get_pcsc_driver();
#elif defined(ENABLE_SPI)
    card->driver = tmc_get_spi_driver();
#endif
    ops = tmc_get_card_driver();

    if(*isReset) {
        rv = card->driver->ops->init(NULL);
        if (rv != CKR_OK)   {
            goto out;
        }
        rv = card->driver->ops->connect();
        if (rv != CKR_OK)   {
            goto out;
        }
    }

    rv = ops->self(card, cmd, cse, *isReset);

    *isReset = FALSE;
out:
    if(card)
        free(card);
    return rv;
}
CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    CK_RV rv = CKR_OK;

    tmc_printf_t("[libsdk]: C_GetInfo\n");
	
    if (pInfo == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;
    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    strcpy_bp(pInfo->manufacturerID,
              TMC_VS_FF_COMPANY_NAME,
              32);
    pInfo->flags = 0;
    strcpy_bp(pInfo->libraryDescription,
              TMC_VS_FF_PRODUCT_NAME,
              32);
    pInfo->libraryVersion.major = 1;
    pInfo->libraryVersion.minor = 0;
    tmc_pkcs11_unlock();
    return rv;
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{

    tmc_printf_t("[libsdk]: C_GetFunctionList\n");

    if (ppFunctionList == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    *ppFunctionList = &pkcs11_function_list;
    return CKR_OK;
}
CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR sLotfo)
{
    CK_RV rv = CKR_OK;

    tmc_printf_t("[libsdk]: C_GetSlotInfo\n");

    if (sLotfo == NULL_PTR)
        return CKR_ARGUMENTS_BAD;
    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;
    memset(sLotfo, 0, sizeof(CK_SLOT_INFO));

    strcpy_bp(sLotfo->slotDescription,
              TMC_SLOT_DESCRIPTION,
              sizeof(sLotfo->slotDescription));

    strcpy_bp(sLotfo->manufacturerID,
              TMC_SLOT_MANUFACTURER_ID,
              sizeof(sLotfo->manufacturerID));

    sLotfo->flags |= (unsigned long)(CKF_TOKEN_PRESENT|CKF_HW_SLOT);

    sLotfo->hardwareVersion.major = TMC_SLOT_HARDWARE_VERSION_MAJOR;
    sLotfo->hardwareVersion.minor = TMC_SLOT_HARDWARE_VERSION_MINOR;

    sLotfo->firmwareVersion.major = TMC_SLOT_FIRMWARE_VERSION_MAJOR;
    sLotfo->firmwareVersion.minor = TMC_SLOT_FIRMWARE_VERSION_MINOR;

    tmc_pkcs11_unlock();
    return rv;

}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    struct tmc_pkcs11_slot *slot;
    struct tmc_fw_data *fw_data = NULL;
    struct tmc_card *card;
    uint8_t Serial_Number[16] = {0};
    CK_ULONG UidLength = sizeof(Serial_Number);
    struct tmcse_pin_info pin_info;
    uint8_t Token_init=0;
    CK_BYTE cmd1[] = {0x00,0xA4,0x04,0x00,0x08,0xA0,0x00,0x00,0x00,0x03,0x00,0x00,0x00};
    CK_BYTE cmd2[] = {0x00,0xCA,0x9F,0x7F,0x2A};
    CK_BYTE buf[128] = {0};
    CK_RV rv = CKR_OK;

    tmc_printf_t("[libsdk]: C_GetTokenInfo\n");

    memset(Serial_Number,0,16);
    if (pInfo == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;

    rv = slot_get_token(slotID, &slot);
    if (rv != CKR_OK)   {
        goto out;
    }

    if (slot->p11card == NULL) {
        rv = CKR_TOKEN_NOT_PRESENT;
        goto out;
    }

    strcpy_bp(pInfo->label, TMC_TOKEN_LABEL, sizeof(pInfo->label));

    strcpy_bp(pInfo->manufacturerID, TMC_TOKEN_MANUFACTURER_ID, sizeof(pInfo->manufacturerID));

    strcpy_bp(pInfo->model, TMC_TOKEN_DEVICE_MODE, sizeof(pInfo->model));

    card = slot->p11card->card;
    if(card->ops->get_uid != NULL)
    {
        rv = card->ops->get_uid(card, (uint8_t *)(Serial_Number),&UidLength);
        if (rv != CKR_OK) {
            goto out;
        }
    }
    strcpy_bp(pInfo->serialNumber, Serial_Number, UidLength);

    pInfo->flags |= (unsigned long) ( CKF_RNG
                                      |CKF_LOGIN_REQUIRED
    //                                  |CKF_USER_PIN_INITIALIZED
    //                                  |CKF_TOKEN_INITIALIZED
    //                                  |CKF_USER_PIN_COUNT_LOW
                                      |CKF_USER_PIN_FINAL_TRY
    //                                  |CKF_USER_PIN_LOCKED
    //                                  |CKF_USER_PIN_TO_BE_CHANGED
    //                                  |CKF_SO_PIN_COUNT_LOW
                                      |CKF_SO_PIN_FINAL_TRY
    //                                  |CKF_SO_PIN_LOCKED
    //                                  |CKF_SO_PIN_TO_BE_CHANGED
    );

    //Get SO PIN Info
    rv = card->ops->get_pin_info(card, CKU_SO, &pin_info);
    if (rv != CKR_OK) {
        goto out;
    }
    else {
        if(pin_info.maxTryCounter != pin_info.curTryCounter) {
            pInfo->flags |= CKF_SO_PIN_COUNT_LOW;
        }
        if(pin_info.curTryCounter == 0x00) {
            pInfo->flags |= CKF_SO_PIN_LOCKED;
        }
        if(pin_info.isDefault == 0x00) {
            pInfo->flags |= CKF_SO_PIN_TO_BE_CHANGED;
        }
    }

    //Get User PIN Info
    rv = card->ops->get_pin_info(card, CKU_USER, &pin_info);
    if(rv != CKR_USER_PIN_NOT_INITIALIZED) {
        pInfo->flags |= CKF_USER_PIN_INITIALIZED;
    }
    else if (rv == CKR_OK) {
        if(pin_info.maxTryCounter != pin_info.curTryCounter) {
            pInfo->flags |= CKF_USER_PIN_COUNT_LOW;
        }
        if(pin_info.curTryCounter == 0x00) {
            pInfo->flags |= CKF_USER_PIN_LOCKED;
        }
    }
    else {
        goto out;
    }
	
    rv = card->ops->get_card_state(card, &Token_init);
    if (rv != CKR_OK) {
        goto out;
    }
    if((rv == CKR_OK)&&(Token_init != 0)) {
       pInfo->flags |= CKF_TOKEN_INITIALIZED;
    }


    pInfo->ulMaxSessionCount = TMC_TOKEN_MAXSESSION_COUNTER;
    pInfo->ulSessionCount = list_size(&sessions) - 1;

    pInfo->ulMaxRwSessionCount = TMC_TOKEN_MAXRWSESSION_COUNTER;
    pInfo->ulRwSessionCount = list_size(&sessions) - 1;
	
    pInfo->ulMaxPinLen = TMC_TOKEN_MAX_PIN_LEN;
    pInfo->ulMinPinLen = TMC_TOKEN_MIN_PIN_LEN;

    pInfo->ulTotalPublicMemory = TMC_TOKEN_TOTAL_PUBLIC_MEMORY;
    pInfo->ulFreePublicMemory = TMC_TOKEN_FREE_PUBLIC_MEMORY;
	
    pInfo->ulTotalPrivateMemory = TMC_TOKEN_TOTAL_PVIVATE_MEMORY;
    pInfo->ulFreePrivateMemory = TMC_TOKEN_FREE_PVIVATE_MEMORY;

    pInfo->hardwareVersion.major = TMC_TOKEN_HARDWARE_VERSION_MAJOR;
    pInfo->hardwareVersion.minor = TMC_TOKEN_HARDWARE_VERSION_MINOR;

    pInfo->firmwareVersion.major = TMC_TOKEN_FIRMWARE_VERSION_MAJOR;
    pInfo->firmwareVersion.minor = TMC_TOKEN_FIRMWARE_VERSION_MINOR;
	
    out:
    tmc_pkcs11_unlock();
    return rv;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
                         CK_MECHANISM_TYPE_PTR pMechanismList,
                         CK_ULONG_PTR pulCount)
{
    struct tmc_pkcs11_slot *slot;
    CK_RV rv;

    tmc_printf_t("[libsdk]: C_GetMechanismList\n");

    if (pulCount == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;

    rv = slot_get_token(slotID, &slot);
    if (rv == CKR_OK)
        rv = tmc_pkcs11_get_mechanism_list(slot->p11card, pMechanismList, pulCount);

    tmc_pkcs11_unlock();
    return rv;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID,
                         CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR pInfo)
{
    struct tmc_pkcs11_slot *slot;
    CK_RV rv;

    tmc_printf_t("[libsdk]: C_GetMechanismInfo\n");

    if (pInfo == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;

    rv = slot_get_token(slotID, &slot);
    if (rv == CKR_OK)
        rv = tmc_pkcs11_get_mechanism_info(slot->p11card, type, pInfo);

    tmc_pkcs11_unlock();
    return rv;
}


CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,	/* the session's handle */
                       CK_SESSION_INFO_PTR pInfo)
{				/* receives session information */
    CK_RV rv;
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_slot *slot;
    int logged_out;

    tmc_printf_t("[libsdk]: C_GetSessionInfo\n");

    if (pInfo == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;

    session = list_seek(&sessions, &hSession);
    if (!session) {
        rv = CKR_SESSION_HANDLE_INVALID;
        goto out;
    }

    pInfo->slotID = session->slot->id;
    pInfo->flags = session->flags;
    pInfo->ulDeviceError = 0;

    slot = session->slot;
    if(session->flags & CKF_RW_SESSION) {
        if(slot->login_user == CKU_USER) {
            pInfo->state = CKS_RW_USER_FUNCTIONS;
        }
        else if(slot->login_user == CKU_SO){
            pInfo->state = CKS_RW_SO_FUNCTIONS;
        }
        else {
            pInfo->state = CKS_RW_PUBLIC_SESSION;
        }
    }
    else {
        if(slot->login_user == CKU_USER) {
            pInfo->state = CKS_RO_USER_FUNCTIONS;
        }
        else {
            pInfo->state = CKS_RO_PUBLIC_SESSION;
        }
    }

    out:
    tmc_pkcs11_unlock();
    return rv;
}



CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,	/* the session's handle */
                       CK_BYTE_PTR RandomData,	/* receives the random data */
                       CK_ULONG ulRandomLen)
{				/* number of bytes to be generated */
    CK_RV rv;
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_slot *slot;
    struct tmc_card *card;
    uint8_t i;
    uint8_t blockNum;
    uint8_t padNum;
    uint8_t Random_Block_Size_Per = 0x10;

    tmc_printf_t("[libsdk]: C_GenerateRandom\n");

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;

    rv = get_session(hSession, &session);

    if (rv == CKR_OK) {
        card = session->slot->p11card->card;
        //slot = session->slot;
        //if (slot->p11card->framework->get_random == NULL)
        if(card->ops->get_challenge == NULL)
            rv = CKR_RANDOM_NO_RNG;
        else
        {
            rv = card->ops->get_challenge(card, ulRandomLen, RandomData);
        }
    }

    tmc_pkcs11_unlock();
    return rv;
}
CK_RV
C_FindObjectsInit(CK_SESSION_HANDLE hSession,	/* the session's handle */
                  CK_ATTRIBUTE_PTR pTemplate,	/* attribute values to match */
                  CK_ULONG ulCount)		/* attributes in search template */
{
    CK_RV rv;
    CK_BBOOL is_private = TRUE;
    CK_ATTRIBUTE private_attribute = { CKA_PRIVATE, &is_private, sizeof(is_private) };
    int match, hide_private;
    unsigned int i, j;
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_object *object;
    struct tmc_pkcs11_find_operation *operation;
    struct tmc_pkcs11_slot *slot;

    tmc_printf_t("[libsdk]: C_FindObjectsInit\n");

    if (pTemplate == NULL_PTR && ulCount > 0)
        return CKR_ARGUMENTS_BAD;

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;

    rv = get_session(hSession, &session);
    if (rv != CKR_OK)
        goto out;

    rv = session_start_operation(session, SC_PKCS11_OPERATION_FIND,
                                 &find_mechanism, (struct tmc_pkcs11_operation **)&operation);
    if (rv != CKR_OK)
        goto out;

    operation->current_handle = 0;
    operation->num_handles = 0;
    operation->allocated_handles = 0;
    operation->handles = NULL;
    slot = session->slot;

    /* Check whether we should hide private objects */
    hide_private = 0;
    if (slot->login_user != CKU_USER && (slot->token_info.flags & CKF_LOGIN_REQUIRED))
        hide_private = 1;

    /* For each object in token do */
    //head object is a object to take place head of objects list, not a real obj
    for (i=1; i<list_size(&slot->objects); i++) {
        object = (struct tmc_pkcs11_object *)list_get_at(&slot->objects, i);

        /* User not logged in and private object? */
        if (hide_private) {
            if (object->ops->get_attribute(session, object, &private_attribute) != CKR_OK)
                continue;
            if (is_private) {
                continue;
            }
        }

        /* Try to match every attribute */
        match = 1;
        for (j = 0; j < ulCount; j++) {
            rv = object->ops->cmp_attribute(session, object, &pTemplate[j]);
            if (rv == 0) {
                match = 0;
                break;
            }
        }

        if (match) {

            tmc_printf_t("[libsdk]: match object's fid = 0x%04X\n", object->fid);

            /* Realloc handles - remove restriction on only 32 matching objects -dee */
            if (operation->num_handles >= operation->allocated_handles) {
                operation->allocated_handles += SC_PKCS11_FIND_INC_HANDLES;
                operation->handles = realloc(operation->handles,
                                             sizeof(CK_OBJECT_HANDLE) * operation->allocated_handles);
                if (operation->handles == NULL) {
                    rv = CKR_HOST_MEMORY;
                    goto out;
                }
            }
            operation->handles[operation->num_handles++] = object->handle;
        }
    }
    rv = CKR_OK;
    out:
    tmc_pkcs11_unlock();
    return rv;
}


CK_RV
C_FindObjects(CK_SESSION_HANDLE hSession,	/* the session's handle */
              CK_OBJECT_HANDLE_PTR phObject,	/* receives object handle array */
              CK_ULONG ulMaxObjectCount,	/* max handles to be returned */
              CK_ULONG_PTR pulObjectCount)	/* actual number returned */
{
    CK_RV rv;
    CK_ULONG to_return;
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_find_operation *operation;

    tmc_printf_t("[libsdk]: C_FindObjects\n");

    if (phObject == NULL_PTR || ulMaxObjectCount == 0 || pulObjectCount == NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;

    rv = get_session(hSession, &session);
    if (rv != CKR_OK)
        goto out;

    rv = session_get_operation(session, SC_PKCS11_OPERATION_FIND, (tmc_pkcs11_operation_t **) & operation);
    if (rv != CKR_OK)
        goto out;

    to_return = (CK_ULONG) operation->num_handles - operation->current_handle;
    if (to_return > ulMaxObjectCount)
        to_return = ulMaxObjectCount;

    *pulObjectCount = to_return;

    memcpy(phObject, &operation->handles[operation->current_handle], to_return * sizeof(CK_OBJECT_HANDLE));

    operation->current_handle += to_return;

    out:	tmc_pkcs11_unlock();
    return rv;
}


CK_RV
C_FindObjectsFinal(CK_SESSION_HANDLE hSession)	/* the session's handle */
{
    CK_RV rv;
    struct tmc_pkcs11_session *session;

    tmc_printf_t("[libsdk]: C_FindObjectsFinal\n");

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;

    rv = get_session(hSession, &session);
    if (rv != CKR_OK)
        goto out;

    rv = session_get_operation(session, SC_PKCS11_OPERATION_FIND, NULL);
    if (rv == CKR_OK)
        session_stop_operation(session, SC_PKCS11_OPERATION_FIND);

    out:	tmc_pkcs11_unlock();
    return rv;
}

CK_RV
C_GetAttributeValue(CK_SESSION_HANDLE hSession,	/* the session's handle */
                    CK_OBJECT_HANDLE hObject,	/* the object's handle */
                    CK_ATTRIBUTE_PTR pTemplate,	/* specifies attributes, gets values */
                    CK_ULONG ulCount)		/* attributes in template */
{
	static int precedence[] = {
		CKR_OK,
		CKR_BUFFER_TOO_SMALL,
		CKR_ATTRIBUTE_TYPE_INVALID,
		CKR_ATTRIBUTE_SENSITIVE,
		-1
	};
	char object_name[64];
	int j;
	CK_RV rv;
	struct tmc_pkcs11_session *session;
	struct tmc_pkcs11_object *object;
	int res, res_type;
	unsigned int i;

	tmc_printf_t("[libsdk]: C_GetAttributeValue\n");

	if (pTemplate == NULL_PTR || ulCount == 0)
		return CKR_ARGUMENTS_BAD;

	rv = tmc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_object_from_session(hSession, hObject, &session, &object);
	if (rv != CKR_OK)
		goto out;


	res_type = 0;
	for (i = 0; i < ulCount; i++) {

		//ECC Public Key need to use get_pub_key()
		if (pTemplate[i].type == CKA_EC_POINT) {
			res = object->ops->export_pub(session, object, (CK_BYTE_PTR *)&(pTemplate[i].pValue), &(pTemplate[i].ulValueLen));
		}
		else {
			res = object->ops->get_attribute(session, object, &pTemplate[i]);
		}

		if (res != CKR_OK)
			pTemplate[i].ulValueLen = (CK_ULONG) - 1;

		/* the pkcs11 spec has complicated rules on
		* what errors take precedence:
		*      CKR_ATTRIBUTE_SENSITIVE
		*      CKR_ATTRIBUTE_INVALID
		*      CKR_BUFFER_TOO_SMALL
		* It does not exactly specify how other errors
		* should be handled - we give them highest
		* precedence
		*/
		for (j = 0; precedence[j] != -1; j++) {
			if (precedence[j] == res)
				break;
		}
		if (j > res_type) {
			res_type = j;
			rv = res;
		}
	}

	out:
	tmc_pkcs11_unlock();
	return rv;
}


CK_RV
C_SetAttributeValue(CK_SESSION_HANDLE hSession,	/* the session's handle */
                    CK_OBJECT_HANDLE hObject,	/* the object's handle */
                    CK_ATTRIBUTE_PTR pTemplate,	/* specifies attributes and values */
                    CK_ULONG ulCount)		/* attributes in template */
{
    CK_RV rv;
    unsigned int i;
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_object *object;

    tmc_printf_t("[libsdk]: C_SetAttributeValue\n");

    if (pTemplate == NULL_PTR || ulCount == 0)
        return CKR_ARGUMENTS_BAD;

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;

    rv = get_object_from_session(hSession, hObject, &session, &object);
    if (rv != CKR_OK)
        goto out;

    if (!(session->flags & CKF_RW_SESSION)) {
        rv = CKR_SESSION_READ_ONLY;
        goto out;
    }

    if (object->ops->set_attribute == NULL)
        rv = CKR_FUNCTION_NOT_SUPPORTED;
    else {
        for (i = 0; i < ulCount; i++) {
            if ((pTemplate[i].type != CKA_ID) && (pTemplate[i].type != CKA_LABEL)) {
                rv = CKR_ATTRIBUTE_SENSITIVE;
                goto out;
            }
            rv = object->ops->set_attribute(session, object, &pTemplate[i]);
            if (rv != CKR_OK)
                break;
        }
    }

    out:
    tmc_pkcs11_unlock();
    return rv;
}
CK_RV
C_DestroyObject(CK_SESSION_HANDLE hSession,	/* the session's handle */
                CK_OBJECT_HANDLE hObject)	/* the object's handle */
{
    CK_RV rv;
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_object *object;
    CK_BBOOL isToken = FALSE;
    CK_ATTRIBUTE token_attribure = {CKA_TOKEN, &isToken, sizeof(isToken)};

    tmc_printf_t("[libsdk]: C_DestroyObject\n");

    rv = tmc_pkcs11_lock();
    if (rv != CKR_OK)
        return rv;


    rv = get_object_from_session(hSession, hObject, &session, &object);
    if (rv != CKR_OK)
        goto out;


    object->ops->get_attribute(session, object, &token_attribure);
    if((!(session->flags & CKF_RW_SESSION)) && isToken)
        return CKR_SESSION_READ_ONLY;

    if (object->ops->destroy_object == NULL)
        rv = CKR_FUNCTION_NOT_SUPPORTED;
    else
        rv = object->ops->destroy_object(session, object);

    out:
    tmc_pkcs11_unlock();
    return rv;
}

CK_FUNCTION_LIST pkcs11_function_list = {
	{ 2, 11 }, /* Note: NSS/Firefox ignores this version number and uses C_GetInfo() */
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	NULL,//C_GetOperationState
	NULL,//C_SetOperationState
	C_Login,
	C_Logout,
	C_CreateObject,
    NULL,//C_CopyObject,
    C_DestroyObject,
    NULL,//C_GetObjectSize,
    C_GetAttributeValue,
    C_SetAttributeValue,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    C_Digest,
    C_DigestUpdate,
    NULL,//C_DigestKey,
    C_DigestFinal,
	C_SignInit,
	C_Sign,
    C_SignUpdate,
    C_SignFinal,
    NULL,//C_SignRecoverInit,
    NULL,//C_SignRecover,
	C_VerifyInit,
	C_Verify,
    C_VerifyUpdate,
    C_VerifyFinal,
    NULL,//C_VerifyRecoverInit,
    NULL,//C_VerifyRecover,
    NULL,//C_DigestEncryptUpdate,
    NULL,//C_DecryptDigestUpdate,
    NULL,//C_SignEncryptUpdate,
    NULL,//C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
    NULL,//C_WrapKey,
    NULL,//C_UnwrapKey,
    C_DeriveKey,
    NULL,//C_SeedRandom,
	C_GenerateRandom,
    NULL,//C_GetFunctionStatus,
    NULL,//C_CancelFunction,
    NULL,//C_WaitForSlotEvent
    C_SelfCMD,
};


