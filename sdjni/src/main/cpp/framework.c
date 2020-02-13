/*
 * Copyright (C) 2018 TMC
 */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>

#include "sdk.h"

extern tmc_context_t *context;
extern list_t sessions;

void pop_all_login_states(struct tmc_pkcs11_slot *slot)
{

    struct tmc_pkcs11_login *login = (struct tmc_pkcs11_login *)list_fetch(&slot->logins);
    //clear all login state
    while (login) {
        memset(login->pPin, 0, login->ulPinLen);
        free(login->pPin);
        free(login);
        login = (struct tmc_pkcs11_login *)list_fetch(&slot->logins);
    }

}

CK_RV restore_login_state(struct tmc_pkcs11_slot *slot)
{
	CK_RV r = CKR_OK;

	if (slot) {
		if (list_iterator_start(&slot->logins)) {
			struct tmc_pkcs11_login *login = list_iterator_next(&slot->logins);
			while (login) {
				r = slot->p11card->framework->login(slot, login->userType,
						login->pPin, login->ulPinLen);
				if (r != CKR_OK)
					break;
				login = list_iterator_next(&slot->logins);
			}
			list_iterator_stop(&slot->logins);
		}
	}

	return r;
}

CK_RV reset_login_state(struct tmc_pkcs11_slot *slot, CK_RV rv)
{
	if (slot) {
		if (slot->p11card && slot->p11card->framework) {
			slot->p11card->framework->logout(slot);
		}

		if (rv == CKR_USER_NOT_LOGGED_IN) {
			slot->login_user = -1;
			pop_all_login_states(slot);
		}
	}

	return rv;
}


/****************************string util functions ************************/
void strcpy_bp(u8 * dst, const char *src, size_t dstsize)
{
    size_t c;

    if (!dst || !src || !dstsize)
        return;

    memset((char *)dst, 0x00, dstsize);

    c = strlen(src) > dstsize ? dstsize : strlen(src);

    memcpy((char *)dst, src, c);
}

/**************************** mutex functions ************************/
extern list_t virtual_slots;
static CK_C_INITIALIZE_ARGS_PTR	global_locking;
static void *global_lock = NULL;

CK_RV mutex_create(void **mutex)
{
    pthread_mutex_t *m;

    m = calloc(1, sizeof(*m));
    if (m == NULL)
        return CKR_GENERAL_ERROR;;
    pthread_mutex_init(m, NULL);
    *mutex = m;
    return CKR_OK;
}

CK_RV mutex_lock(void *p)
{
    if (pthread_mutex_lock((pthread_mutex_t *) p) == 0)
        return CKR_OK;
    else
        return CKR_GENERAL_ERROR;
}

CK_RV mutex_unlock(void *p)
{
    if (pthread_mutex_unlock((pthread_mutex_t *) p) == 0)
        return CKR_OK;
    else
        return CKR_GENERAL_ERROR;
}

CK_RV mutex_destroy(void *p)
{
    pthread_mutex_destroy((pthread_mutex_t *) p);
    free(p);
    return CKR_OK;
}

static CK_C_INITIALIZE_ARGS _def_locks = {
        mutex_create, mutex_destroy, mutex_lock, mutex_unlock, 0, NULL };

static CK_C_INITIALIZE_ARGS_PTR default_mutex_funcs = &_def_locks;

/* wrapper for the locking functions for libopensc */
static int tmc_create_mutex(void **m)
{
    if (global_locking == NULL)
        return SC_SUCCESS;
    if (global_locking->CreateMutex(m) == CKR_OK)
        return SC_SUCCESS;
    else
        return SC_ERROR_INTERNAL;
}

static int tmc_lock_mutex(void *m)
{
    if (global_locking == NULL)
        return SC_SUCCESS;
    if (global_locking->LockMutex(m) == CKR_OK)
        return SC_SUCCESS;
    else
        return SC_ERROR_INTERNAL;
}

static int tmc_unlock_mutex(void *m)
{
    if (global_locking == NULL)
        return SC_SUCCESS;
    if (global_locking->UnlockMutex(m) == CKR_OK)
        return SC_SUCCESS;
    else
        return SC_ERROR_INTERNAL;

}

static int tmc_destroy_mutex(void *m)
{
    if (global_locking == NULL)
        return SC_SUCCESS;
    if (global_locking->DestroyMutex(m) == CKR_OK)
        return SC_SUCCESS;
    else
        return SC_ERROR_INTERNAL;
}

tmc_thread_context_t tmc_thread_ctx = {
        0, tmc_create_mutex, tmc_lock_mutex,
        tmc_unlock_mutex, tmc_destroy_mutex, NULL
};

/*
 * Locking functions
 */

/**************************** mutex functions ************************/

int tmc_mutex_create(const tmc_context_t *ctx, void **mutex)
{
    if (ctx == NULL)
        return SC_ERROR_INVALID_ARGUMENTS;
    if (ctx->thread_ctx != NULL && ctx->thread_ctx->create_mutex != NULL)
        return ctx->thread_ctx->create_mutex(mutex);
    else
        return SC_SUCCESS;
}

int tmc_mutex_lock(const tmc_context_t *ctx, void *mutex)
{
    if (ctx == NULL)
        return SC_ERROR_INVALID_ARGUMENTS;
    if (ctx->thread_ctx != NULL && ctx->thread_ctx->lock_mutex != NULL)
        return ctx->thread_ctx->lock_mutex(mutex);
    else
        return SC_SUCCESS;
}

int tmc_mutex_unlock(const tmc_context_t *ctx, void *mutex)
{
    if (ctx == NULL)
        return SC_ERROR_INVALID_ARGUMENTS;
    if (ctx->thread_ctx != NULL && ctx->thread_ctx->unlock_mutex != NULL)
        return ctx->thread_ctx->unlock_mutex(mutex);
    else
        return SC_SUCCESS;
}

int tmc_mutex_destroy(const tmc_context_t *ctx, void *mutex)
{
    if (ctx == NULL)
        return SC_ERROR_INVALID_ARGUMENTS;
    if (ctx->thread_ctx != NULL && ctx->thread_ctx->destroy_mutex != NULL)
        return ctx->thread_ctx->destroy_mutex(mutex);
    else
        return SC_SUCCESS;
}

CK_RV
tmc_pkcs11_init_lock(CK_C_INITIALIZE_ARGS_PTR args)
{
    CK_RV rv = CKR_OK;

    int applock = 0;
    int oslock = 0;
    if (global_lock)
        return CKR_OK;

    /* No CK_C_INITIALIZE_ARGS pointer, no locking */
    if (!args)
        return CKR_OK;

    if (args->pReserved != NULL_PTR)
        return CKR_ARGUMENTS_BAD;

    /* If the app tells us OS locking is okay,
     * use that. Otherwise use the supplied functions.
     */
    global_locking = NULL;
    if (args->CreateMutex && args->DestroyMutex &&
        args->LockMutex   && args->UnlockMutex) {
        applock = 1;
    }
    if ((args->flags & CKF_OS_LOCKING_OK)) {
        oslock = 1;
    }

    /* Based on PKCS#11 v2.11 11.4 */
    if (applock && oslock) {
        /* Shall be used in threaded environment, prefer app provided locking */
        global_locking = args;
    } else if (!applock && oslock) {
        /* Shall be used in threaded environment, must use operating system locking */
        global_locking = default_mutex_funcs;
    } else if (applock && !oslock) {
        /* Shall be used in threaded environment, must use app provided locking */
        global_locking = args;
    } else if (!applock && !oslock) {
        /* Shall not be used in threaded environment, use operating system locking */
        global_locking = default_mutex_funcs;
    }

    if (global_locking != NULL) {
        /* create mutex */
        rv = global_locking->CreateMutex(&global_lock);
    }

    return rv;
}

CK_RV tmc_pkcs11_lock(void)
{
    if (context == NULL)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (!global_lock)
        return CKR_OK;
    if (global_locking)  {
        while (global_locking->LockMutex(global_lock) != CKR_OK)
            ;
    }

    return CKR_OK;
}

static void
__tmc_pkcs11_unlock(void *lock)
{
    if (!lock)
        return;
    if (global_locking) {
        while (global_locking->UnlockMutex(lock) != CKR_OK)
            ;
    }
}

void tmc_pkcs11_unlock(void)
{
    __tmc_pkcs11_unlock(global_lock);
}

/*
 * Free the lock - note the lock must be held when
 * you come here
 */
void tmc_pkcs11_free_lock(void)
{
    void	*tempLock;

    if (!(tempLock = global_lock))
        return;

    /* Clear the global lock pointer - once we've
     * unlocked the mutex it's as good as gone */
    global_lock = NULL;

    /* Now unlock. On SMP machines the synchronization
     * primitives should take care of flushing out
     * all changed data to RAM */
    __tmc_pkcs11_unlock(tempLock);

    if (global_locking)
        global_locking->DestroyMutex(tempLock);
    global_locking = NULL;
}

/*
 * context operation functions
 */

int tmc_release_context(tmc_context_t *ctx)
{
    unsigned int i;

    if (ctx == NULL) {
        return SC_ERROR_INVALID_ARGUMENTS;
    }

    //attention: free the drv_data in finish
    if (ctx->driver->ops->finish != NULL)
        ctx->driver->ops->finish(ctx);

    //the driver need other resource?

    if (ctx->mutex != NULL) {
        int r = tmc_mutex_destroy(ctx, ctx->mutex);
        if (r != SC_SUCCESS) {
            return r;
        }
    }

    if (ctx->app_name != NULL)
        free(ctx->app_name);
    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
    return SC_SUCCESS;
}

/**************************** object functions ************************/

CK_RV
get_object_from_session(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                        struct tmc_pkcs11_session **session, struct tmc_pkcs11_object **object)
{
    struct tmc_pkcs11_session *sess;
    CK_ATTRIBUTE_PTR atrr;
    CK_ATTRIBUTE_TYPE type = CKA_PRIVATE;
    CK_RV rv;

    rv = get_session(hSession, &sess);
    if (rv != CKR_OK)
        return rv;

    *object = (struct tmc_pkcs11_object*)list_seek(&sess->slot->objects, &hObject);
    if (!*object)
        return CKR_OBJECT_HANDLE_INVALID;
    
    if(sess->slot->login_user != CKU_USER)
    {
        atrr = (CK_ATTRIBUTE_PTR)list_seek(&(*object)->attrs, &type);
        if(*(CK_BBOOL*)(atrr->pValue))
            return CKR_USER_NOT_LOGGED_IN; 
    }
    
    *session = sess;

    return CKR_OK;
}

CK_RV tmc_context_create(tmc_context_t** ctx_out, tmc_context_param_t* ctx_param)
{
    tmc_context_t *ctx;
    int r;

    if (ctx_out == NULL || ctx_param == NULL)
        return SC_ERROR_INVALID_ARGUMENTS;

    ctx = calloc(1, sizeof(tmc_context_t));
    if (ctx == NULL)
        return SC_ERROR_OUT_OF_MEMORY;

    /* set the application name if set in the parameter options */
    if (ctx_param->app_name != NULL)
        ctx->app_name = strdup(ctx_param->app_name);
    else
        ctx->app_name = strdup("default");
    if (ctx->app_name == NULL) {
        tmc_release_context(ctx);
        return SC_ERROR_OUT_OF_MEMORY;
    }

    ctx->flags = ctx_param->flags;

    /* set thread context and create mutex object (if specified) */
    if (ctx_param->thread_ctx != NULL)
        ctx->thread_ctx = ctx_param->thread_ctx;
    r = tmc_mutex_create(ctx, &ctx->mutex);
    if (r != SC_SUCCESS) {
        tmc_release_context(ctx);
        return r;
    }

#ifdef ENABLE_SPI
    ctx->driver = tmc_get_spi_driver();
#elif defined(ENABLE_PCSC)
    ctx->driver = tmc_get_pcsc_driver();
#endif

    r = ctx->driver->ops->init(ctx);
    if (r != SC_SUCCESS)   {
        tmc_release_context(ctx);
        return r;
    }

    if (ctx->driver->ops->detect_cards == NULL)
    	return SC_ERROR_NOT_SUPPORTED;

    r = ctx->driver->ops->detect_cards(ctx);

    *ctx_out = ctx;
    return r;
}
/**************************** objcet functions ************************/


/**************************** seeker functions ************************/
/* simclist helpers to locate interesting objects by ID */
int session_list_seeker(const void *el, const void *key) {
    const struct tmc_pkcs11_session *session = (struct tmc_pkcs11_session *)el;
    if ((el == NULL) || (key == NULL))
        return 0;
    if (session->handle == *(CK_SESSION_HANDLE*)key)
        return 1;
    return 0;
}
int slot_list_seeker(const void *el, const void *key) {
    const struct tmc_pkcs11_slot *slot = (struct tmc_pkcs11_slot *)el;
    if ((el == NULL) || (key == NULL))
        return 0;
    if (slot->id == *(CK_SLOT_ID *)key)
        return 1;
    return 0;
}
/* simclist helpers to locate interesting objects by ID */
int object_list_seeker(const void *el, const void *key)
{
    const struct tmc_pkcs11_object *object = (struct tmc_pkcs11_object *)el;

    if ((el == NULL) || (key == NULL))
        return 0;
    if (object->handle == *(CK_OBJECT_HANDLE*)key)
        return 1;
    return 0;
}

int attribute_list_seeker(const void *el, const void *key) {
    CK_ATTRIBUTE *attribute = (CK_ATTRIBUTE_PTR)el;
    if ((el == NULL) || (key == NULL))
        return 0;
    if (attribute->type == *((CK_ATTRIBUTE_TYPE *)key))
        return 1;
    return 0;
}

/****************************slot functions ************************/
/* Allocates an existing slot to a card */
CK_RV slot_allocate(struct tmc_pkcs11_slot ** slot, struct tmc_pkcs11_card * p11card)
{
    unsigned int i;
    struct tmc_pkcs11_slot *tmp_slot = NULL;

    /* Locate a free slot for this reader */
    for (i = 0; i < list_size(&virtual_slots); i++) {
        tmp_slot = (struct tmc_pkcs11_slot *) list_get_at(&virtual_slots, i);
        if (tmp_slot->p11card == NULL)
            break;
    }
    if (!tmp_slot || (i == list_size(&virtual_slots)))
        return CKR_FUNCTION_FAILED;
    tmp_slot->p11card = p11card;
    tmp_slot->events = SE_EVENT_CARD_INSERTED;
    *slot = tmp_slot;
    return CKR_OK;
}

struct tmc_pkcs11_slot *tmc_get_slot(void)
{
    unsigned int i;

    /* Locate a slot related to the reader */
    for (i = 0; i<list_size(&virtual_slots); i++) {
        tmc_pkcs11_slot_t *slot = (tmc_pkcs11_slot_t *) list_get_at(&virtual_slots, i);
        if(slot != NULL)
            return slot;
    }
    return NULL;
}

static void init_slot_info(CK_SLOT_INFO_PTR pInfo)
{
    strcpy_bp(pInfo->slotDescription, TMC_SLOT_DESCRIPTION, 64);
    strcpy_bp(pInfo->manufacturerID, TMC_SLOT_MANUFACTURER_ID, 32);
    pInfo->hardwareVersion.major = TMC_SLOT_HARDWARE_VERSION_MAJOR;
    pInfo->hardwareVersion.minor = TMC_SLOT_HARDWARE_VERSION_MINOR;
    pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
    pInfo->firmwareVersion.major = TMC_SLOT_FIRMWARE_VERSION_MAJOR;
    pInfo->firmwareVersion.minor = TMC_SLOT_FIRMWARE_VERSION_MINOR;
}

CK_RV create_slot(void)
{
    /* find unused virtual hotplug slots */
    struct tmc_pkcs11_slot *slot = tmc_get_slot();
    struct tmc_pkcs11_object *obj;

    /* create a new slot if no empty slot is available */
    if (!slot) {
        if (list_size(&virtual_slots) >= 1)
            return CKR_FUNCTION_FAILED;

        slot = (struct tmc_pkcs11_slot *)calloc(1, sizeof(struct tmc_pkcs11_slot));
        if (!slot)
            return CKR_HOST_MEMORY;

        list_append(&virtual_slots, slot);
        if (0 != list_init(&slot->objects)) {
            return CKR_HOST_MEMORY;
        }
        list_attributes_seeker(&slot->objects, object_list_seeker);
        tmc_create_head_object(&obj);
        list_append(&slot->objects, obj);

        if (0 != list_init(&slot->logins)) {
            return CKR_HOST_MEMORY;
        }
    } else {
        /* reuse the old list of logins/objects since they should be empty */
        list_t logins = slot->logins;
        list_t objects = slot->objects;

        memset(slot, 0, sizeof *slot);

        slot->logins = logins;
        slot->objects = objects;
    }

    slot->login_user = -1;
    slot->id = (CK_SLOT_ID) list_locate(&virtual_slots, slot);

    init_slot_info(&slot->slot_info);

    return CKR_OK;
}

CK_RV slot_get_slot(CK_SLOT_ID id, struct tmc_pkcs11_slot ** slot)
{
    if (context == NULL)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    *slot = list_seek(&virtual_slots, &id);	/* FIXME: check for null? */
    if (!*slot)
        return CKR_SLOT_ID_INVALID;
    return CKR_OK;
}

CK_RV slot_get_token(CK_SLOT_ID id, struct tmc_pkcs11_slot ** slot)
{
    int rv;

    rv = slot_get_slot(id, slot);
    if (rv != CKR_OK)
        return rv;

    if (!((*slot)->slot_info.flags & CKF_TOKEN_PRESENT)) {
        if ((*slot)->p11card == NULL)
            return CKR_TOKEN_NOT_PRESENT;
        rv = se_detect(context);
        if (rv != CKR_OK)
            return rv;
    }

    if (!((*slot)->slot_info.flags & CKF_TOKEN_PRESENT)) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    return CKR_OK;
}

CK_RV slot_token_removed(CK_SLOT_ID id)
{
    int rv;
    CK_RV token_was_present;
    struct tmc_pkcs11_slot *slot;
    struct tmc_pkcs11_object *object;

    rv = slot_get_slot(id, &slot);
    if (rv != CKR_OK)
        return rv;

    token_was_present = (slot->slot_info.flags & CKF_TOKEN_PRESENT);

    /* Terminate active sessions */
    tmc_pkcs11_close_all_sessions(id);

    while ((object = (struct tmc_pkcs11_object*)list_fetch(&slot->objects))) {
        if (object->ops->release)
            object->ops->release(object);
    }

    /* Release framework stuff */
    if (slot->p11card != NULL) {
        if (slot->fw_data != NULL &&
            slot->p11card->framework != NULL && slot->p11card->framework->release_token != NULL) {
            slot->p11card->framework->release_token(slot->p11card, slot->fw_data);
            slot->fw_data = NULL;
        }
    }

    /* Reset relevant slot properties */
    slot->slot_info.flags &= ~CKF_TOKEN_PRESENT;
    slot->login_user = -1;
    pop_all_login_states(slot);

    if (token_was_present)
        slot->events = SE_EVENT_CARD_REMOVED;

    memset(&slot->token_info, 0, sizeof slot->token_info);

    return CKR_OK;
}

void *tmc_mem_alloc_secure(tmc_context_t *ctx, size_t len)
{
    void *pointer;
    int locked = 0;

    pointer = calloc(len, sizeof(unsigned char));
    if (!pointer)
        return NULL;
    /* TODO mprotect */
    /* Do not swap the memory */
    if (mlock(pointer, len) >= 0)
	locked = 1;

    if (!locked) {
        if (ctx->flags) {
            free (pointer);
            pointer = NULL;
        } else {
        }
    }
    return pointer;
}

CK_RV push_login_state(struct tmc_pkcs11_slot *slot,
                       CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    CK_RV r = CKR_HOST_MEMORY;
    struct tmc_pkcs11_login *login = NULL;

    login = (struct tmc_pkcs11_login *) calloc(1, sizeof *login);
    if (login == NULL) {
        goto err;
    }

    if (pPin && ulPinLen) {
        login->pPin = (CK_CHAR_PTR)(tmc_mem_alloc_secure(context, (sizeof *pPin)*ulPinLen));
        if (login->pPin == NULL) {
            goto err;
        }
        memcpy(login->pPin, pPin, (sizeof *pPin)*ulPinLen);
        login->ulPinLen = ulPinLen;
    }
    login->userType = userType;

    if (0 > list_append(&slot->logins, login)) {
        goto err;
    }

    login = NULL;
    r = CKR_OK;

    err:
    if (login) {
        if (login->pPin) {
            memset(login->pPin, 0, login->ulPinLen);
            free(login->pPin);
        }
        free(login);
    }

    return r;
}

/****************************session functions ************************/

CK_RV get_session(CK_SESSION_HANDLE hSession, struct tmc_pkcs11_session **session)
{
    *session = (struct tmc_pkcs11_session*)list_seek(&sessions, &hSession);
    if (!*session)
        return CKR_SESSION_HANDLE_INVALID;
    return CKR_OK;
}

/* Internal version of C_CloseSession that gets called with
* the global lock held */
static CK_RV tmc_pkcs11_close_session(CK_SESSION_HANDLE hSession)
{
    struct tmc_pkcs11_slot *slot;
    struct tmc_pkcs11_session *session;

    struct tmc_pkcs11_object *obj;
    CK_ATTRIBUTE_PTR attr;
    CK_RV rv = CKR_OK;

    session = (struct tmc_pkcs11_session*)list_seek(&sessions, &hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;

    /* If we're the last session using this slot, make sure
     * we log out */
    slot = session->slot;
    slot->nsessions--;
    if (slot->nsessions == 0 && slot->login_user >= 0) {
        slot->login_user = -1;
        slot->p11card->framework->logout(slot);
    }

    //delete session objects and their attributes ,reduce space

    if(list_iterator_start(&slot->objects) == 1)
    {
        do
        {
            obj = list_iterator_next(&slot->objects);
            if(!obj)
            {
                break;
            }

            if(obj->hSession != hSession)
                continue;

            if(list_iterator_start(&obj->attrs) == 1)
            {
                do{
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
    list_iterator_stop(&sessions);
    rv = list_delete(&sessions, session);
    list_iterator_start(&sessions);
    free(session);
    return rv;
}

/* Internal version of C_CloseAllSessions that gets called with
 * the global lock held */
CK_RV tmc_pkcs11_close_all_sessions(CK_SLOT_ID slotID)
{
    CK_RV rv = CKR_OK, error;
    struct tmc_pkcs11_session *session = NULL;
    if(list_iterator_start(&sessions) != 1)
        goto out;
        
    while(list_iterator_hasnext(&sessions))
    {
        session = list_iterator_next(&sessions);
        if(!session->slot)
            continue;
        if (session->slot->id == slotID)
            if ((error = tmc_pkcs11_close_session(session->handle)) != CKR_OK)
                rv = error;
    }
    //list_clear(&sessions);
    out:
        list_iterator_stop(&sessions);
    return rv;
}

/****************************driver functions ************************/
int tmc_detect_card_presence(tmc_context_t *ctx)
{
    int r;
    if (ctx->driver->ops->detect_card_presence == NULL)
        return SC_ERROR_NOT_SUPPORTED;

    r = ctx->driver->ops->detect_card_presence(ctx);
    return r;
}

/****************************se functions ************************/
static void tmc_card_free(tmc_card_t *card)
{
    //release all algoithms
    if(card->algorithms != NULL)
    {
        int i;
        for(i = 0; i < card->algorithm_count;i++)
        {
            struct tmc_algorithm_info *info = (card->algorithms + i);
            if(info->algorithm == SC_ALGORITHM_EC)
            {
                struct tmc_ec_parameters ep = info->u._ec.params;
                free(ep.named_curve);
                free(ep.der.value);
            }
        }
        free(card->algorithms);
        card->algorithms = NULL;
        card->algorithm_count = 0;
    }

    //destroy mutex
    if(card->mutex != NULL)
    {
        tmc_mutex_destroy(card->ctx, card->mutex);
    }

    memset(card, 0, sizeof *card);
    free(card);
}

static tmc_card_t * tmc_card_new(void)//tmc_context_t *ctx)
{
    tmc_card_t *card;

    if (context == NULL)
        return NULL;

    card = (tmc_card_t *)calloc(1, sizeof(struct tmc_card));
    if (card == NULL)
        return NULL;

    card->manage_fid = (uint16_t) 0xEE01;
    card->ctx = context;

    if (tmc_mutex_create(card->ctx, &card->mutex) != SC_SUCCESS) {
        free(card);
        return NULL;
    }

    return card;
}

int tmc_disconnect_card(struct tmc_card *card)
{
    int r;
    tmc_context_t * ctx;

    if (!card)
        return SC_ERROR_INVALID_ARGUMENTS;

    ctx = card->ctx;
    if (card->lock_count != 0)
        return SC_ERROR_NOT_ALLOWED;
    if (card->ops->finish) {
        r = card->ops->finish(card);
    }

    if (card->driver->ops->disconnect) {
        r = card->driver->ops->disconnect(ctx);
    }
    tmc_card_free(card);
    return r;
}

int tmc_connect_card( tmc_card_t **card_out)
{
    tmc_card_t *card;
    int i, r = 0, idx, connected = 0;

    if (card_out == NULL)
        return SC_ERROR_INVALID_ARGUMENTS;
    if (context->driver->ops->connect == NULL)
        return SC_ERROR_NOT_SUPPORTED;

    card = tmc_card_new();
    if (card == NULL)
        return SC_ERROR_OUT_OF_MEMORY;

    r = context->driver->ops->connect();

    if (r < 0)
        goto err;

    connected = 1;

    card->driver = context->driver;
    //if we have another SE applet,change this method.
    card->ops = tmc_get_card_driver();
	
	if (card->ops->init != NULL) {
	    r = card->ops->init(card);
		if (r) {
			goto err;
		}
	}

    /* initialize max_send_size/max_recv_size to a meaningful value */
    card->max_recv_size = 256;
    card->max_send_size = 256;

    *card_out = card;

    return SC_SUCCESS;
    err:
    if (connected)
        card->driver->ops->disconnect(context);
    if (card != NULL)
        tmc_card_free(card);
    return r;
}

CK_RV se_removed(void)
{
    unsigned int i;
    struct tmc_pkcs11_card *p11card = NULL;
    /* Mark all slots as "token not present" */
    tmc_pkcs11_slot_t *slot = (tmc_pkcs11_slot_t *) list_get_at(&virtual_slots, 0);
    /* Save the "card" object */
    if (slot->p11card)
        p11card = slot->p11card;
    slot_token_removed(slot->id);

    if (p11card) {
        p11card->framework->unbind(p11card);
        tmc_disconnect_card(p11card->card);
        for (i=0; i < p11card->nmechanisms; ++i) {
            if (p11card->mechanisms[i]->free_mech_data) {
                p11card->mechanisms[i]->free_mech_data(p11card->mechanisms[i]->mech_data);
            }
            free(p11card->mechanisms[i]);
        }
        free(p11card->mechanisms);
        free(p11card);
    }

    return CKR_OK;
}


CK_RV se_detect(tmc_context_t *ctx)
{
    struct tmc_pkcs11_card *p11card = NULL;
    int rc;
    CK_RV rv;
    unsigned int i;
    int j;

    /* Check if SE is valid */
    rc = tmc_detect_card_presence(ctx);
    if (rc < 0) {
        se_removed();
        return CKR_FUNCTION_FAILED;
    }

    tmc_pkcs11_slot_t *slot = (tmc_pkcs11_slot_t *) list_get_at(&virtual_slots, 0);
    p11card = slot->p11card;
    /* Detect the card if it's not known already */
    if (p11card == NULL) {
        p11card = (struct tmc_pkcs11_card *)calloc(1, sizeof(struct tmc_pkcs11_card));
        if (!p11card)
            return CKR_HOST_MEMORY;
    }

    if (p11card->card == NULL) {
        rc = tmc_connect_card(&p11card->card);
        if (rc != SC_SUCCESS)   {
            return CKR_FUNCTION_FAILED;
        }

    }
    /* Detect the framework */
    if (p11card->framework == NULL) {
        /* Initialize framework */
        //if we have another SE,change this method

        p11card->framework = tmc_get_framework_ops();
        rv = p11card->framework->create_tokens(p11card);
        if(rv != CKR_OK)
            return rv;
        rv = p11card->framework->bind(p11card);
        if(rv != CKR_OK)
            return rv;
        rv = p11card->framework->read_objects(slot);
        if(rv != CKR_OK)
            return rv;
    }
    return CKR_OK;
}

/* process lock function*/

int tmc_lock(tmc_card_t *card)
{
    int r = 0, r2 = 0;
    if (card == NULL)
        return SC_ERROR_INVALID_ARGUMENTS;

    r = tmc_mutex_lock(card->ctx, card->mutex);
    if (card->lock_count == 0) {
        r = card->driver->ops->lock(card->ctx);
        card->lock_count = 1;
    }
    r2 = tmc_mutex_unlock(card->ctx, card->mutex);
    if (r2 != SC_SUCCESS) {
        r = r != SC_SUCCESS ? r : r2;
    }

    return r;
}

int tmc_unlock(tmc_card_t *card)
{
    int r, r2;

    if (!card)
        return SC_ERROR_INVALID_ARGUMENTS;

    r = tmc_mutex_lock(card->ctx, card->mutex);
    if (r != SC_SUCCESS)
        return r;
    if (card->lock_count != 0) {
        r = card->driver->ops->unlock(card->ctx);
        card->lock_count = 0;
    }
    r2 = tmc_mutex_unlock(card->ctx, card->mutex);
    if (r2 != SC_SUCCESS) {
        r = r != SC_SUCCESS ? r : r2;
    }

    return r;
}
/** cipher function**/

/*
 * Initialize a decryption context. When we get here, we know
 * the key object is capable of decrypting _something_
 */
CK_RV
tmc_pkcs11_decr_init(struct tmc_pkcs11_session *session,
                     CK_MECHANISM_PTR pMechanism,
                     struct tmc_pkcs11_object *key,
                     CK_MECHANISM_TYPE key_type)
{
    struct tmc_pkcs11_card *p11card;
    tmc_pkcs11_operation_t *operation;

    tmc_pkcs11_mechanism_type_t *mt;
    void * value_ptr = NULL;
    CK_RV rv;

    if (!session || !session->slot
        || !(p11card = session->slot->p11card))
        return CKR_ARGUMENTS_BAD;

    /* See if we support this mechanism type */
    mt = tmc_pkcs11_find_mechanism(p11card, pMechanism->mechanism, CKF_DECRYPT);
    if (mt == NULL)
        return CKR_MECHANISM_INVALID;

    if(key_type == CKK_DES2)
        key_type = CKK_DES3;

    /* See if compatible with key type */
    if (mt->key_type != key_type)
        return CKR_KEY_TYPE_INCONSISTENT;

    rv = session_start_operation(session, SC_PKCS11_OPERATION_DECRYPT, mt, &operation);
    if (rv != CKR_OK)
        return rv;


    memcpy(&operation->mechanism, pMechanism, sizeof(CK_MECHANISM));

    value_ptr = calloc(1, operation->mechanism.ulParameterLen);
    if(!value_ptr)
    {
        rv = CKR_HOST_MEMORY;
        goto error;
    }

    memcpy(value_ptr, operation->mechanism.pParameter,
           operation->mechanism.ulParameterLen);

    operation->mechanism.pParameter = value_ptr;
    
    

    rv = mt->decrypt_init(operation, key);
    error:
    if (rv != CKR_OK)
        session_stop_operation(session, SC_PKCS11_OPERATION_DECRYPT);

    return rv;
}

CK_RV
tmc_pkcs11_decr(struct tmc_pkcs11_session *session,
                CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    tmc_pkcs11_operation_t *op;
    int rv;

    rv = session_get_operation(session, SC_PKCS11_OPERATION_DECRYPT, &op);
    if (rv != CKR_OK)
        return rv;

    rv = op->type->decrypt(op, pEncryptedData, ulEncryptedDataLen,
                           pData, pulDataLen);

    if (rv != CKR_BUFFER_TOO_SMALL && pData != NULL)
        session_stop_operation(session, SC_PKCS11_OPERATION_DECRYPT);

    return rv;
}

CK_RV
tmc_pkcs11_decr_update(struct tmc_pkcs11_session *session,
			CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
			CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	tmc_pkcs11_operation_t *op;
	int rv;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_DECRYPT, &op);
	if (rv != CKR_OK)
		goto done;

	rv = op->type->decryptUpdate(op, pEncryptedData, ulEncryptedDataLen,pData,pulDataLen);
    if (rv != CKR_OK)
        goto done;
    return rv;
done:
    if (rv != CKR_BUFFER_TOO_SMALL)
		session_stop_operation(session, SC_PKCS11_OPERATION_DECRYPT);
    return rv;
}

CK_RV
tmc_pkcs11_decr_final(struct tmc_pkcs11_session *session,
			CK_BYTE_PTR pData, CK_ULONG_PTR ulDataLen)
{
	tmc_pkcs11_operation_t *op;
	int rv;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_DECRYPT, &op);
	if (rv != CKR_OK)
		goto done;

	rv = op->type->decryptFinal(op, pData, ulDataLen);

done:
    if (rv != CKR_BUFFER_TOO_SMALL && pData)
		session_stop_operation(session, SC_PKCS11_OPERATION_DECRYPT);
}

CK_RV
tmc_pkcs11_encr_init(struct tmc_pkcs11_session *session,
                     CK_MECHANISM_PTR pMechanism,
                     struct tmc_pkcs11_object *key,
                     CK_MECHANISM_TYPE key_type)
{
    struct tmc_pkcs11_card *p11card;
    tmc_pkcs11_operation_t *operation;
    void * value_ptr = NULL;

    tmc_pkcs11_mechanism_type_t *mt;
    CK_RV rv;

    if (!session || !session->slot
        || !(p11card = session->slot->p11card))
        return CKR_ARGUMENTS_BAD;

    /* See if we support this mechanism type */
    mt = tmc_pkcs11_find_mechanism(p11card, pMechanism->mechanism, CKF_ENCRYPT);
    if (mt == NULL)
        return CKR_MECHANISM_INVALID;

    if(key_type == CKK_DES2)
        key_type = CKK_DES3;

    /* See if compatible with key type */
    if (mt->key_type != key_type)
        return CKR_KEY_TYPE_INCONSISTENT;

    rv = session_start_operation(session, SC_PKCS11_OPERATION_ENCRYPT, mt, &operation);
    if (rv != CKR_OK)
        return rv;


    memcpy(&operation->mechanism, pMechanism, sizeof(CK_MECHANISM));
    
    value_ptr = calloc(1, operation->mechanism.ulParameterLen);
    if(!value_ptr)
    {
        rv = CKR_HOST_MEMORY;
        goto error;
    } 

    if(operation->mechanism.ulParameterLen)
    {
        memcpy(value_ptr, operation->mechanism.pParameter,
               operation->mechanism.ulParameterLen); 
    }
    
    operation->mechanism.pParameter = value_ptr;


    rv = mt->encrypt_init(operation, key);
    error:
    if (rv != CKR_OK)
        session_stop_operation(session, SC_PKCS11_OPERATION_ENCRYPT);


    return rv;
}

CK_RV
tmc_pkcs11_encr(struct tmc_pkcs11_session *session,
                CK_BYTE_PTR pData, CK_ULONG pulDataLen,
                CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR ulEncryptedDataLen)
{
    tmc_pkcs11_operation_t *op;
    int rv;

    rv = session_get_operation(session, SC_PKCS11_OPERATION_ENCRYPT, &op);
    if (rv != CKR_OK)
        return rv;



    rv = op->type->encrypt(op, pData, pulDataLen, pEncryptedData, ulEncryptedDataLen);

    if (rv != CKR_BUFFER_TOO_SMALL && pEncryptedData)
        session_stop_operation(session, SC_PKCS11_OPERATION_ENCRYPT);

    return rv;
}

CK_RV
tmc_pkcs11_encr_update(struct tmc_pkcs11_session *session,
			CK_BYTE_PTR pData, CK_ULONG ulDataLen,
			CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR ulEncryptedDataLen)
{
	tmc_pkcs11_operation_t *op;
	int rv;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_ENCRYPT, &op);
	if (rv != CKR_OK)
		goto error;

    rv = op->type->encryptUpdate(op, pData, ulDataLen,pEncryptedData,ulEncryptedDataLen);


    if (rv != CKR_OK)
        goto error;
    return rv;

error:
    if (rv != CKR_BUFFER_TOO_SMALL)
		session_stop_operation(session, SC_PKCS11_OPERATION_ENCRYPT);
    return rv;
}

CK_RV
tmc_pkcs11_encr_final(struct tmc_pkcs11_session *session,
			CK_BYTE_PTR pData, CK_ULONG_PTR ulDataLen)
{
	tmc_pkcs11_operation_t *op;
	int rv;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_ENCRYPT, &op);
	if (rv != CKR_OK)
		goto done;

	rv = op->type->encryptFinal(op, pData, ulDataLen);

done:
    if (rv != CKR_BUFFER_TOO_SMALL && pData)
		session_stop_operation(session, SC_PKCS11_OPERATION_ENCRYPT);
}


CK_RV
tmc_pkcs11_deri(struct tmc_pkcs11_session *session,		/* the session's handle */
                  CK_MECHANISM_PTR pMechanism,
                  struct tmc_pkcs11_object * baseKey,
                  CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount,
                  CK_OBJECT_HANDLE_PTR phKey)
{
    CK_RV rv;
    struct tmc_pkcs11_card *p11card;
    tmc_pkcs11_operation_t *op;
    struct tmc_pkcs11_mechanism_type * mt;
    struct agreement_data * data;



    if (!session || !session->slot
        || !(p11card = session->slot->p11card)
        ||!pTemplate)
    {
        rv = CKR_ARGUMENTS_BAD;
        goto done;
    }

    /* See if we support this mechanism type */
    mt = tmc_pkcs11_find_mechanism(p11card, pMechanism->mechanism, CKF_DERIVE);
    if (mt == NULL)
    {
        rv = CKR_MECHANISM_INVALID;
        goto done;
    }


    rv = session_start_operation(session, SC_PKCS11_OPERATION_DERIVE, mt, &op);
    if (rv != CKR_OK)
        goto done;

    data = (struct agreement_data *)calloc(1, sizeof(struct agreement_data));
    if(!data)
    {
        rv = CKR_HOST_MEMORY;
        goto done;
    }

    data->pTemplate = pTemplate;
    data->ulAttrbuteCount = ulAttributeCount;
    data->key = baseKey;
    op->priv_data = data;
    //CK_ECDH1_DERIVE_PARAMS *params = (CK_ECDH1_DERIVE_PARAMS*)pMechanism->pParameter;
    memcpy(&op->mechanism, pMechanism, sizeof(CK_MECHANISM));

    rv = mt->derive(op, baseKey, phKey);

done:
    session_stop_operation(session, SC_PKCS11_OPERATION_DERIVE);
    return rv;
}


/*
 * Initialize a signing context. When we get here, we know
 * the key object is capable of signing _something_
 */
CK_RV
tmc_pkcs11_sign_init(struct tmc_pkcs11_session *session, CK_MECHANISM_PTR pMechanism,
                    struct tmc_pkcs11_object *key, CK_MECHANISM_TYPE key_type)
{
    struct tmc_pkcs11_card *p11card;
    tmc_pkcs11_operation_t *operation;
    tmc_pkcs11_mechanism_type_t *mt;
    int rv;

    if (!session || !session->slot || !(p11card = session->slot->p11card))
        return CKR_ARGUMENTS_BAD;

    /* See if we support this mechanism type */
    //sc_log(context, "mechanism 0x%lX, key-type 0x%lX",
    //       pMechanism->mechanism, key_type);
    mt = tmc_pkcs11_find_mechanism(p11card, pMechanism->mechanism, CKF_SIGN);
    if (mt == NULL) {
        tmc_printf_t("[libsdk]: C_SignInit->tmc_pkcs11_sign_init mechanism = 0x%08X\n", pMechanism->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    /* See if compatible with key type */
    if (mt->key_type != key_type)
    {
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    rv = session_start_operation(session, SC_PKCS11_OPERATION_SIGN, mt, &operation);
    if (rv != CKR_OK)
        return rv;

    memcpy(&operation->mechanism, pMechanism, sizeof(CK_MECHANISM));
    rv = mt->sign_init(operation, key);
    if (rv != CKR_OK)
        session_stop_operation(session, SC_PKCS11_OPERATION_SIGN);

    return rv;
}

CK_RV rsa_pkcs1_v15_padding(CK_BYTE_PTR pDigest, CK_ULONG ulDigestLen, CK_ULONG ulRSAModLen, CK_BYTE_PTR pDest, CK_ULONG_PTR pulDestLen)
{
    CK_RV rv = CKR_OK;
    CK_ULONG off = 0;
    CK_BYTE_PTR pBuf = NULL;
    CK_BYTE_PTR pOid = NULL;
    CK_ULONG ulOidLen = 0;
	CK_BYTE oid_sha_1[]   = {0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14};
    CK_BYTE oid_sha_256[] = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
    CK_BYTE oid_sha_384[] = {0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30};
    CK_BYTE oid_sha_512[] = {0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40};

    if(ulRSAModLen < 64) {
        return CKR_ARGUMENTS_BAD;
    }

    pBuf = malloc(ulRSAModLen);
    if (pBuf == NULL) {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    switch(ulDigestLen) {
		case SHA1_HASH_SIZE:
            pOid = oid_sha_1;
            ulOidLen = sizeof(oid_sha_1);
			break;
        case SHA256_HASH_SIZE:
            pOid = oid_sha_256;
            ulOidLen = sizeof(oid_sha_256);
            break;
        case SHA384_HASH_SIZE:
            pOid = oid_sha_384;
            ulOidLen = sizeof(oid_sha_384);
            break;
        case SHA512_HASH_SIZE:
            pOid = oid_sha_512;
            ulOidLen = sizeof(oid_sha_512);
            break;
        default:
            if ((ulDigestLen != (sizeof(oid_sha_1)+SHA1_HASH_SIZE))
                &&(ulDigestLen != (sizeof(oid_sha_256)+SHA256_HASH_SIZE))
                &&(ulDigestLen != (sizeof(oid_sha_384)+SHA384_HASH_SIZE))
                &&(ulDigestLen != (sizeof(oid_sha_512)+SHA512_HASH_SIZE))) {
                    rv = CKR_DATA_LEN_RANGE;
                    goto out;
            }
    }

    //RSA_PKCS1_V15 Padding rules : 00 01 FF...FF 00 OID H

    pBuf[off++] = 0x00;
    pBuf[off++] = 0x01;

    memset(pBuf + off, 0xFF, (ulRSAModLen - 3 - ulOidLen - ulDigestLen));
    off += (ulRSAModLen - 3 - ulOidLen - ulDigestLen);

    pBuf[off++] = 0x00;

    if (pOid != NULL) {
        memcpy(pBuf + off, pOid, ulOidLen);
        off += ulOidLen;
    }

    memcpy(pBuf + off, pDigest, ulDigestLen);
    off += ulDigestLen;

    //End Padding

    memcpy(pDest, pBuf, ulRSAModLen);
    *pulDestLen = ulRSAModLen;

    out:

    if(pBuf)
    {
        free(pBuf);
    }
    return rv;
}

CK_RV
tmc_pkcs11_sign(struct tmc_pkcs11_session *session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_ULONG ulRsaModLen,
               CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    struct tmc_pkcs11_operation *op;
    struct signature_data *data;
    struct tmc_pkcs11_object *key;
    struct tmc_pkcs11_operation * md_op;
    CK_RV rv;
    CK_ULONG tmp = 0;

    rv = session_get_operation(session, SC_PKCS11_OPERATION_SIGN, &op);
    if (rv != CKR_OK)
        return rv;
    data = op->priv_data;
    key = data->key;
    md_op = data->md;

    if(md_op)
    {
        switch (md_op->type->mech)
        {
            case CKM_SHA_1:
                tmp = SHA1_HASH_SIZE;
                break;
            case CKM_SHA256:
                tmp = SHA256_HASH_SIZE;
                break;
            case CKM_SHA224:
                tmp = SHA224_HASH_SIZE;
                break;
            case CKM_SHA384:
                tmp = SHA384_HASH_SIZE;
                break;
            case CKM_SHA512:
                tmp = SHA512_HASH_SIZE;
                break;
            case CKM_SM3_256:
                tmp = SM3_HASH_SIZE;
                break;
            default:
                return CKR_MECHANISM_INVALID;
        }

        rv = md_op->type->md_update(md_op, pData, ulDataLen);
        if(rv != CKR_OK)
            goto error;

        rv = md_op->type->md_final(md_op, pSignature, &tmp);
        if(rv != CKR_OK)
            goto error;

        ulDataLen = tmp;
    }
    else
    {
        memcpy(pSignature, pData, ulDataLen);
    }

    //add by zhangzch sdk process padding for RSA -- hirain test
    if(op->mechanism.mechanism == CKM_RSA_PKCS) {

        rv = rsa_pkcs1_v15_padding(pSignature, ulDataLen, ulRsaModLen, pSignature, pulSignatureLen);
        if (rv != CKR_OK)
            goto error;
		
        ulDataLen = *pulSignatureLen;

        tmc_printf_t("[libsdk]: rsa_pkcs1_v15_padding [%d]", ulDataLen);
        for (int i = 0; i < ulDataLen; i++) {
            if (i%16 == 0) {
                tmc_printf("\n\t");
            }
            tmc_printf("%02X ",pSignature[i]);
        }
        tmc_printf("\n");
    }

    rv = key->ops->sign(session, (void *)data, pSignature, ulDataLen, pSignature);
    //if (rv != CKR_OK)
    //    goto error;
    //return rv;
    error:
        session_stop_operation(session, SC_PKCS11_OPERATION_SIGN);
        return rv;

}


CK_RV
tmc_pkcs11_sign_update(struct tmc_pkcs11_session *session,
		      CK_BYTE_PTR pData, CK_ULONG ulDataLen)
{
	tmc_pkcs11_operation_t *op;
	int rv;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_SIGN, &op);
	if (rv != CKR_OK)
		return rv;

	if (op->type->sign_update == NULL) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto done;
	}

	rv = op->type->sign_update(op, pData, ulDataLen);

done:
	if (rv != CKR_OK)
		session_stop_operation(session, SC_PKCS11_OPERATION_SIGN);
	return rv;

}

CK_RV
tmc_pkcs11_sign_final(struct tmc_pkcs11_session *session, CK_ULONG ulModLen,
		     CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	tmc_pkcs11_operation_t *op;
	int rv;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_SIGN, &op);
	if (rv != CKR_OK)
		return rv;

	/* Bail out for signature mechanisms that don't do hashing */
	if (op->type->sign_final == NULL) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto done;
	}

	rv = op->type->sign_final(op, ulModLen, pSignature, pulSignatureLen);

done:
	if (rv != CKR_BUFFER_TOO_SMALL && pSignature != NULL)
		session_stop_operation(session, SC_PKCS11_OPERATION_SIGN);

	return rv;
}


CK_RV
tmc_pkcs11_sign_size(struct tmc_pkcs11_session *session, CK_ULONG_PTR pLength)
{
    tmc_pkcs11_operation_t *op;
    struct signature_data * data;
    struct tmc_pkcs11_object * key;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE_TYPE type = CKA_MODULUS_BITS;
    int rv;

    rv = session_get_operation(session, SC_PKCS11_OPERATION_SIGN, &op);
    if (rv != CKR_OK)
        return rv;

    data = op->priv_data;
    key = data->key;

    switch (op->mechanism.mechanism)
    {
        case CKM_RSA_X_509:
        case CKM_RSA_PKCS:
        case CKM_SHA1_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA224_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS:
            attr = list_seek(&key->attrs, &type);
            if(!attr)
                return CKR_KEY_HANDLE_INVALID;
            *pLength = (*(CK_ULONG_PTR)attr->pValue) >> 3;//modulus bits / 8
            break;
        case CKM_SM2_SM3_256:
        case CKM_SM2_SM3_256_E:
            *pLength = 64;
            break;
        case CKM_ECDSA:
        case CKM_ECDSA_SHA1:
        case CKM_ECDSA_SHA256:
        case CKM_ECDSA_SHA224:
        case CKM_ECDSA_SHA384:
        case CKM_ECDSA_SHA512:
            //TBD: change length for other ecparam besides spec256k1
            *pLength = 64;
            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
    }


    if (rv != CKR_OK)
        session_stop_operation(session, SC_PKCS11_OPERATION_SIGN);

    return rv;
}

CK_RV
tmc_pkcs11_ver_init(struct tmc_pkcs11_session *session, CK_MECHANISM_PTR pMechanism,
                    struct tmc_pkcs11_object *key, CK_MECHANISM_TYPE key_type)
{
    struct tmc_pkcs11_card *p11card;
    tmc_pkcs11_operation_t *operation;
    tmc_pkcs11_mechanism_type_t *mt;
    int rv;

    if (!session || !session->slot
        || !(p11card = session->slot->p11card))
        return CKR_ARGUMENTS_BAD;

    /* See if we support this mechanism type */
    mt = tmc_pkcs11_find_mechanism(p11card, pMechanism->mechanism, CKF_VERIFY);
    if (mt == NULL)
        return CKR_MECHANISM_INVALID;

    /* See if compatible with key type */
    if (mt->key_type != key_type)
        return CKR_KEY_TYPE_INCONSISTENT;

    rv = session_start_operation(session, SC_PKCS11_OPERATION_VERIFY, mt, &operation);
    if (rv != CKR_OK)
        return rv;

    memcpy(&operation->mechanism, pMechanism, sizeof(CK_MECHANISM));

    rv = mt->verif_init(operation, key);

    if (rv != CKR_OK)
        session_stop_operation(session, SC_PKCS11_OPERATION_VERIFY);

    return rv;

}

CK_RV
tmc_pkcs11_ver(struct tmc_pkcs11_session *session, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
               CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    struct tmc_pkcs11_operation *op;
    struct signature_data *data;
    struct tmc_pkcs11_object *key;
    struct tmc_pkcs11_operation *md_op;
    CK_ULONG tmp = 0;
    CK_RV rv;

    rv = session_get_operation(session, SC_PKCS11_OPERATION_VERIFY, &op);
    if (rv != CKR_OK)
        return rv;
    data = op->priv_data;
    key = data->key;
    md_op = data->md;

    memcpy(data->buffer, pData, ulDataLen);
    
    if(md_op)
    {
        switch (md_op->type->mech)
        {
            case CKM_SHA_1:
                tmp = SHA1_HASH_SIZE;
                break;
            case CKM_SHA256:
                tmp = SHA256_HASH_SIZE;
                break;
            case CKM_SHA224:
                tmp = SHA224_HASH_SIZE;
                break;
            case CKM_SHA384:
                tmp = SHA384_HASH_SIZE;
                break;
            case CKM_SHA512:
                tmp = SHA512_HASH_SIZE;
                break;
            case CKM_SM3_256:
                tmp = SM3_HASH_SIZE;
                break;
            default:
                return CKR_MECHANISM_INVALID;
        }
        
        rv = md_op->type->md_update(md_op, data->buffer, ulDataLen);
        if(rv != CKR_OK)
            goto error;

        rv = md_op->type->md_final(md_op, data->buffer, &tmp);
        if(rv != CKR_OK)
            goto error;

        ulDataLen = tmp;
    }

    //add by zhangzch sdk process padding for RSA -- hirain test
    if(op->mechanism.mechanism == CKM_RSA_PKCS) {
        CK_ATTRIBUTE_PTR attr;
        CK_ATTRIBUTE_TYPE type = CKA_MODULUS_BITS;
        CK_ULONG ulRsaModLen;

        attr = list_seek(&key->attrs, &type);
        if(!attr)
            return CKR_KEY_HANDLE_INVALID;
        ulRsaModLen = *(CK_ULONG_PTR)attr->pValue;
        ulRsaModLen >>= 3;
        tmp = sizeof(data->buffer);
        rsa_pkcs1_v15_padding(data->buffer, ulDataLen, ulRsaModLen, data->buffer, &tmp);
        ulDataLen = tmp;
    }

    rv = key->ops->signVerify(session, key, data->buffer, ulDataLen, pSignature, ulSignatureLen);


    error:
        session_stop_operation(session, SC_PKCS11_OPERATION_VERIFY);

    return rv;

}

CK_RV
tmc_pkcs11_ver_update(struct tmc_pkcs11_session *session,
		      CK_BYTE_PTR pData, CK_ULONG ulDataLen)
{
	tmc_pkcs11_operation_t *op;
	int rv;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_VERIFY, &op);
	if (rv != CKR_OK)
		return rv;

	if (op->type->verif_update == NULL) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto done;
	}

	rv = op->type->verif_update(op, pData, ulDataLen);

done:
	if (rv != CKR_OK)
		session_stop_operation(session, SC_PKCS11_OPERATION_VERIFY);

	return rv;
}

CK_RV
tmc_pkcs11_ver_final(struct tmc_pkcs11_session *session,
		     CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	tmc_pkcs11_operation_t *op;
	int rv;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_VERIFY, &op);
	if (rv != CKR_OK)
		return rv;

	if (op->type->verif_final == NULL) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto done;
	}

	rv = op->type->verif_final(op, pSignature, ulSignatureLen);

done:
	session_stop_operation(session, SC_PKCS11_OPERATION_VERIFY);
	return rv;
}

CK_RV
tmc_pkcs11_digest_init(struct tmc_pkcs11_session *session,
			CK_MECHANISM_PTR pMechanism)
{
   struct tmc_pkcs11_card *p11card;
	tmc_pkcs11_operation_t *operation;
	tmc_pkcs11_mechanism_type_t *mt;
	int rv;

	if (!session || !session->slot || !(p11card = session->slot->p11card))
	    rv = CKR_ARGUMENTS_BAD;

	/* See if we support this mechanism type */
	mt = tmc_pkcs11_find_mechanism(p11card, pMechanism->mechanism, CKF_DIGEST);
	if (mt == NULL)
    {
        rv = CKR_MECHANISM_INVALID;
        goto error;
    }


	rv = session_start_operation(session, SC_PKCS11_OPERATION_DIGEST, mt, &operation);
	if (rv != CKR_OK)
    {
	    goto error;
    }

	memcpy(&operation->mechanism, pMechanism, sizeof(CK_MECHANISM));

	rv = mt->md_init(operation);
    error:
	if (rv != CKR_OK)
		session_stop_operation(session, SC_PKCS11_OPERATION_DIGEST);

    return  rv;

}

CK_RV
tmc_pkcs11_digest_update(struct tmc_pkcs11_session *session,
                     CK_BYTE_PTR pData, CK_ULONG ulDataLen)
{
    tmc_pkcs11_operation_t *op;
    int rv;

    rv = session_get_operation(session, SC_PKCS11_OPERATION_DIGEST, &op);
    if (rv != CKR_OK)
        return rv;

    if (op->type->md_update == NULL) {
        rv = CKR_KEY_TYPE_INCONSISTENT;
        goto done;
    }

    rv = op->type->md_update(op, pData, ulDataLen);

    done:
    //session_stop_operation(session, SC_PKCS11_OPERATION_DIGEST);
    return rv;
}


CK_RV
tmc_pkcs11_digest_final(struct tmc_pkcs11_session *session,
			CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	tmc_pkcs11_operation_t *op;
	CK_RV rv;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_DIGEST, &op);
	if (rv != CKR_OK)
		return rv;

	/* This is a request for the digest length */
	if (pData == NULL)
    {
	    switch (op->mechanism.mechanism)
        {
            case CKM_SHA_1:
                *pulDataLen = SHA1_HASH_SIZE;
                break;
            case CKM_SHA224:
                *pulDataLen = SHA224_HASH_SIZE;
                break;
            case CKM_SHA256:
                *pulDataLen = SHA256_HASH_SIZE;
                break;
            case CKM_SHA384:
                *pulDataLen = SHA384_HASH_SIZE;
                break;
            case CKM_SHA512:
                *pulDataLen = SHA512_HASH_SIZE;
                break;
            case CKM_SM3_256:
                *pulDataLen = SM3_HASH_SIZE;
                break;
            default:
                return CKR_MECHANISM_INVALID;
        }
        return CKR_OK;
    }

	rv = op->type->md_final(op, pData, pulDataLen);
	if (rv == CKR_BUFFER_TOO_SMALL || !pData)
		return rv;

	session_stop_operation(session, SC_PKCS11_OPERATION_DIGEST);
	return rv;
}
static CK_RV
tmc_assert_user_priv(struct tmc_pkcs11_session *session,
                     CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    CK_BBOOL isPrivate = FALSE;
    CK_BBOOL isToken = TRUE;
    CK_BBOOL isDefault = TRUE; 
    
    
    
    for(CK_ULONG i = 0; i < ulCount; i++)
    {
        switch (pTemplate->type)
        {
            case CKA_PRIVATE:
                isPrivate = *(CK_BBOOL *)(pTemplate->pValue);
                break;
            case CKA_TOKEN:
                isToken = *(CK_BBOOL *)(pTemplate->pValue);
                isDefault = FALSE;
                break;
            case CKA_CLASS:
                //secret object is a session object in default 
                isToken &= !(*(CK_BBOOL *)(pTemplate->pValue) == CKO_SECRET_KEY
                        && isDefault); 
                break;
            default:
                break;
        }
        
        pTemplate++;
    }

    if((!(session->flags & CKF_RW_SESSION)) && isToken)
        return CKR_SESSION_READ_ONLY;
    
    if(isPrivate && (session->slot->login_user != CKU_USER))
        return CKR_USER_NOT_LOGGED_IN;
    return CKR_OK;
}

CK_RV tmc_create_object_int(CK_SESSION_HANDLE hSession,	/* the session's handle */
                           CK_ATTRIBUTE_PTR pTemplate,		/* the object's template */
                           CK_ULONG ulCount,			/* attributes in template */
                           CK_OBJECT_HANDLE_PTR phObject,		/* receives new object's handle. */
                           int use_lock)
{
    CK_RV rv = CKR_OK;
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_card *card;
    if (pTemplate == NULL_PTR || ulCount == 0)
        return CKR_ARGUMENTS_BAD;
    if (use_lock) {
        rv = tmc_pkcs11_lock();
        if (rv != CKR_OK)
            return rv;
    }
    session = list_seek(&sessions, &hSession);
    if (!session) {
        rv = CKR_SESSION_HANDLE_INVALID;
        goto out;
    }

    rv = tmc_assert_user_priv(session, pTemplate, ulCount);
    if(rv != CKR_OK)
        goto out;
    
    card = session->slot->p11card;
    if (card->framework->create_object == NULL)
        rv = CKR_FUNCTION_NOT_SUPPORTED;
    else
        rv = card->framework->create_object(hSession, pTemplate, ulCount, phObject);
    return  rv;

    out:
    if (use_lock)
        tmc_pkcs11_unlock();
    return rv;
}
CK_RV tmc_pkcs11_get_mechanism_list(struct tmc_pkcs11_card *p11card,
				CK_MECHANISM_TYPE_PTR pList,
				CK_ULONG_PTR pulCount)
{
	tmc_pkcs11_mechanism_type_t *mt;
	unsigned int n, count = 0;
	int rv;

	if (!p11card)
		return CKR_TOKEN_NOT_PRESENT;

	for (n = 0; n < p11card->nmechanisms; n++) {
		if (!(mt = p11card->mechanisms[n]))
			continue;
		if (pList && count < *pulCount)
			pList[count] = mt->mech;
		count++;
	}

	rv = CKR_OK;
	if (pList && count > *pulCount)
		rv = CKR_BUFFER_TOO_SMALL;
	*pulCount = count;
	return rv;
}

CK_RV tmc_pkcs11_get_mechanism_info(struct tmc_pkcs11_card *p11card,
			CK_MECHANISM_TYPE mechanism,
			CK_MECHANISM_INFO_PTR pInfo)
{
	tmc_pkcs11_mechanism_type_t *mt;

	if (!(mt = tmc_pkcs11_find_mechanism(p11card, mechanism, 0)))
		return CKR_MECHANISM_INVALID;
	memcpy(pInfo, &mt->mech_info, sizeof(*pInfo));
	return CKR_OK;
}
CK_RV get_card_by_session(CK_SESSION_HANDLE hSession, struct tmc_card **card)
{
    struct tmc_pkcs11_session *session;

    session = (struct tmc_pkcs11_session*)list_seek(&sessions, &hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;

    *card = session->slot->p11card->card;
    if (!*card) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    return CKR_OK;
}
CK_RV get_slot_from_session(CK_SESSION_HANDLE hSession, struct tmc_pkcs11_slot **slot)
{
    struct tmc_pkcs11_session *session;

    session = (struct tmc_pkcs11_session*)list_seek(&sessions, &hSession);
    if (!session)
        return CKR_SESSION_HANDLE_INVALID;

    *slot = session->slot;
    if (!*slot) {
        return CKR_TOKEN_NOT_PRESENT;
    }
    return CKR_OK;
}

