//
// Created by Administrator on 2018/8/8.
//

#include <stdlib.h>
#include <string.h>


#include "sdk.h"
#include "gcm128.h"

CK_BYTE g_manageFile[16];
CK_BYTE g_attrArr[3500];
CK_BYTE g_tempBuff[1024];

extern tmc_context_t *context;
static struct tmc_pkcs11_object_ops secret_ops;
static struct tmc_pkcs11_object_ops pub_ops;
static struct tmc_pkcs11_object_ops priv_ops;
static struct tmc_pkcs11_object_ops data_cert_ops;
CK_BYTE ec_secp256k1[0x00CB] = {0x00,0x20,
              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
              0x00,0x20,
              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,
              0x00,0x41,
              0x04,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,
              0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
              0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,
              0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98,
              0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,
              0x5D,0xA4,0xFB,0xFC,0x0E,0x11,0x08,0xA8,
              0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,
              0x9C,0x47,0xD0,0x8F,0xFB,0x10,0xD4,0xB8,
              0x00,0x20,
              0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
              0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
              0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
              0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41,
              0x00,0x20,
              0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
              0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
              0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
              0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,};

CK_BBOOL gIsTrue = CK_TRUE;
CK_BBOOL gIsFalse = CK_FALSE;
CK_ATTRIBUTE gAttrToken[2] = {CKA_TOKEN,&gIsFalse,sizeof(gIsTrue),
                                CKA_TOKEN,&gIsTrue,sizeof(gIsFalse)};

/** object function */
CK_RV tmc_add_default_attr(struct tmc_pkcs11_object *obj,CK_ATTRIBUTE_TYPE attrType) {
    if (!obj) {
        return CKR_ARGUMENTS_BAD;
    }
    switch (attrType) {
        case CKA_CLASS:

            break;
        case CKA_TOKEN:

            break;
        case CKA_KEY_TYPE:

            break;
        default:
            return CKR_ATTRIBUTE_TYPE_INVALID;
    }

}
void tmc_delete_object_attrs(struct tmc_pkcs11_object *obj) {
    CK_ATTRIBUTE_PTR attr;
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
void tmc_add_object(struct tmc_pkcs11_slot *slot, struct tmc_pkcs11_object *obj,
                    CK_OBJECT_HANDLE_PTR pHandle)
{
    CK_OBJECT_HANDLE handle =
            (CK_OBJECT_HANDLE)(uintptr_t)obj;
    if (list_contains(&slot->objects, obj))
        return;
    list_append(&slot->objects, obj);

    obj->handle = handle;
    *pHandle = handle;
}
CK_RV tmc_find_alloc_ec_param(CK_BYTE_PTR paramName, CK_BYTE **pParam,CK_ULONG_PTR pParamLen,CK_ULONG_PTR pKeybits)
{

    if (strcmp(paramName,ec_curve_infos[0].oid_encoded) != 0) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    else {
        *pParam = (CK_BYTE *)&ec_secp256k1[0];
        *pParamLen = sizeof(ec_secp256k1);
        if (pKeybits) {
            *pKeybits = 0x0100;//256
        }
    }
    return CKR_OK;
}

CK_RV array_to_attr_list(CK_BYTE_PTR pAttr,CK_ULONG length, struct tmc_pkcs11_object *obj) {
    CK_RV rv;
    CK_ULONG offset;
    CK_ATTRIBUTE_PTR attr;
    CK_ULONG attr_type = 0,attr_length = 0;

    // save attribute in sdk
    for (offset = 0; offset < length;) {

        attr = calloc(1,sizeof(CK_ATTRIBUTE));
        if (!attr) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }

        //Attribute's Type
        memcpy(&attr_type,pAttr,SIZE_CK_ULONG);
        attr->type = attr_type;
        pAttr+=SIZE_CK_ULONG;

        //Attribute's Length
        memcpy(&attr_length,pAttr,SIZE_CK_ULONG);
        attr->ulValueLen = attr_length;
        pAttr+=SIZE_CK_ULONG;
		
        //There is invaild space in EF, just ignore it.
        if (attr_length == 0) {
            free(attr);
            return CKR_OK;
        }
        attr->pValue = calloc(1,attr_length);
        if (!attr->pValue) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }

        //Attribute's Value
        memcpy(attr->pValue,pAttr,attr_length);
        pAttr+=attr_length;

        if ( 0 > list_append(&obj->attrs,attr)) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }

//	debug code
//	tmc_printf_t("Attribute's Address = %p\n",attr);
//	tmc_printf_t("Attribute's Type = %08X\n",attr->type);
//	tmc_printf_t("Attribute's Length = %08X\n",attr->ulValueLen);
//	tmc_printf_t("Attribute's Value = ");
//	for(int i=0;i<attr->ulValueLen;i++) {
//		tmc_printf("%02X",((CK_BYTE*)attr->pValue)[i]);
//	}
//	tmc_printf("\n\n");
		
        offset += (SIZE_CK_ULONG + SIZE_CK_ULONG + attr_length);
    }
    return CKR_OK;

    err:
    free(attr);
    list_destroy(&obj->attrs);
    return rv;
}
CK_RV attribute_list_to_array(const void *el, CK_ULONG attrsLen) {
    CK_ULONG listEleCnt = list_size(el);
    CK_ULONG i,length = 0;
    CK_BYTE_PTR attrArr = g_attrArr;

    CK_ATTRIBUTE_PTR attr;
    if ( el == NULL_PTR || listEleCnt == 0) {
        return CKR_ARGUMENTS_BAD;
    }

    //检查目标数组的大小是否足够.
    if (sizeof(g_attrArr) < attrsLen) {
        return CKR_HOST_MEMORY;
    }

    memset(g_attrArr,0, sizeof(g_attrArr));

    //对象属性列表保存到数组中.
    for (i=0; i < listEleCnt; i++) {
        attr = list_get_at(el,i);

        memcpy(attrArr,&attr->type,SIZE_CKA_TYPE);
        attrArr+=SIZE_CKA_TYPE;

        memcpy(attrArr,&attr->ulValueLen,SIZE_CK_ULONG);
        attrArr+=SIZE_CK_ULONG;

        memcpy(attrArr,attr->pValue,attr->ulValueLen);
        attrArr+=attr->ulValueLen;

        length += (SIZE_CKA_TYPE+SIZE_CK_ULONG+attr->ulValueLen);
    }

    if (attrsLen != length) {
        return CKR_ARGUMENTS_BAD;
    }
    return CKR_OK;
}
CK_RV attr_storage(CK_BBOOL isSkipVal, CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount,void *ptr, CK_ULONG_PTR pAttrSize) {
    CK_RV rv;
    int i;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE_PTR attrTemp[ulCount+1];//为CKA_VALUE_LEN预留
    CK_BBOOL HasVLen = CK_FALSE;
    CK_ULONG attrSize = 0,valueLen = 0;
    CK_ULONG attrCount = ulCount;

    // save attribute template.
    for (i = 0; i < ulCount; i++,pTemplate++) {

        attr = pTemplate;

        if (!(attr->ulValueLen))
        {
            rv = CKR_TEMPLATE_INCONSISTENT;
            goto err;
        }

        if ((attr->type == CKA_VALUE) || (attr->type == CKA_MODULUS) ||
                ((attr->type >= CKA_PRIVATE_EXPONENT) && (attr->type <=  CKA_COEFFICIENT))
                ) {
            valueLen = attr->ulValueLen;

            if (isSkipVal) {
                continue;//需要单独处理对象的value
            }
        }
        if (attr->type == CKA_MODULUS_BITS) {
            valueLen = (*(CK_ULONG_PTR) (attr->pValue))/8;
        }

        if (attr->type == CKA_VALUE_LEN) {
            HasVLen = CK_TRUE;
        }

        attrTemp[i] = calloc(1,sizeof(CK_ATTRIBUTE));
        attrSize += SIZE_CKA_TYPE;
        if (attrTemp[i]  == NULL_PTR) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }

        attrTemp[i]->pValue = calloc(1,attr->ulValueLen);
        if (attrTemp[i] ->pValue == NULL_PTR) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }
        memcpy(attrTemp[i]->pValue, attr->pValue, attr->ulValueLen);
        attrTemp[i]->ulValueLen = attr->ulValueLen;
        attrTemp[i]->type = attr->type;
        attrSize += attr->ulValueLen;
        attrSize += SIZE_CK_ULONG;
        //add attribute to the attrs-list of object
        rv = list_append(ptr,attrTemp[i]);
        if (rv <0) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }

    }
    //添加CKA_VALUE_LEN
    if (!HasVLen) {
        attrTemp[i] = calloc(1,sizeof(CK_ATTRIBUTE));
        attrCount += 1;

        attrTemp[i]->type = CKA_VALUE_LEN;
        attrSize+= sizeof(CK_ULONG);
        attrTemp[i]->ulValueLen = SIZE_CK_ULONG;
        attrSize+= sizeof(CK_ULONG);

        attrTemp[i]->pValue = (CK_ULONG *) calloc(1,SIZE_CK_ULONG);
        memcpy(attrTemp[i]->pValue,&valueLen,SIZE_CK_ULONG);
        attrSize+= attrTemp[i]->ulValueLen;
        rv = list_append(ptr,attrTemp[i]);

        if (rv <0) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }
    }

    *pAttrSize = attrSize ;
    return CKR_OK;

    err:
    for (i = 0; i < attrCount; i++) {
        if (attrTemp[i] != NULL_PTR) {
            if (attrTemp[i]->pValue != NULL_PTR) {
                free(attrTemp[i]->pValue);
            }
            free(attrTemp[i]);
        }
    }

    if (ptr != NULL_PTR) {
        list_destroy(ptr);
        free(ptr);
    }
    return rv;
}
CK_RV attr_find_ptr(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ULONG type, void **ptr, CK_ULONG * sizep)
{
    unsigned int n;

    for (n = 0; n < ulCount; n++, pTemplate++) {
        if (pTemplate->type == type)
            break;
    }

    if (n >= ulCount)
        return CKR_TEMPLATE_INCOMPLETE;

    if (sizep)
        *sizep = pTemplate->ulValueLen;
    *ptr = pTemplate->pValue;
    return CKR_OK;
}
CK_RV attr_extract(CK_ATTRIBUTE_PTR pAttr, void *ptr, CK_ULONG_PTR sizep) {
    unsigned int size;

    if (sizep) {
        size = *sizep;
        if (size < pAttr->ulValueLen)
            return CKR_ATTRIBUTE_VALUE_INVALID;
        *sizep = pAttr->ulValueLen;
    } else {
        switch (pAttr->type) {
            case CKA_CLASS:
                size = sizeof(CK_OBJECT_CLASS);
                break;
            case CKA_KEY_TYPE:
                size = sizeof(CK_KEY_TYPE);
                break;
            case CKA_PRIVATE:
            case CKA_TOKEN:
                size = sizeof(CK_BBOOL);
                break;
            case CKA_CERTIFICATE_TYPE:
                size = sizeof(CK_CERTIFICATE_TYPE);
                break;
            case CKA_VALUE_LEN:
            case CKA_MODULUS_BITS:
                size = sizeof(CK_ULONG);
                break;
            case CKA_OBJECT_ID:
                //size = sizeof(struct sc_object_id);
                break;
            case CKA_ID:
                size = pAttr->ulValueLen;
                break;
            case CKA_VALUE:
                size = pAttr->ulValueLen;
                break;
            default:
                return CKR_FUNCTION_FAILED;
        }
        if (size != pAttr->ulValueLen)
            return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    memcpy(ptr, pAttr->pValue, pAttr->ulValueLen);
    return CKR_OK;
}

CK_RV attr_find(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ULONG type, void *ptr, CK_ULONG_PTR sizep)
{
    unsigned int n;

    for (n = 0; n < ulCount; n++, pTemplate++) {
        if (pTemplate->type == type)
            break;
    }

    if (n >= ulCount)
        return CKR_TEMPLATE_INCOMPLETE;
    return attr_extract(pTemplate, ptr, sizep);
}
CK_RV attr_find2(CK_ATTRIBUTE_PTR pTemp1, CK_ULONG ulCount1,
                 CK_ATTRIBUTE_PTR pTemp2, CK_ULONG ulCount2, CK_ULONG type, void *ptr, CK_ULONG_PTR sizep)
{
    CK_RV rv;

    rv = attr_find(pTemp1, ulCount1, type, ptr, sizep);
    if (rv != CKR_OK)
        rv = attr_find(pTemp2, ulCount2, type, ptr, sizep);

    return rv;
}
CK_RV attr_find_alloc(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ULONG type, void **ptr, CK_ULONG_PTR sizep)
{
    unsigned int n;
    void * tmp_ptr = NULL_PTR;
    CK_RV rv;

    for (n = 0; n < ulCount; n++, pTemplate++) {
        if (pTemplate->type == type) {
            tmp_ptr = calloc(1, pTemplate->ulValueLen);
            if(!tmp_ptr) {
                return CKR_HOST_MEMORY;
            }
            break;
        }
    }

    if (n >= ulCount)
        return CKR_TEMPLATE_INCOMPLETE;
    *sizep = pTemplate->ulValueLen;
    rv = attr_extract(pTemplate, tmp_ptr, sizep);
    if(rv != CKR_OK)
    {
        free(tmp_ptr);
        return rv;
    }
    *ptr = tmp_ptr;
    return rv;
}
//匹配返回1
CK_RV tmc_cmp_attribute(struct tmc_pkcs11_session *session,
                   void *object, CK_ATTRIBUTE_PTR attr) {
                   
    struct tmc_pkcs11_object *obj = (struct tmc_pkcs11_object *) object;

    CK_ATTRIBUTE_PTR obj_attr;
    CK_RV rv = CK_FALSE;
    CK_ULONG i;
    for (i=0;i<list_size(&obj->attrs);i++) {
        obj_attr = (CK_ATTRIBUTE_PTR)list_get_at(&obj->attrs,i);
        if (obj_attr->type == attr->type) {
            if (attr->ulValueLen == obj_attr->ulValueLen &&
                !memcmp(attr->pValue,obj_attr->pValue,attr->ulValueLen)) {
                return CK_TRUE;
            }
        }
    }
    return rv;
}
CK_RV add_new_attribute (struct tmc_pkcs11_object *obj,CK_ATTRIBUTE_TYPE attrType,
            void* hValue,CK_ULONG_PTR pAttrsLen) {
    CK_ATTRIBUTE_PTR attr = NULL_PTR;
    CK_ULONG_PTR pValue = NULL_PTR;
    CK_ULONG length = 0;
    CK_RV rv;

    if (!obj) {
        return CKR_ARGUMENTS_BAD;
    }
    attr = calloc(1,sizeof(CK_ATTRIBUTE));
    if (!attr) {
        return CKR_HOST_MEMORY;
    }

    switch (attrType) {
        case CKA_TOKEN:
        case CKA_PRIVATE:
            length = sizeof(CK_BBOOL);
            break;
        case CKA_KEY_TYPE:
        case CKA_CLASS:
        case CKA_VALUE_LEN:
        case CKA_MODULUS_BITS:
            length = sizeof(CK_ULONG);
            break;
        default:
            rv = CKR_ATTRIBUTE_TYPE_INVALID;
            goto err;
    }
    pValue = calloc(1,length);
    if (!pValue) {
        rv = CKR_HOST_MEMORY;
        goto err;
    }
    memcpy(pValue,hValue,length);

    attr->type = attrType;
    attr->ulValueLen = length;
    attr->pValue = pValue;

    //add attr into attr list.
    if (0 > list_append(&obj->attrs,attr)) {
        rv = CKR_HOST_MEMORY;
        goto err;
    }

    //change the length of attr list.
    *pAttrsLen += (SIZE_CKA_TYPE + SIZE_CK_ULONG + length);

    return CKR_OK;

    err:
        if (pValue) {
            free(pValue);
        }
        if (attr) {
            free(attr);
        }
        return rv;
}
/* Following two are only implemented with internal PC/SC and don't consume a reader object */

/** operation function */

CK_RV session_get_operation(struct tmc_pkcs11_session * session, int type, tmc_pkcs11_operation_t ** operation)
{
    tmc_pkcs11_operation_t *op;


    if (type < 0 || type >= SC_PKCS11_OPERATION_MAX)
        return CKR_ARGUMENTS_BAD;
   if (!(op = session->operation[type]))
        return CKR_OPERATION_NOT_INITIALIZED;

    if (operation)
        *operation = op;

    return CKR_OK;
}

tmc_pkcs11_operation_t *
tmc_pkcs11_new_operation(struct tmc_pkcs11_session *session,
                         tmc_pkcs11_mechanism_type_t *type)
{
    tmc_pkcs11_operation_t *res;
    res = (tmc_pkcs11_operation_t*)calloc(1, type->obj_size);
    if (res) {
        res->session = session;
        res->type = type;
    }
    return res;
}

/** algorithm impl operation*/

void
tmc_pkcs11_release_operation(tmc_pkcs11_operation_t **ptr)
{
    tmc_pkcs11_operation_t *operation = *ptr;

    if (!operation)
        return;
    if (operation->type && operation->type->release)
        operation->type->release(operation);
    memset(operation, 0, sizeof(*operation));
    free(operation);
    *ptr = NULL;
}

/* Session manipulation */
CK_RV session_start_operation(struct tmc_pkcs11_session * session,
                              int type, tmc_pkcs11_mechanism_type_t * mech, struct tmc_pkcs11_operation ** operation)
{
    tmc_pkcs11_operation_t *op;

    if (context == NULL)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    if (type < 0 || type >= SC_PKCS11_OPERATION_MAX)
        return CKR_ARGUMENTS_BAD;

    if (session->operation[type] != NULL)
        return CKR_OPERATION_ACTIVE;

    if (!(op = tmc_pkcs11_new_operation(session, mech)))
        return CKR_HOST_MEMORY;

    session->operation[type] = op;
    if (operation)
        *operation = op;

    return CKR_OK;
}


CK_RV session_stop_operation(struct tmc_pkcs11_session * session, int type)
{
    if (type < 0 || type >= SC_PKCS11_OPERATION_MAX)
        return CKR_ARGUMENTS_BAD;

    if (session->operation[type] == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;
    tmc_pkcs11_release_operation(&session->operation[type]);
    return CKR_OK;
}

/* Also used for verification data */
struct hash_signature_info {
    CK_MECHANISM_TYPE	mech;
    CK_MECHANISM_TYPE	hash_mech;
    CK_MECHANISM_TYPE	sign_mech;
    tmc_pkcs11_mechanism_type_t *hash_type;
    tmc_pkcs11_mechanism_type_t *sign_type;
};


static CK_RV cipher_unpadding(CK_MECHANISM_PTR mech, u8* pData, u8* pPaddern,
                              CK_ULONG_PTR pUldataLen)
{
    u_int32_t tmpLen;
    switch (mech->mechanism)
    {
        //采用PKCS#7填充，解填充
        case CKM_AES_CBC_PAD:
        case CKM_DES_CBC_PAD:
        case CKM_DES3_CBC_PAD:
        case CKM_SM4_CBC_PAD:
            tmpLen = (u_int32_t)(pPaddern[*pUldataLen - 1] & 0xff);
            *pUldataLen -= tmpLen;
            break;
        default:
            break;
    }

    if(*pUldataLen < 0)
        return CKR_BUFFER_TOO_SMALL;

    if(pData)
    {
        memcpy(pData, pPaddern, *pUldataLen);
    }

    return CKR_OK;
}

static CK_RV cipher_padding(CK_MECHANISM_PTR mech, u8* pData, u8* pPaddern,
                            CK_ULONG pUldataLen, CK_ULONG block_size)
{
    u_int32_t tmpLen = 0;
    switch (mech->mechanism)
    {
        //采用PKCS#7填充，填充
        case CKM_AES_CBC_PAD:
        case CKM_DES_CBC_PAD:
        case CKM_DES3_CBC_PAD:
        case CKM_SM4_CBC_PAD:
            tmpLen = (u_int32_t)(block_size - pUldataLen);
            break;
        case CKM_SM4_CBC:
        case CKM_SM4_ECB:
        case CKM_SM1_CBC:
        case CKM_SM1_ECB:
        case CKM_SM1_CBC_PAD:
        case CKM_AES_CBC:
        case CKM_AES_ECB:
        case CKM_DES3_CBC:
        case CKM_DES3_ECB:
        case CKM_DES_CBC:
        case CKM_DES_ECB:
            break;
        default:
            return CKR_OK;
    }



    memcpy(pPaddern, pData, pUldataLen);
    pPaddern += pUldataLen;
    if(tmpLen)
        memset(pPaddern , (u8)tmpLen, tmpLen);

    return CKR_OK;
}

static void
tmc_pkcs11_signature_release(tmc_pkcs11_operation_t *operation)
{
    struct signature_data *data;
    data = (struct signature_data *) operation->priv_data;
    if (!data)
        return;
    tmc_pkcs11_release_operation(&data->md);
    memset(data, 0, sizeof(*data));
    free(data);
}

static  void
tmc_pkcs11_agreement_release(tmc_pkcs11_operation_t *operation)
{
    struct agreement_data *data;
    data = (struct agreement_data *) operation->priv_data;
    if (!data)
        return;
    memset(data, 0, sizeof(*data));
    free(data);
}

static void
tmc_pkcs11_digest_release(tmc_pkcs11_operation_t *operation)
{
    void *data;

    data = operation->priv_data;
    if (!data)
        return;
    memset(data, 0, sizeof(*data));
    free(data);
}

/*
 * Initialize a signature operation
 */
static CK_RV
tmc_pkcs11_signature_init(tmc_pkcs11_operation_t *operation,
                          struct tmc_pkcs11_object *key)
{
    struct hash_signature_info *info;
    struct signature_data *data;
    CK_RV rv;
    int can_do_it = 0;

    if (!(data = (struct signature_data *)calloc(1, sizeof(*data))))
        return CKR_HOST_MEMORY;
    data->info = NULL;
    data->key = key;

    if (key->ops->can_do)   {
        rv = key->ops->can_do(operation->session, key, operation->type->mech, CKF_SIGN);
        if (rv == CKR_OK)   {
            /* Mechanism recognised and can be performed by pkcs#15 card */
            can_do_it = 1;
        }
        else if (rv == CKR_FUNCTION_NOT_SUPPORTED)   {
            /* Mechanism not recognised by pkcs#15 card */
            can_do_it = 0;
        }
        else  {
            /* Mechanism recognised but cannot be performed by pkcs#15 card, or some general error. */
            free(data);
            return rv;
        }
    }

    /* If this is a signature with hash operation,
     * and card cannot perform itself signature with hash operation,
     * set up the hash operation */
    info = (struct hash_signature_info *) operation->type->mech_data;
    if (info != NULL && !can_do_it) {
        /* Initialize hash operation */

        data->md = tmc_pkcs11_new_operation(operation->session, info->hash_type);
        if (data->md == NULL)
            rv = CKR_HOST_MEMORY;
        else
            rv = info->hash_type->md_init(data->md);
        if (rv != CKR_OK) {
            tmc_pkcs11_release_operation(&data->md);
            free(data);
            return rv;
        }
        data->info = info;
    }

    operation->priv_data = data;
    return CKR_OK;
}
static CK_RV
tmc_pkcs11_verify_init(tmc_pkcs11_operation_t *operation,
                          struct tmc_pkcs11_object *key)
{
    struct hash_signature_info *info;
    struct signature_data *data;
    CK_RV rv;
    int can_do_it = 0;

    if (!(data = (struct signature_data *)calloc(1, sizeof(*data))))
        return CKR_HOST_MEMORY;
    data->info = NULL;
    data->key = key;

    if (key->ops->can_do)   {
        rv = key->ops->can_do(operation->session, key, operation->type->mech, CKF_SIGN);
        if (rv == CKR_OK)   {
            /* Mechanism recognised and can be performed by pkcs#15 card */
            can_do_it = 1;
        }
        else if (rv == CKR_FUNCTION_NOT_SUPPORTED)   {
            /* Mechanism not recognised by pkcs#15 card */
            can_do_it = 0;
        }
        else  {
            /* Mechanism recognised but cannot be performed by pkcs#15 card, or some general error. */
            free(data);
            return rv;
        }
    }

    /* If this is a signature with hash operation,
     * and card cannot perform itself signature with hash operation,
     * set up the hash operation */
    info = (struct hash_signature_info *) operation->type->mech_data;
    if (info != NULL && !can_do_it) {
        /* Initialize hash operation */

        data->md = tmc_pkcs11_new_operation(operation->session, info->hash_type);
        if (data->md == NULL)
            rv = CKR_HOST_MEMORY;
        else
            rv = info->hash_type->md_init(data->md);
        if (rv != CKR_OK) {
            tmc_pkcs11_release_operation(&data->md);
            free(data);
            return rv;
        }
        data->info = info;
    }

    operation->priv_data = data;
    return CKR_OK;
}
static CK_RV
tmc_pkcs11_signature_update(tmc_pkcs11_operation_t *operation,
                            CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    struct signature_data *data;

    data = (struct signature_data *) operation->priv_data;
    if (data->md) {
        CK_RV rv = data->md->type->md_update(data->md, pPart, ulPartLen);
        return rv;
    }

    /* This signature mechanism operates on the raw data */
    if (data->buffer_len + ulPartLen > sizeof(data->buffer))
        return CKR_DATA_LEN_RANGE;
    memcpy((CK_BYTE_PTR)(data->buffer + data->buffer_len), pPart, ulPartLen);
    data->buffer_len += ulPartLen;
    return CKR_OK;
}

static CK_RV
tmc_pkcs11_verify_final(tmc_pkcs11_operation_t *operation,
                           CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    struct signature_data *data;
    CK_ULONG ulDataLen;
    CK_RV rv;

    data = (struct signature_data *) operation->priv_data;
    if (data->md) {
        tmc_pkcs11_operation_t	*md = data->md;
        CK_ULONG len = sizeof(data->buffer);

        rv = md->type->md_final(md, data->buffer, &len);
        if (rv == CKR_BUFFER_TOO_SMALL)
            rv = CKR_FUNCTION_FAILED;
        if (rv != CKR_OK)
            return rv;
        data->buffer_len = len;
    }

    //add by zhangzch sdk process padding for RSA -- hirain test
    if(operation->mechanism.mechanism == CKM_RSA_PKCS) {
        CK_ATTRIBUTE_PTR attr;
        CK_ATTRIBUTE_TYPE type = CKA_MODULUS_BITS;
        CK_ULONG ulRsaModLen;

        attr = list_seek(&data->key->attrs, &type);
        if(!attr)
            return CKR_KEY_HANDLE_INVALID;
        ulRsaModLen = *(CK_ULONG_PTR)attr->pValue;
        ulRsaModLen >>= 3;
        rsa_pkcs1_v15_padding(data->buffer, data->buffer_len, ulRsaModLen, data->buffer, &ulDataLen);
    }

    rv = data->key->ops->signVerify(operation->session, data->key,
                              data->buffer, ulDataLen, pSignature, ulSignatureLen);
    return rv;
}

static CK_RV
tmc_pkcs11_signature_final(tmc_pkcs11_operation_t *operation, CK_ULONG ulModLen,
                           CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    struct signature_data *data;
    CK_ULONG ulDataLen = 0;
    CK_RV rv;

    data = (struct signature_data *) operation->priv_data;
    if (data->md) {
        tmc_pkcs11_operation_t	*md = data->md;
        CK_ULONG len = sizeof(data->buffer);

        rv = md->type->md_final(md, data->buffer, &len);
        if (rv == CKR_BUFFER_TOO_SMALL)
            rv = CKR_FUNCTION_FAILED;
        if (rv != CKR_OK)
            return rv;
        data->buffer_len = (unsigned int)len;
    }

    if(operation->mechanism.mechanism == CKM_RSA_PKCS) {

        rv = rsa_pkcs1_v15_padding(data->buffer, data->buffer_len, ulModLen, pSignature, &ulDataLen);
        if (rv != CKR_OK)
            return rv;
    }

    rv = data->key->ops->sign(operation->session, data, pSignature, ulDataLen, pSignature);

    return rv;
}

static CK_RV
tmc_pkcs11_signature_size(tmc_pkcs11_operation_t *operation, CK_ULONG_PTR pLength)
{
    struct tmc_pkcs11_object *key;
    CK_ATTRIBUTE attr = { CKA_MODULUS_BITS, pLength, sizeof(*pLength) };
    CK_KEY_TYPE key_type;
    CK_ATTRIBUTE attr_key_type = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };
    CK_RV rv;

    key = ((struct signature_data *) operation->priv_data)->key;
    /*
     * EC and GOSTR do not have CKA_MODULUS_BITS attribute.
     * But other code in framework treats them as if they do.
     * So should do switch(key_type)
     * and then get what ever attributes are needed.
     */
    rv = key->ops->get_attribute(operation->session, key, &attr_key_type);
    if (rv == CKR_OK) {
        switch(key_type) {
            case CKK_RSA:
                rv = key->ops->get_attribute(operation->session, key, &attr);
                /* convert bits to bytes */
                if (rv == CKR_OK)
                    *pLength = (*pLength + 7) / 8;
                break;
            case CKK_EC:
                /* TODO: -DEE we should use something other then CKA_MODULUS_BITS... */
                rv = key->ops->get_attribute(operation->session, key, &attr);
                *pLength = ((*pLength + 7)/8) * 2 ; /* 2*nLen in bytes */
                break;
            case CKK_GOSTR3410:
                rv = key->ops->get_attribute(operation->session, key, &attr);
                if (rv == CKR_OK)
                    *pLength = (*pLength + 7) / 8 * 2;
                break;
            default:
                rv = CKR_MECHANISM_INVALID;
        }
    }

    return rv;
}

static CK_RV
tmc_pkcs11_derive(tmc_pkcs11_operation_t *operation,
                  struct tmc_pkcs11_object *basekey,
                  CK_OBJECT_HANDLE_PTR phKey)
{


    CK_BYTE_PTR pSeedData;
    CK_ULONG ulSeedDataLen;
    CK_MECHANISM_TYPE kdf_type = CKM_VENDOR_DEFINED;
    CK_ECDH1_DERIVE_PARAMS *params;



    switch (operation->mechanism.mechanism)
    {
        case CKM_DH_PKCS_DERIVE:
            pSeedData = operation->mechanism.pParameter;
            ulSeedDataLen = operation->mechanism.ulParameterLen;
            break;
        case CKM_ECDH1_DERIVE:
            params = (CK_ECDH1_DERIVE_PARAMS *)operation->mechanism.pParameter;
            pSeedData = params->pPublicData;
            ulSeedDataLen = params->ulPublicDataLen;
            kdf_type = params->kdf;
            break;
        default:
            return CKR_MECHANISM_INVALID;
    }

    if(!basekey->ops->derive)
    {
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    return basekey->ops->derive(operation->session, operation->priv_data, operation->mechanism.mechanism,
                         kdf_type, pSeedData,
                         ulSeedDataLen, phKey);

}
static CK_RV
tmc_pkcs11_encrypt_init(tmc_pkcs11_operation_t *operation,
                        struct tmc_pkcs11_object *key)
{
    struct signature_data *data;
    CK_RV rv;

    if (!(data = (struct signature_data *)calloc(1, sizeof(*data))))
        return CKR_HOST_MEMORY;


    data->key = key;

    if (key->ops->can_do) {
        rv = key->ops->can_do(operation->session, key, operation->type->mech, CKF_ENCRYPT);
        if ((rv == CKR_OK) || (rv == CKR_FUNCTION_NOT_SUPPORTED))   {
            /* Mechanism recognized and can be performed by pkcs#15 card or algorithm references not supported */
        }
        else {
            /* Mechanism cannot be performed by pkcs#15 card, or some general error. */
            free(data);
            return rv;
        }
    }
    operation->priv_data = data;
    return CKR_OK;
}

static CK_RV
tmc_pkcs11_md_init(tmc_pkcs11_operation_t *operation)
{
    CK_MECHANISM_TYPE mech_type = operation->type->mech;
    void * digest_context = NULL_PTR;
    switch (mech_type){
        case CKM_SHA_1:
            digest_context = malloc(sizeof(SHA1Context));
            if(!digest_context)
                return CKR_HOST_MEMORY;
            SHA1Init((SHA1Context *)digest_context);
            break;
        case CKM_SHA224:
            digest_context = malloc(sizeof(SHA256Context));
            if(!digest_context)
                return CKR_HOST_MEMORY;
            SHA224Init((SHA256Context *)digest_context);
            break;
        case CKM_SHA256:
            digest_context = malloc(sizeof(SHA256Context));
            if(!digest_context)
                return CKR_HOST_MEMORY;
            SHA256Init((SHA256Context *)digest_context);
            break;
        case CKM_SHA384:
            digest_context = malloc(sizeof(SHA384Context));
            if(!digest_context)
                return CKR_HOST_MEMORY;
            SHA384Init((SHA384Context *)digest_context);
            break;
        case CKM_SHA512:
            digest_context = malloc(sizeof(SHA512Context));
            if(!digest_context)
                return CKR_HOST_MEMORY;
            SHA512Init((SHA512Context *)digest_context);
            break;
        case CKM_SM3_256:
            SM3_Init(&digest_context);
            if(!digest_context)
                return CKR_HOST_MEMORY;
            //TBD
            break;
        default:
            return CKR_MECHANISM_INVALID;
    }
    operation->priv_data = digest_context;

    return CKR_OK;
}

static CK_RV
tmc_pkcs11_md_update(struct tmc_pkcs11_operation *operation,
        CK_BYTE_PTR pData, CK_ULONG pulDataLen)
{
    CK_MECHANISM_TYPE mech_type = operation->type->mech;
    switch (mech_type){
        case CKM_SHA_1:
            SHA1Update((SHA1Context *)operation->priv_data,
                       (const void  *)pData, (unsigned int) pulDataLen);
            break;
        case CKM_SHA224:
        case CKM_SHA256:
            SHA256Update((SHA256Context *)operation->priv_data,
                         (const void  *)pData, (unsigned int) pulDataLen);
            break;
        case CKM_SHA384:
            SHA384Update((SHA384Context *)operation->priv_data,
                         (const void  *)pData, (unsigned int) pulDataLen);
            break;
        case CKM_SHA512:
            SHA512Update((SHA512Context *)operation->priv_data,
                         (const void  *)pData, (unsigned int) pulDataLen);
            break;
        case CKM_SM3_256:
            SM3_Update(operation->priv_data, (const u_int8_t *)pData, (u_int32_t) pulDataLen);
            break;
        default:
            break;
    }
    return CKR_OK;
}

static CK_RV
tmc_pkcs11_md_final(struct tmc_pkcs11_operation *operation,
                     CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    CK_MECHANISM_TYPE mech_type = operation->type->mech;
    switch (mech_type){
        case CKM_SHA_1:
            if(*pulDataLen < SHA1_HASH_SIZE)
            {
                *pulDataLen = SHA1_HASH_SIZE;
                return pData ? CKR_BUFFER_TOO_SMALL : CKR_OK;
            }

            SHA1Final((SHA1Context *)operation->priv_data,
                       (unsigned char *)pData);
            *pulDataLen = SHA1_HASH_SIZE;
            break;
        case CKM_SHA224:
            if(*pulDataLen < SHA224_HASH_SIZE)
            {
                *pulDataLen = SHA224_HASH_SIZE;
                return pData ? CKR_BUFFER_TOO_SMALL : CKR_OK;
            }

            SHA256Final((SHA256Context *)operation->priv_data,
                      (unsigned char *)pData, SHA224_HASH_WORDS);
            *pulDataLen = SHA224_HASH_SIZE;
            break;
        case CKM_SHA256:
            if(*pulDataLen < SHA256_HASH_SIZE)
            {
                *pulDataLen = SHA256_HASH_SIZE;
                return pData ? CKR_BUFFER_TOO_SMALL : CKR_OK;
            }

            SHA256Final((SHA256Context *)operation->priv_data,
                        (unsigned char *)pData, SHA256_HASH_WORDS);
            *pulDataLen = SHA256_HASH_SIZE;
            break;
        case CKM_SHA384:
            if(*pulDataLen < SHA384_HASH_SIZE)
            {
                *pulDataLen = SHA384_HASH_SIZE;
                return pData ? CKR_BUFFER_TOO_SMALL : CKR_OK;
            }

            SHA384Final((SHA384Context *)operation->priv_data,
                        (unsigned char *)pData);
            *pulDataLen = SHA384_HASH_SIZE;
            break;
        case CKM_SHA512:
            if(*pulDataLen < SHA512_HASH_SIZE)
            {
                *pulDataLen = SHA512_HASH_SIZE;
                return pData ? CKR_BUFFER_TOO_SMALL : CKR_OK;
            }

            SHA512Final((SHA512Context *)operation->priv_data,
                        (unsigned char *)pData);
            *pulDataLen = SHA512_HASH_SIZE;
            break;
        case CKM_SM3_256:
            if(*pulDataLen < SM3_HASH_SIZE)
            {
                *pulDataLen = SM3_HASH_SIZE;
                return pData ? CKR_BUFFER_TOO_SMALL : CKR_OK;
            }
            SM3_Final(operation->priv_data,
                        (unsigned char *)pData);
            *pulDataLen = SM3_HASH_SIZE;
            //free(&operation->priv_data);
            operation->priv_data = NULL;
            break;
        default:
            break;
    }
    return CKR_OK;
}

static CK_ULONG get_block_size(CK_MECHANISM_TYPE mech_type)
{
    switch (mech_type)
    {
        case CKM_SM4_CBC:
        case CKM_SM4_ECB:
        case CKM_SM4_CBC_PAD:
        case CKM_SM1_CBC:
        case CKM_SM1_ECB:
        case CKM_SM1_CBC_PAD:
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD:
        case CKM_AES_ECB:
        case CKM_AES_GCM:
            return 16;
        case CKM_DES3_CBC:
        case CKM_DES3_ECB:
        case CKM_DES3_CBC_PAD:
        case CKM_DES_CBC:
        case CKM_DES_ECB:
        case CKM_DES_CBC_PAD:
            return 8;
        default:
            break;
    }
    return 0;
}

static CK_RV get_padded_size(CK_MECHANISM_TYPE mech_type, CK_ULONG_PTR pre_len,
        CK_ULONG block_size)
{
    CK_ULONG range_len = *pre_len;

    switch (mech_type)
    {
        case CKM_SM4_CBC:
        case CKM_SM4_ECB:
        case CKM_SM1_ECB:
        case CKM_AES_ECB:
        case CKM_SM1_CBC:
        case CKM_AES_CBC:
        case CKM_DES3_CBC:
        case CKM_DES_CBC:
        case CKM_DES3_ECB:
        case CKM_DES_ECB:
            range_len = range_len/block_size * block_size;
            if(range_len != *pre_len)
                return CKR_DATA_LEN_RANGE;
            else
                return CKR_OK;
        case CKM_SM4_CBC_PAD:
        case CKM_SM1_CBC_PAD:
        case CKM_AES_CBC_PAD:
        case CKM_DES3_CBC_PAD:
        case CKM_DES_CBC_PAD:
            range_len = range_len/block_size * block_size;
            *pre_len = range_len + block_size;
            return CKR_OK;
        case CKM_SM2_SM3_256:
            *pre_len += SM2_PAD_LEN;
            return CKR_OK;
        case CKM_AES_GCM:
            *pre_len = range_len + 16;
            return CKR_OK;
        default:
            break;
    }
    return CKR_OK;
}


static CK_RV
tmc_pkcs11_encrypt_update(tmc_pkcs11_operation_t *operation,
                   CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                   CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pEncryptedDataLen)
{
    CK_RV rv = CKR_OK;
    CK_ULONG blocksize;
    CK_ULONG tmp;
    struct signature_data *data;
    struct tmc_pkcs11_object *key;
    CK_MECHANISM_PTR mech;

    data = (struct signature_data*) operation->priv_data;
    key = data->key;
    mech = &operation->mechanism;

    blocksize = get_block_size(mech->mechanism);


    if(!blocksize)
        return CKR_MECHANISM_INVALID;

    tmp = ulDataLen;
    //rv = get_padded_size(mech->mechanism, &tmp, blocksize);
    //if(rv != CKR_OK)
    //    return rv;

    //返回需要数组长度
    if(!pEncryptedData)
    {
        *pEncryptedDataLen = tmp;
        return rv;
    }

    //判度用户提供数组是否足够长
    if(*pEncryptedDataLen < tmp)
        return CKR_BUFFER_TOO_SMALL;

    memcpy((CK_BYTE_PTR)pEncryptedData,
           data->buffer,
           (CK_ULONG)data->buffer_len);

    memcpy((CK_BYTE_PTR)(pEncryptedData + data->buffer_len),
           pData,
           (CK_ULONG)(tmp - data->buffer_len));

    rv = key->ops->encrypt(operation->session,
                      key, &operation->mechanism,
                      pEncryptedData,tmp,
                      pEncryptedData, pEncryptedDataLen);

    if(rv != CKR_OK)
    {
        memset(pEncryptedData, 0, tmp);
        return rv;
    }

    tmp = (CK_ULONG)(ulDataLen - tmp + data->buffer_len);
    if(tmp)
    {
        memcpy((CK_BYTE_PTR)(data->buffer),
               (CK_BYTE_PTR)(pData + tmp),
               tmp);
    }

    data->buffer_len = (unsigned int)tmp;
    return rv;
}

static CK_RV
tmc_pkcs11_encrypt_final(tmc_pkcs11_operation_t *operation,
                         CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pEncryptedDataLen)
{
    CK_RV rv = CKR_OK;
    struct signature_data * data = operation->priv_data;
    CK_ULONG tmp = (CK_ULONG)data->buffer_len;
    CK_ULONG blocksize = 0;
    struct tmc_pkcs11_object * key = data->key;

    blocksize = get_block_size(operation->mechanism.mechanism);
    if(!blocksize)
        return CKR_MECHANISM_INVALID;

    rv = get_padded_size(operation->mechanism.mechanism, &tmp, blocksize);
    if(rv != CKR_OK)
        return rv;

    if(!pEncryptedData)
    {
        *pEncryptedDataLen = tmp;
        return rv;
    }

    if(*pEncryptedDataLen < tmp)
        return CKR_BUFFER_TOO_SMALL;

    rv = cipher_padding(&operation->mechanism, (CK_BYTE_PTR)data->buffer,
                        (CK_BYTE_PTR)data->buffer, (CK_ULONG)data->buffer_len, tmp);
    if(rv != CKR_OK)
        return rv;

    return key->ops->encrypt(operation->session,
                           key, &operation->mechanism,
                           data->buffer,tmp,
                           pEncryptedData, pEncryptedDataLen);
}

extern CK_RV tmc_encrypt_gcm(struct tmc_pkcs11_session * session, struct tmc_pkcs11_object * key, CK_MECHANISM_PTR mech,CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                             CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pEncryptedDataLen);

static CK_RV
tmc_pkcs11_encrypt(tmc_pkcs11_operation_t *operation,
                   CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                   CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pEncryptedDataLen)
{
    CK_RV rv = CKR_OK;
    CK_BYTE_PTR cache;
    CK_ULONG blocksize = 0;
    CK_ULONG tmp;
    struct signature_data *data;
    struct tmc_pkcs11_object *key;
    CK_MECHANISM_PTR mech;

    data = (struct signature_data*) operation->priv_data;
    key = data->key;
    mech = &operation->mechanism;
    cache = data->buffer;

    blocksize = get_block_size(mech->mechanism);
    tmp = ulDataLen;


    rv = get_padded_size(mech->mechanism, &tmp, blocksize);
    if(rv != CKR_OK)
        return rv;

    if(!blocksize)
    {
        rv = key->ops->encrypt(operation->session,
                               key, &operation->mechanism,
                               pData, ulDataLen,
                               pEncryptedData, pEncryptedDataLen);
        return rv;
        //*pEncryptedDataLen = tmp;

    }


    //返回需要数组长度
    if(!pEncryptedData)
    {
        *pEncryptedDataLen = tmp;
        return rv;
    }

    //判度用户提供数组是否足够长
    if(*pEncryptedDataLen < tmp)
    {
        *pEncryptedDataLen = tmp;
        return CKR_BUFFER_TOO_SMALL;
    }

    if (mech->mechanism == CKM_AES_GCM) {// zhangzch 20190428
        rv = tmc_encrypt_gcm(operation->session, key, &operation->mechanism,
                               pData, ulDataLen,
                               pEncryptedData, &tmp);
        if(rv != CKR_OK)
            return rv;
    }
    else {
        tmp -= blocksize;

        //last block is different from other blocks for sym algo
        if(tmp)
        {
            rv = key->ops->encrypt(operation->session,
                                   key, &operation->mechanism,
                                   pData, tmp,
                                   pEncryptedData, &tmp);
            if(rv != CKR_OK)
                return rv;
        }
        rv = cipher_padding(mech, (CK_BYTE_PTR)(pData + tmp),
                            cache, (CK_ULONG)(ulDataLen - tmp), blocksize);
        if(rv != CKR_OK)
            return rv;
        key->ops->encrypt(operation->session,
                          key, &operation->mechanism,
                          cache, blocksize,
                          (u8 *) (pEncryptedData + tmp), &blocksize);
        *pEncryptedDataLen = tmp + blocksize;
    }

    return rv;
}



/*
 * Initialize a decrypt operation
 */
static CK_RV
tmc_pkcs11_decrypt_init(tmc_pkcs11_operation_t *operation,
                        struct tmc_pkcs11_object *key)
{
    struct signature_data *data;
    CK_RV rv;

    if (!(data = (struct signature_data *)calloc(1, sizeof(*data))))
        return CKR_HOST_MEMORY;

    data->key = key;

    if (key->ops->can_do)   {
        rv = key->ops->can_do(operation->session, key, operation->type->mech, CKF_DECRYPT);
        if ((rv == CKR_OK) || (rv == CKR_FUNCTION_NOT_SUPPORTED))   {
            /* Mechanism recognized and can be performed by pkcs#15 card or algorithm references not supported */
        }
        else {
            /* Mechanism cannot be performed by pkcs#15 card, or some general error. */
            free(data);
            return rv;
        }
    }
    operation->priv_data = data;
    return CKR_OK;
}

static CK_RV
tmc_pkcs11_decrypt_final(tmc_pkcs11_operation_t *operation,
                          CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    CK_RV rv = CKR_OK;
    struct signature_data *data = (struct signature_data*) operation->priv_data;
    CK_BYTE_PTR cache = data->buffer;
    CK_ULONG blocksize = get_block_size(operation->mechanism.mechanism);
    struct tmc_pkcs11_object *key = data->key;

    //dofinal应该检查之前update的数据为整块
    if(data->buffer_len % blocksize)
        return CKR_DATA_LEN_RANGE;
    switch (operation->mechanism.mechanism)
    {
        case CKM_SM4_CBC_PAD:
        case CKM_SM1_CBC_PAD:
        case CKM_AES_CBC_PAD:
        case CKM_DES3_CBC_PAD:
        case CKM_DES_CBC_PAD:
            *pulDataLen = 0;
            return CKR_OK;
        default:
            break;
    }

    if(!pData)
    {
        *pulDataLen = data->buffer_len;
        return rv;
    }

    if(*pulDataLen < data->buffer_len)
        return CKR_BUFFER_TOO_SMALL;

    return key->ops->decrypt(operation->session,
                                  key, &operation->mechanism,
                                  cache, data->buffer_len,
                                  pData, pulDataLen);
}

static CK_RV
tmc_pkcs11_decrypt_update(tmc_pkcs11_operation_t *operation,
                                  CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                                  CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    CK_RV rv = CKR_OK;
    struct signature_data *data = (struct signature_data*) operation->priv_data;
    CK_BYTE_PTR cache = data->buffer;
    CK_ULONG blocksize = get_block_size(operation->mechanism.mechanism);
    struct tmc_pkcs11_object *key = data->key;
    ulEncryptedDataLen += data->buffer_len;
    CK_ULONG outLen = (CK_ULONG)(ulEncryptedDataLen / blocksize * blocksize);

    //保留至少一块在cache中,update不处理解填充
    if(ulEncryptedDataLen == outLen)
    {
       outLen -= blocksize;
    }

    if(!pData)
    {
        *pulDataLen = outLen;
        return rv;
    }

    if(*pulDataLen < outLen)
        return CKR_BUFFER_TOO_SMALL;

    memcpy(pData, cache, data->buffer_len);
    memcpy((CK_BYTE_PTR)(pData + data->buffer_len),
            pEncryptedData, (CK_ULONG)(outLen - data->buffer_len));
    if(outLen)
    {
        rv = key->ops->decrypt(operation->session,
                               key, &operation->mechanism,
                               pData, outLen,
                               pData, &outLen);
        if(rv != CKR_OK)
            return rv;
    }
    
    memcpy(data->buffer,
           (CK_BYTE_PTR)(pEncryptedData + outLen - data->buffer_len),
           (CK_ULONG)(ulEncryptedDataLen - outLen));
    data->buffer_len = (unsigned int)(ulEncryptedDataLen - outLen);

    *pulDataLen = outLen;
    return rv;

}

static CK_RV update_parameter(CK_MECHANISM_PTR mech,
                              CK_BYTE_PTR pData, CK_ULONG pulDataLen);
static CK_RV tmc_decrypt_gcm(struct tmc_pkcs11_session * session, struct tmc_pkcs11_object * key, CK_MECHANISM_PTR mech, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                             CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);

static CK_RV
tmc_pkcs11_decrypt(tmc_pkcs11_operation_t *operation,
                   CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                   CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    CK_RV rv = CKR_OK;
    CK_BYTE_PTR cache;
    CK_BYTE_PTR iv_cache = NULL;
    CK_ULONG blocksize = 0;
    CK_ULONG tmp;
    struct signature_data *data;
    struct tmc_pkcs11_object *key;
    CK_MECHANISM_PTR mech;
    CK_ULONG i = 0;

    data = (struct signature_data*) operation->priv_data;
    key = data->key;
    mech = &operation->mechanism;
    blocksize = get_block_size(mech->mechanism);
    cache = data->buffer;

    tmp = (CK_ULONG)(ulEncryptedDataLen - blocksize);

    if(!blocksize)
    {
        //*pulDataLen = ulEncryptedDataLen - SM2_PAD_LEN;

        if(!pData)
            return rv;

        rv = key->ops->decrypt(operation->session,
                               key, &operation->mechanism,
                               pEncryptedData, tmp,
                               pData, &tmp);
        *pulDataLen = tmp;
        return rv;
    }

    if(pData)
    {
        if(*pulDataLen < tmp)
            return CKR_BUFFER_TOO_SMALL;

        if (mech->mechanism == CKM_AES_GCM) {

            rv = tmc_decrypt_gcm(operation->session,
                            key, &operation->mechanism,
                            pEncryptedData, ulEncryptedDataLen,
                            pData, pulDataLen);
            return rv;
        }

        if(tmp)
        {
            rv = key->ops->decrypt(operation->session,
                                   key, &operation->mechanism,
                                   pEncryptedData, tmp,
                                   pData, &tmp);

            if(rv != CKR_OK)
                return rv;
        }



        rv = key->ops->decrypt(operation->session,
                               key, &operation->mechanism,
                               (CK_BYTE_PTR)(pEncryptedData + tmp), blocksize,
                               cache, &blocksize);
        if(rv != CKR_OK)
            return rv;

        rv = cipher_unpadding(mech, (CK_BYTE_PTR)(pData + tmp),
                              cache, &blocksize);

        if(rv != CKR_OK)
            return rv;


        tmp = blocksize + tmp;

        *pulDataLen = tmp;
        if(*pulDataLen < tmp)
        {

            rv = CKR_BUFFER_TOO_SMALL;
        }


        return rv;
    }
    else
    {
        if (mech->mechanism == CKM_AES_GCM) {
            *pulDataLen = ulEncryptedDataLen - 16;
            return CKR_OK;
        }
        iv_cache = calloc(1, mech->ulParameterLen);

        memcpy(iv_cache, mech->pParameter, mech->ulParameterLen);
        
        //因为CBC等类型需要更新IV，所以要在cache中计算所有块才能推算出需要长度
        if(tmp)
        {
            

            rv = update_parameter(mech, (CK_BYTE_PTR)(pEncryptedData + tmp - blocksize),
                             blocksize);
            
            if(rv != CKR_OK)
                goto error;
        }




        rv = key->ops->decrypt(operation->session,
                key, &operation->mechanism,
                (CK_BYTE_PTR)(pEncryptedData + tmp), blocksize,
                cache, &blocksize);

        if(rv != CKR_OK)
            goto error;


        *pulDataLen = blocksize;

        rv = cipher_unpadding(mech, NULL,
                              cache, pulDataLen);

        *pulDataLen += tmp;

        error:
        if(iv_cache)
        {
            rv = update_parameter(mech, iv_cache,
                                  mech->ulParameterLen);
            free(iv_cache);
        }
        return rv;

    }


}


/** mechanism operation*/

/*
 * Look up a mechanism
 */
tmc_pkcs11_mechanism_type_t *
tmc_pkcs11_find_mechanism(struct tmc_pkcs11_card *p11card, CK_MECHANISM_TYPE mech, unsigned int flags)
{
    tmc_pkcs11_mechanism_type_t *mt;
    unsigned int n;

    for (n = 0; n < p11card->nmechanisms; n++) {
        mt = p11card->mechanisms[n];
        if (mt && mt->mech == mech && ((mt->mech_info.flags & flags) == flags))
            return mt;
    }
    return NULL;
}

void free_info(const void *info)
{
    free((void *) info);
}

/*
 * Register a sign+hash algorithm derived from an algorithm supported
 * by the token + a software hash mechanism
 */
CK_RV
tmc_pkcs11_register_sign_and_hash_mechanism(struct tmc_pkcs11_card *p11card,
                                            CK_MECHANISM_TYPE mech,
                                            CK_MECHANISM_TYPE hash_mech,
                                            tmc_pkcs11_mechanism_type_t *sign_type)
{
    tmc_pkcs11_mechanism_type_t *hash_type, *new_type;
    struct hash_signature_info *info;
    CK_MECHANISM_INFO mech_info = sign_type->mech_info;
    CK_RV rv;

    if (!(hash_type = tmc_pkcs11_find_mechanism(p11card, hash_mech, CKF_DIGEST)))
        return CKR_MECHANISM_INVALID;

    /* These hash-based mechs can only be used for sign/verify */
    mech_info.flags &= (CKF_SIGN | CKF_SIGN_RECOVER | CKF_VERIFY | CKF_VERIFY_RECOVER);

    info = (struct hash_signature_info *)calloc(1, sizeof(*info));
    if (!info)
        return SC_ERROR_OUT_OF_MEMORY;

    info->mech = mech;
    info->sign_type = sign_type;
    info->hash_type = hash_type;
    info->sign_mech = sign_type->mech;
    info->hash_mech = hash_mech;

    new_type = tmc_pkcs11_new_fw_mechanism(mech, &mech_info, sign_type->key_type, info, free_info);
    if (!new_type) {
        free_info(info);
        return CKR_HOST_MEMORY;
    }

    rv = tmc_pkcs11_register_mechanism(p11card, new_type);
    if (CKR_OK != rv) {
        new_type->free_mech_data(new_type->mech_data);
        free(new_type);
    }

    return rv;
}
struct tmc_pkcs11_mechanism_type hash_type = {
        0,
        0,
        0,
        0,
        0,
        0,
        NULL,
        tmc_pkcs11_md_init,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
};
struct hash_signature_info sig_info = {
        0,//CK_MECHANISM_TYPE	mech;
        0,//CK_MECHANISM_TYPE	hash_mech;
        0,//CK_MECHANISM_TYPE	sign_mech;
        &hash_type,
        &hash_type//tmc_pkcs11_mechanism_type_t *sign_type;
};
/*
 * Create new mechanism type for a mechanism supported by
 * the card
 */
tmc_pkcs11_mechanism_type_t *
tmc_pkcs11_new_fw_mechanism(CK_MECHANISM_TYPE mech,
                            CK_MECHANISM_INFO_PTR pInfo,
                            CK_KEY_TYPE key_type,
                            const void *priv_data,
                            void (*free_priv_data)(const void *priv_data))
{
    tmc_pkcs11_mechanism_type_t *mt;

    mt = (tmc_pkcs11_mechanism_type_t *)calloc(1, sizeof(*mt));
    if (mt == NULL)
        return mt;
    mt->mech = mech;
    mt->mech_info = *pInfo;
    mt->key_type = key_type;
    mt->mech_data = priv_data;
    mt->free_mech_data = free_priv_data;
    mt->obj_size = sizeof(tmc_pkcs11_mechanism_type_t);

    mt->release = tmc_pkcs11_signature_release;

    if (pInfo->flags & CKF_SIGN)
    {
        mt->sign_init = tmc_pkcs11_signature_init;
        mt->sign_update = tmc_pkcs11_signature_update;
        mt->sign_final = tmc_pkcs11_signature_final;
        mt->sign_size = tmc_pkcs11_signature_size;
        mt->verif_init = tmc_pkcs11_verify_init;
        mt->verif_update = tmc_pkcs11_signature_update;
        mt->verif_final = tmc_pkcs11_verify_final;

    }
    if (pInfo->flags & CKF_UNWRAP) {
        /* TODO */
    }
    if (pInfo->flags & CKF_DERIVE) {
        mt->derive = tmc_pkcs11_derive;
        mt->release = tmc_pkcs11_agreement_release;
    }
    if (pInfo->flags & CKF_DECRYPT) {
        mt->decrypt_init = tmc_pkcs11_decrypt_init;
        mt->decrypt = tmc_pkcs11_decrypt;
	 	mt->decryptUpdate = tmc_pkcs11_decrypt_update;
	 	mt->decryptFinal = tmc_pkcs11_decrypt_final;
    }
    if (pInfo->flags & CKF_ENCRYPT) {
        mt->encrypt_init = tmc_pkcs11_encrypt_init;
        mt->encrypt = tmc_pkcs11_encrypt;
	    mt->encryptUpdate = tmc_pkcs11_encrypt_update;
	    mt->encryptFinal = tmc_pkcs11_encrypt_final;
    }
    if (pInfo->flags & CKF_DIGEST) {
        mt->md_init = tmc_pkcs11_md_init;
	    mt->md_update = tmc_pkcs11_md_update;
	    mt->md_final = tmc_pkcs11_md_final;

    }


    return mt;
}

tmc_pkcs11_mechanism_type_t *
tmc_pkcs11_new_md_fw_mechanism(CK_MECHANISM_TYPE mech,
                            CK_MECHANISM_INFO_PTR pInfo,
                            CK_KEY_TYPE key_type,
                            const void *priv_data,
                            void (*free_priv_data)(const void *priv_data))
{
    tmc_pkcs11_mechanism_type_t * mt;
    mt =  tmc_pkcs11_new_fw_mechanism(mech, pInfo, key_type,
                                        priv_data, priv_data);
    mt->release = tmc_pkcs11_digest_release;
    return mt;
}

/*
 * Register a mechanism
 */
CK_RV
tmc_pkcs11_register_mechanism(struct tmc_pkcs11_card *p11card,
                              tmc_pkcs11_mechanism_type_t *mt)
{
    tmc_pkcs11_mechanism_type_t **p;

    if (mt == NULL)
        return CKR_HOST_MEMORY;

    p = (tmc_pkcs11_mechanism_type_t **) realloc(p11card->mechanisms,
                                                 (p11card->nmechanisms + 2) * sizeof(*p));
    if (p == NULL)
        return CKR_HOST_MEMORY;
    p11card->mechanisms = p;
    p[p11card->nmechanisms++] = mt;
    p[p11card->nmechanisms] = NULL;
    return CKR_OK;
}

/** framework operation*/

int tmc_internal_bind(tmc_card_t *card, tmc_internal_card_t * *inter_card) {
    struct tmc_internal_card *tmc_card = NULL;
    struct tmc_file_info *file_app = NULL;
    struct tmc_file_info *pub_df = NULL;
    u8 tmp_aid[10] = {"PolarisApp"};
    u8 tmp_resp[SC_MAX_APDU_BUFFER_SIZE] = {0x0};

    CK_ULONG reLen;
    int r;

    if (inter_card == NULL) {
        return SC_ERROR_INVALID_ARGUMENTS;
    }

    //lock the card
    tmc_lock(card);
    r = card->ops->select_file(card, tmp_aid, sizeof(tmp_aid), tmp_resp, &reLen);

    //if token was't initialized, just return
    if (r == SC_ERROR_FILE_NOT_FOUND) {
        tmc_printf_t("[libsdk]: Token is not present\n");
        r = SC_ERROR_CARD_NOT_PRESENT;
        goto error;
    }
    //other errors, throw error
    else if (r != SC_SUCCESS)
        goto error;

    tmc_unlock(card);
    return SC_SUCCESS;
    error:
    tmc_unlock(card);
    return r;
}
CK_RV tmc_pkcs11_register_generic_mechanisms(tmc_pkcs11_card_t *p11_card)
{
    CK_MECHANISM_INFO AES_mech_info;
    CK_MECHANISM_INFO DES_mech_info;
    CK_MECHANISM_INFO RSA_mech_info;
    CK_MECHANISM_INFO SM1_SM4_mech_info;
    CK_MECHANISM_INFO SM2_mech_info;
    CK_MECHANISM_INFO SM3_mech_info;
    CK_MECHANISM_INFO SHA_mech_info;

    tmc_pkcs11_mechanism_type_t *mt;
    int rc;

    AES_mech_info.flags = CKF_HW | CKF_DECRYPT | CKF_ENCRYPT; /* check for more */
    AES_mech_info.ulMinKeySize = (unsigned long) 16;
    AES_mech_info.ulMaxKeySize = (unsigned long) 32;

    DES_mech_info.flags = CKF_HW | CKF_DECRYPT | CKF_ENCRYPT; /* check for more */
    DES_mech_info.ulMinKeySize = (unsigned long) 8;
    DES_mech_info.ulMaxKeySize = (unsigned long) 24;

    SM1_SM4_mech_info.flags = CKF_HW | CKF_DECRYPT | CKF_ENCRYPT; /* check for more */
    SM1_SM4_mech_info.ulMinKeySize = (unsigned long) 16;
    SM1_SM4_mech_info.ulMaxKeySize = (unsigned long) 16;

    RSA_mech_info.flags = CKF_HW | CKF_DECRYPT |CKF_ENCRYPT; /* check for more */
    RSA_mech_info.ulMinKeySize = (unsigned long) 128;
    RSA_mech_info.ulMaxKeySize = (unsigned long) 512;

    SM2_mech_info.flags = CKF_HW | CKF_DECRYPT | CKF_ENCRYPT; /* check for more */
    SM2_mech_info.ulMinKeySize = (unsigned long) 32;
    SM2_mech_info.ulMaxKeySize = (unsigned long) 32;

    SHA_mech_info.flags = CKF_HW | CKF_DIGEST; /* check for more */
    SM3_mech_info.flags = CKF_HW | CKF_DIGEST; /* check for more */



    mt = tmc_pkcs11_new_fw_mechanism(CKM_AES_CBC, &AES_mech_info, CKK_AES, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_fw_mechanism(CKM_AES_CBC_PAD, &AES_mech_info, CKK_AES, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;
    
    mt = tmc_pkcs11_new_fw_mechanism(CKM_AES_ECB, &AES_mech_info, CKK_AES, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_fw_mechanism(CKM_AES_GCM, &AES_mech_info, CKK_AES, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_fw_mechanism(CKM_DES3_CBC, &DES_mech_info, CKK_DES3, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_fw_mechanism(CKM_DES3_CBC_PAD, &DES_mech_info, CKK_DES3, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_fw_mechanism(CKM_DES3_ECB, &DES_mech_info, CKK_DES3, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_fw_mechanism(CKM_SM1_CBC, &SM1_SM4_mech_info, CKK_SM1, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_fw_mechanism(CKM_SM4_CBC, &SM1_SM4_mech_info, CKK_SM4, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_fw_mechanism(CKM_SM1_ECB, &SM1_SM4_mech_info, CKK_SM1, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_fw_mechanism(CKM_SM4_ECB, &SM1_SM4_mech_info, CKK_SM4, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_md_fw_mechanism(CKM_SM3_256, &SM3_mech_info, 0, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;
	
    mt = tmc_pkcs11_new_md_fw_mechanism(CKM_SHA_1, &SHA_mech_info, 0, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_md_fw_mechanism(CKM_SHA224, &SHA_mech_info, 0, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_md_fw_mechanism(CKM_SHA256, &SHA_mech_info, 0, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_md_fw_mechanism(CKM_SHA384, &SHA_mech_info, 0, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_md_fw_mechanism(CKM_SHA512, &SHA_mech_info, 0, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_fw_mechanism(CKM_RSA_PKCS, &RSA_mech_info, CKK_RSA, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_fw_mechanism(CKM_SM2_SM3_256, &SM2_mech_info, CKK_SM2, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11_card, mt);
    if (rc != CKR_OK)
        return rc;


    return 0;
}

static int register_ec_mechanisms(struct tmc_pkcs11_card *p11card, int flags,
                                  unsigned long ext_flags, CK_ULONG min_key_size, CK_ULONG max_key_size)
{
    CK_MECHANISM_INFO mech_info;
    tmc_pkcs11_mechanism_type_t *mt;
    CK_FLAGS ec_flags = 0;
    int rc;

    if (ext_flags & SC_ALGORITHM_EXT_EC_F_P)
        ec_flags |= CKF_EC_F_P;
    if (ext_flags & SC_ALGORITHM_EXT_EC_F_2M)
        ec_flags |= CKF_EC_F_2M;
    if (ext_flags & SC_ALGORITHM_EXT_EC_ECPARAMETERS)
        ec_flags |= CKF_EC_ECPARAMETERS;
    if (ext_flags & SC_ALGORITHM_EXT_EC_NAMEDCURVE)
        ec_flags |= CKF_EC_NAMEDCURVE;
    if (ext_flags & SC_ALGORITHM_EXT_EC_UNCOMPRESES)
        ec_flags |= CKF_EC_UNCOMPRESS;
    if (ext_flags & SC_ALGORITHM_EXT_EC_COMPRESS)
        ec_flags |= CKF_EC_COMPRESS;



    mech_info.flags = CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_DERIVE; /* check for more */
    mech_info.flags |= ec_flags;
    mech_info.ulMinKeySize = min_key_size;
    mech_info.ulMaxKeySize = max_key_size;

    if(flags & SC_ALGORITHM_ECDSA_HASH_NONE) {
        mt = tmc_pkcs11_new_fw_mechanism(CKM_ECDSA, &mech_info, CKK_EC, NULL, NULL);
        if (!mt)
            return CKR_HOST_MEMORY;
        rc = tmc_pkcs11_register_mechanism(p11card, mt);
        if (rc != CKR_OK)
            return rc;

        if(ext_flags & SC_ALGORITHM_ECDSA_HASH_SHA1)
        {
            rc = tmc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_ECDSA_SHA1, CKM_SHA_1, mt);
            if (rc != CKR_OK)
                return rc;
        }
        rc = tmc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_ECDSA_SHA256, CKM_SHA256, mt);
        if (rc != CKR_OK)
            return rc;

        if(ext_flags & SC_ALGORITHM_ECDSA_HASH_SHA384)
        {
            rc = tmc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_ECDSA_SHA384, CKM_SHA384, mt);
            if (rc != CKR_OK)
                return rc;
        }
        if(ext_flags & SC_ALGORITHM_ECDSA_HASH_SHA512)
        {
            rc = tmc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_ECDSA_SHA512, CKM_SHA512, mt);
            if (rc != CKR_OK)
                return rc;
        }
    }


    /* ADD ECDH mechanisms */
    /* The PIV uses curves where CKM_ECDH1_DERIVE and CKM_ECDH1_COFACTOR_DERIVE produce the same results */
    mt = tmc_pkcs11_new_fw_mechanism(CKM_ECDH1_DERIVE, &mech_info, CKK_EC, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11card, mt);
    if (rc != CKR_OK)
        return rc;

    mt = tmc_pkcs11_new_fw_mechanism(CKM_DH_PKCS_DERIVE, &mech_info, CKK_DH, NULL, NULL);
    if (!mt)
        return CKR_HOST_MEMORY;
    rc = tmc_pkcs11_register_mechanism(p11card, mt);
    if (rc != CKR_OK)
        return rc;

    if (flags & SC_ALGORITHM_ONBOARD_KEY_GEN) {
        mech_info.flags = CKF_HW | CKF_GENERATE_KEY_PAIR;
        mech_info.flags |= ec_flags;
        mt = tmc_pkcs11_new_fw_mechanism(CKM_EC_KEY_PAIR_GEN, &mech_info, CKK_EC, NULL, NULL);
        if (!mt)
            return CKR_HOST_MEMORY;
        rc = tmc_pkcs11_register_mechanism(p11card, mt);
        if (rc != CKR_OK)
            return rc;
    }

    return CKR_OK;
}


/*
 * Mechanism handling
 * FIXME: We should consult the card's algorithm list to
 * find out what operations it supports
 */
static CK_RV
register_mechanisms(struct tmc_pkcs11_card *p11card)
{
    tmc_card_t *card = p11card->card;
    tmc_algorithm_info_t *alg_info;
    CK_MECHANISM_INFO RSA_mech_info,SM2_mech_info;
    CK_ULONG ec_min_key_size, ec_max_key_size;
    unsigned long ec_ext_flags;
    tmc_pkcs11_mechanism_type_t *mt;
    unsigned int num;
    int rc, rsa_flags = 0, ec_flags = 0, sm2_flags = 0;

    /* Register generic mechanisms */
    tmc_pkcs11_register_generic_mechanisms(p11card);

    RSA_mech_info.flags = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY;
    RSA_mech_info.ulMinKeySize = 128;
    RSA_mech_info.ulMaxKeySize = 512;

    SM2_mech_info.flags = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY;
    SM2_mech_info.ulMinKeySize = 32;
    SM2_mech_info.ulMaxKeySize = 32;

    ec_min_key_size = 32;
    ec_max_key_size = 32;
    ec_ext_flags = 0;

    /* For now, we just OR all the algorithm specific
     * flags, based on the assumption that cards don't
     * support different modes for different key *sizes*. */
    num = card->algorithm_count;
    alg_info = card->algorithms;
    while (num--) {
        switch (alg_info->algorithm) {
            case SC_ALGORITHM_RSA:
                if (alg_info->key_length < RSA_mech_info.ulMinKeySize)
                    RSA_mech_info.ulMinKeySize = alg_info->key_length;
                if (alg_info->key_length > RSA_mech_info.ulMaxKeySize)
                    RSA_mech_info.ulMaxKeySize = alg_info->key_length;
                rsa_flags |= alg_info->flags;
                break;
            case SC_ALGORITHM_EC:
                if (alg_info->key_length < ec_min_key_size)
                    ec_min_key_size = alg_info->key_length;
                if (alg_info->key_length > ec_max_key_size)
                    ec_max_key_size = alg_info->key_length;
                ec_flags |= alg_info->flags;
                ec_ext_flags |= alg_info->u._ec.ext_flags;
                break;
        }
        alg_info++;
    }

    if (ec_flags & SC_ALGORITHM_ECDSA_RAW) {
        rc = register_ec_mechanisms(p11card, ec_flags, ec_ext_flags, ec_min_key_size, ec_max_key_size);
        if (rc != CKR_OK)
            return rc;
    }


    /* Check if we support raw RSA */
    if (rsa_flags & SC_ALGORITHM_RSA_RAW) {
        mt = tmc_pkcs11_new_fw_mechanism(CKM_RSA_X_509, &RSA_mech_info, CKK_RSA, NULL, NULL);
        rc = tmc_pkcs11_register_mechanism(p11card, mt);
        if (rc != CKR_OK)
            return rc;

        /* We support PKCS1 padding in software */
        /* either the card supports it or OpenSC does */
        rsa_flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
    }

    /* No need to Check for PKCS1  We support it in software and turned it on above so always added it */
    if (rsa_flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
        mt = tmc_pkcs11_new_fw_mechanism(CKM_RSA_PKCS, &RSA_mech_info, CKK_RSA, NULL, NULL);
        rc = tmc_pkcs11_register_mechanism(p11card, mt);
        if (rc != CKR_OK)
            return rc;


        /* sc_pkcs11_register_sign_and_hash_mechanism expects software hash */
        /* All hashes are in OpenSSL
         * Either the card set the hashes or we helped it above */

        if (rsa_flags & SC_ALGORITHM_RSA_HASH_SHA1) {
            rc = tmc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_SHA1_RSA_PKCS, CKM_SHA_1, mt);
            if (rc != CKR_OK)
                return rc;
        }
        if (rsa_flags & SC_ALGORITHM_RSA_HASH_SHA256) {
            rc = tmc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_SHA256_RSA_PKCS, CKM_SHA256, mt);
            if (rc != CKR_OK)
                return rc;
        }
        if (rsa_flags & SC_ALGORITHM_RSA_HASH_SHA384) {
            rc = tmc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_SHA384_RSA_PKCS, CKM_SHA384, mt);
            if (rc != CKR_OK)
                return rc;
        }
        if (rsa_flags & SC_ALGORITHM_RSA_HASH_SHA512) {
            rc = tmc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_SHA512_RSA_PKCS, CKM_SHA512, mt);
            if (rc != CKR_OK)
                return rc;
        }
        if (rsa_flags & SC_ALGORITHM_RSA_HASH_MD5) {
            rc = tmc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_MD5_RSA_PKCS, CKM_MD5, mt);
            if (rc != CKR_OK)
                return rc;
        }
        if (rsa_flags & SC_ALGORITHM_RSA_HASH_RIPEMD160) {
            rc = tmc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_RIPEMD160_RSA_PKCS, CKM_RIPEMD160, mt);
            if (rc != CKR_OK)
                return rc;
        }

    }

    sm2_flags |= SC_ALGORITHM_SM2_HASH_SM3_256;
    if (sm2_flags & SC_ALGORITHM_SM2_HASH_SM3_256) {
        mt = tmc_pkcs11_new_fw_mechanism(CKM_SM2_SM3_256, &SM2_mech_info, CKK_SM2, NULL, NULL);
        rc = tmc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_SM2_SM3_256, CKM_SM3_256, mt);
        if (rc != CKR_OK)
            return rc;
    }

    sm2_flags |= SC_ALGORITHM_SM2_HASH_SM3_256_E;
    if (sm2_flags & SC_ALGORITHM_SM2_HASH_SM3_256_E) {
        mt = tmc_pkcs11_new_fw_mechanism(CKM_SM2_SM3_256_E, &SM2_mech_info, CKK_SM2, NULL, NULL);
        rc = tmc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_SM2_SM3_256_E, CKM_SM3_256, mt);
        if (rc != CKR_OK)
            return rc;
    }


    /* TODO support other padding mechanisms */

    if (rsa_flags & SC_ALGORITHM_ONBOARD_KEY_GEN) {
        RSA_mech_info.flags = CKF_HW | CKF_GENERATE_KEY_PAIR;
        mt = tmc_pkcs11_new_fw_mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, &RSA_mech_info, CKK_RSA, NULL, NULL);
        if (!mt)
            return CKR_HOST_MEMORY;
        rc = tmc_pkcs11_register_mechanism(p11card, mt);
        if (rc != CKR_OK)
            return rc;
    }

    return CKR_OK;
}


static CK_RV switch_token_session(struct tmc_pkcs11_object * key,
                                   struct tmcse_key ** pUniontmc_key){
    CK_ATTRIBUTE_PTR ptr;
    CK_ATTRIBUTE_TYPE tmp = CKA_TOKEN;
    CK_BBOOL is_token = FALSE;
    struct tmcse_key * uniontmc_key = (struct tmcse_key*)malloc(sizeof(struct tmcse_key));

    if(!key)
    {
        return CKR_KEY_HANDLE_INVALID;
    }
    if(!pUniontmc_key)
    {
        return CKR_FUNCTION_FAILED;
    }
    if(!(ptr = (CK_ATTRIBUTE_PTR)list_seek(&(key->attrs), &tmp)))
    {
        return CKR_KEY_HANDLE_INVALID;
    }

    if(!uniontmc_key)
    {
        return CKR_HOST_MEMORY;
    }
    is_token = *(CK_BBOOL *)ptr->pValue;
    //TOKEN密钥的值存储在SE上，session密钥密文存在结构体内部
    if(is_token)
    {
        uniontmc_key->key.fid = key->fid;
    }
    else
    {
        tmp = CKA_VALUE;
        uniontmc_key->key.value.data = (u8*)((CK_ATTRIBUTE*)(list_seek(&(key->attrs)
                , &tmp)))->pValue;
        tmp = CKA_VALUE_LEN;
        uniontmc_key->key.value.length = *(CK_ULONG_PTR)((CK_ATTRIBUTE*)(list_seek(&(key->attrs)
                , &tmp)))->pValue;
        uniontmc_key->key.value.length += ENC_KEY_BLOCK_SIZE;

    }
    uniontmc_key->isToken = is_token;
    *pUniontmc_key = uniontmc_key;
    return CKR_OK;
}

static CK_RV rsa_session_key_to_cache(struct tmc_pkcs11_object * key,
        struct tmcse_key * uniontmc_key)
{
    CK_ATTRIBUTE_TYPE tmp = CKA_MODULUS_BITS;
    CK_ATTRIBUTE_PTR tmp_attr = NULL;
    CK_BYTE_PTR ptr = NULL;
    CK_ULONG length;

    tmp_attr = (CK_ATTRIBUTE*)(list_seek(&(key->attrs)
            , &tmp));

    if(!tmp_attr) {
        tmp = CKA_VALUE_LEN;//RSA should use CKA_MODULUS_BITS

        tmp_attr = (CK_ATTRIBUTE*)(list_seek(&(key->attrs)
                , &tmp));
        if(!tmp_attr)
            return CKR_KEY_TYPE_INCONSISTENT;
        length = *(CK_ULONG_PTR)(tmp_attr->pValue);
        if(!length)
            return CKR_KEY_TYPE_INCONSISTENT;
    }
    else {
        length = *(CK_ULONG_PTR)(tmp_attr->pValue);
        if(!length)
            return CKR_KEY_TYPE_INCONSISTENT;

        length = length / 8 ;
    }

    tmp = CKA_VALUE;
    tmp_attr = (CK_ATTRIBUTE*)(list_seek(&(key->attrs)
            , &tmp));
    if(!tmp_attr)
        return CKR_KEY_TYPE_INCONSISTENT;
    ptr = (u8*)tmp_attr->pValue;
    if(!ptr)
        return CKR_KEY_TYPE_INCONSISTENT;
    length += length;

    uniontmc_key->key.value.data = ptr;
    uniontmc_key->key.value.length = length;
    //uniontmc_key->key.value.length = length / ENC_KEY_BLOCK_SIZE * ENC_KEY_BLOCK_SIZE + ENC_KEY_BLOCK_SIZE;

    return CKR_OK;
}

static CK_RV rsa_pub_session_key_to_cache(struct tmc_pkcs11_object * key,
                                      struct tmcse_key * uniontmc_key,
                                              CK_BYTE_PTR *cache)
{
    CK_RV rv;
    CK_ULONG length;
    CK_ATTRIBUTE_PTR tmp_attr = NULL;
    CK_ATTRIBUTE_TYPE tmp = CKA_MODULUS_BITS;
    CK_BYTE_PTR ptr = NULL;

    tmp_attr = (CK_ATTRIBUTE*)(list_seek(&(key->attrs)
            , &tmp));

    if(!tmp_attr) {
        tmp = CKA_VALUE_LEN;//RSA should use CKA_MODULUS_BITS

        tmp_attr = (CK_ATTRIBUTE*)(list_seek(&(key->attrs)
                , &tmp));
        if(!tmp_attr)
            return CKR_KEY_TYPE_INCONSISTENT;
        length = *(CK_ULONG_PTR)(tmp_attr->pValue);
        if(!length)
            return CKR_KEY_TYPE_INCONSISTENT;
    }
    else {
        length = *(CK_ULONG_PTR)(tmp_attr->pValue);
        if(!length)
            return CKR_KEY_TYPE_INCONSISTENT;

        length = length / 8 ;
    }

    tmp = CKA_MODULUS;
    tmp_attr = (CK_ATTRIBUTE*)(list_seek(&(key->attrs)
            , &tmp));
    if(!tmp_attr)
        return CKR_KEY_TYPE_INCONSISTENT;
    ptr = (u8*)tmp_attr->pValue;
    if(!ptr)
        return CKR_KEY_TYPE_INCONSISTENT;
    tmp = CKA_PUBLIC_EXPONENT;

    ptr = calloc(1, length + RSA_PUB_EXP_LEN);
    if(!ptr)
        return CKR_HOST_MEMORY;
    memcpy(ptr, tmp_attr->pValue, length);
    ptr += length;
    tmp_attr = (CK_ATTRIBUTE*)(list_seek(&(key->attrs)
            , &tmp));
    if(!tmp_attr)
        return CKR_KEY_TYPE_INCONSISTENT;
    if(!(tmp_attr->pValue))
        return CKR_KEY_TYPE_INCONSISTENT;
    memcpy(ptr, tmp_attr->pValue, RSA_PUB_EXP_LEN);
    ptr -= length;
    uniontmc_key->key.value.data = ptr;
    uniontmc_key->key.value.length = length + RSA_PUB_EXP_LEN;
    //uniontmc_key->key.value.length = length / ENC_KEY_BLOCK_SIZE * ENC_KEY_BLOCK_SIZE + ENC_KEY_BLOCK_SIZE;
    *cache = ptr;
    return CKR_OK;
}

static CK_RV switch_pub_asym_token_session(struct tmc_pkcs11_object * key,
                                       struct tmcse_key ** pUniontmc_key,
                                       CK_MECHANISM_TYPE mech,
                                       CK_BYTE_PTR * cache){
    CK_ATTRIBUTE_PTR ptr;
    CK_ATTRIBUTE_TYPE tmp = CKA_TOKEN;
    CK_ATTRIBUTE_PTR  attr = NULL;
    CK_BBOOL is_token = FALSE;
    struct tmcse_key * uniontmc_key = (struct tmcse_key*)malloc(sizeof(struct tmcse_key));

    if(!key)
    {
        return CKR_KEY_HANDLE_INVALID;
    }
    if(!pUniontmc_key)
    {
        return CKR_FUNCTION_FAILED;
    }
    if(!(ptr = (CK_ATTRIBUTE_PTR)list_seek(&(key->attrs), &tmp)))
    {
        return CKR_KEY_HANDLE_INVALID;
    }

    if(!uniontmc_key)
    {
        return CKR_HOST_MEMORY;
    }
    is_token = *(CK_BBOOL *)ptr->pValue;
    //TOKEN密钥的值存储在SE上，session密钥密文存在结构体内部
    if(is_token)
    {
        uniontmc_key->key.fid = key->fid;
    }
    else
    {
        switch (mech)
        {
            case CKM_RSA_PKCS:
            case CKM_RSA_9796:
            case CKM_RSA_PKCS_PSS:
                rsa_pub_session_key_to_cache(key, uniontmc_key, cache);
                //session密钥采用AES加密，用M2模式
                uniontmc_key->key.value.length = uniontmc_key->key.value.length;
                break;
            case CKM_SM2_SM3_256:
                tmp = CKA_VALUE;
                attr = (CK_ATTRIBUTE*)(list_seek(&(key->attrs)
                        , &tmp));
                if(!attr)
                    return CKR_KEY_TYPE_INCONSISTENT;
                uniontmc_key->key.value.data = (u8*)(attr->pValue);
                tmp = CKA_VALUE_LEN;
                uniontmc_key->key.value.length = *(CK_ULONG_PTR)((CK_ATTRIBUTE*)(list_seek(&(key->attrs)
                        , &tmp)))->pValue;
                //uniontmc_key->key.value.length += ENC_KEY_BLOCK_SIZE;
                break;

            case CKM_ECDSA:
            case CKM_ECDSA_SHA1:
            case CKM_ECDSA_SHA256:
            case CKM_ECDSA_SHA384:
            case CKM_ECDSA_SHA512:
                tmp = CKA_EC_POINT;
                attr = (CK_ATTRIBUTE*)(list_seek(&(key->attrs)
                        , &tmp));
                if(!attr)
                    return CKR_KEY_TYPE_INCONSISTENT;
                uniontmc_key->key.value.data = (u8*)attr->pValue;
                tmp = CKA_VALUE_LEN;
                attr = (CK_ATTRIBUTE*)(list_seek(&(key->attrs)
                        , &tmp));
                if(!attr)
                    return CKR_KEY_TYPE_INCONSISTENT;
                uniontmc_key->key.value.length = *(CK_ULONG_PTR)attr->pValue;
                break;
            default:
                return CKR_KEY_TYPE_INCONSISTENT;
        }

    }
    uniontmc_key->isToken = is_token;
    *pUniontmc_key = uniontmc_key;
    return CKR_OK;
}

static CK_RV switch_asym_token_session(struct tmc_pkcs11_object * key,
                                  struct tmcse_key ** pUniontmc_key,
                                          CK_MECHANISM_TYPE mech){
    CK_ATTRIBUTE_PTR ptr;
    CK_ATTRIBUTE_TYPE tmp = CKA_TOKEN;
    CK_BBOOL is_token = FALSE;
    struct tmcse_key * uniontmc_key = (struct tmcse_key*)malloc(sizeof(struct tmcse_key));

    if(!key)
    {
        return CKR_KEY_HANDLE_INVALID;
    }
    if(!pUniontmc_key)
    {
        return CKR_FUNCTION_FAILED;
    }
    if(!(ptr = (CK_ATTRIBUTE_PTR)list_seek(&(key->attrs), &tmp)))
    {
        return CKR_KEY_HANDLE_INVALID;
    }

    if(!uniontmc_key)
    {
        return CKR_HOST_MEMORY;
    }
    is_token = *(CK_BBOOL *)ptr->pValue;
    //TOKEN密钥的值存储在SE上，session密钥密文存在结构体内部
    if(is_token)
    {
        uniontmc_key->key.fid = key->fid;
    }
    else
    {
       switch (mech)
       {
           case CKM_RSA_PKCS:
           case CKM_RSA_9796:
           case CKM_RSA_PKCS_PSS:
               rsa_session_key_to_cache(key, uniontmc_key);
               //session密钥采用AES加密，用M2模式
               uniontmc_key->key.value.length = uniontmc_key->key.value.length /
                       ENC_KEY_BLOCK_SIZE * ENC_KEY_BLOCK_SIZE + ENC_KEY_BLOCK_SIZE;
               break;
           case CKM_SM2_SM3_256:
           case CKM_ECDSA:
           case CKM_ECDSA_SHA1:
           case CKM_ECDSA_SHA256:
           case CKM_ECDSA_SHA384:
           case CKM_ECDSA_SHA512:
               tmp = CKA_VALUE;
               uniontmc_key->key.value.data = (u8*)((CK_ATTRIBUTE*)(list_seek(&(key->attrs)
                       , &tmp)))->pValue;
               tmp = CKA_VALUE_LEN;
               uniontmc_key->key.value.length = *(CK_ULONG_PTR)((CK_ATTRIBUTE*)(list_seek(&(key->attrs)
                       , &tmp)))->pValue;
               uniontmc_key->key.value.length += ENC_KEY_BLOCK_SIZE;
               break;
           default:
               return CKR_KEY_TYPE_INCONSISTENT;
       }

    }
    uniontmc_key->isToken = is_token;
    *pUniontmc_key = uniontmc_key;
    return CKR_OK;
}

static CK_RV assert_parameter(CK_MECHANISM_PTR mech, u8** pParameter,
        u_int32_t* pUlparaLen)
{
    *pParameter = (u8*)mech->pParameter;
    *pUlparaLen = (u_int32_t)mech->ulParameterLen;
    switch (mech->mechanism)
    {
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD:
            if(*pUlparaLen != 16 || !*pParameter)
                return CKR_DATA_INVALID;
            break;
        default:
            break;
    }

    return CKR_OK;
}

static CK_RV update_parameter(CK_MECHANISM_PTR mech,
        CK_BYTE_PTR pData, CK_ULONG pulDataLen)
{
    CK_BYTE tmp[200];
    switch (mech->mechanism)
    {
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD:
        case CKM_DES3_CBC:
        case CKM_DES3_CBC_PAD:
        case CKM_DES_CBC:
        case CKM_DES_CBC_PAD:
        case CKM_SM4_CBC:
        case CKM_SM4_CBC_PAD:

            memcpy(tmp,  (CK_BYTE_PTR)(pData + pulDataLen - mech->ulParameterLen),
                   mech->ulParameterLen);

            memcpy(mech->pParameter, (CK_BYTE_PTR)(pData + pulDataLen - mech->ulParameterLen),
                   mech->ulParameterLen);
            break;
        default:
            break;
    }

    return CKR_OK;
}


/*secret key ops*/

static CK_RV tmc_decrypt(struct tmc_pkcs11_session * session, struct tmc_pkcs11_object * key, CK_MECHANISM_PTR mech, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                         CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    CK_RV rv;
    struct tmc_pkcs11_operation * op;
    struct tmcse_key * uniontmc_key;
    struct tmc_card * card = session->slot->p11card->card;

    CK_BYTE cache[16];

    session_get_operation(session, SC_PKCS11_OPERATION_DECRYPT, &op);

    rv = switch_token_session(key, &uniontmc_key);
    if(rv != CKR_OK)
        goto end;

    memcpy(cache,  (CK_BYTE_PTR)(pEncryptedData + ulEncryptedDataLen - mech->ulParameterLen),
            mech->ulParameterLen);



    rv = card->ops->dec_data(card, op->mechanism.mechanism, uniontmc_key,
                  pEncryptedData, ulEncryptedDataLen,
                  (u8*)mech->pParameter, (u_int32_t)mech->ulParameterLen,
                  pData, pulDataLen
          );

    if(rv != CKR_OK)
        return rv;



    //IV等参数，需要更新
    rv = update_parameter(mech, cache, mech->ulParameterLen);
    if(rv != CKR_OK)
        goto end;


    end:
    if(uniontmc_key)
    {
        free(uniontmc_key);
    }
    return rv;

}

static CK_RV tmc_asym_decrypt(struct tmc_pkcs11_session * session, struct tmc_pkcs11_object * key, CK_MECHANISM_PTR mech, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                         CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    CK_RV rv;
    struct tmc_pkcs11_operation * op;
    struct tmcse_key * uniontmc_key;
    struct tmc_card * card = session->slot->p11card->card;


    session_get_operation(session, SC_PKCS11_OPERATION_DECRYPT, &op);

    rv = switch_asym_token_session(key, &uniontmc_key, op->mechanism.mechanism);
    if(rv != CKR_OK)
        goto end;

    rv = card->ops->decrypt(card, op->mechanism.mechanism, key->keyType, uniontmc_key,
                             pEncryptedData, ulEncryptedDataLen,pData, pulDataLen
    );

    if(rv != CKR_OK)
        return rv;

        goto end;
    end:
    if(uniontmc_key)
    {
        free(uniontmc_key);
    }
    return rv;

}

void tmc_cipher_128(struct tmc_card *card, unsigned long mechanism, unsigned char in[16], unsigned char out[16], void *key)
{
    CK_RV rv;
    unsigned long enc_len = 0;
    tmcse_key_t *pkey = (tmcse_key_t*)key;

    rv = card->ops->enc_data(card, mechanism, pkey,in, 16,NULL,0,out,&enc_len);
}

CK_RV tmc_encrypt_gcm(struct tmc_pkcs11_session * session, struct tmc_pkcs11_object * key, CK_MECHANISM_PTR mech,CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                         CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pEncryptedDataLen)
{
    CK_RV rv;
    struct tmcse_key * uniontmc_key;
    struct tmc_pkcs11_operation * op;
    struct tmc_card * card = session->slot->p11card->card;
    GCM_CTX ctx;
    tmcse_gcm_param_t *param = (tmcse_gcm_param_t*)mech->pParameter;
    CK_ULONG ulCipherLen,ulTagLen;


    session_get_operation(session, SC_PKCS11_OPERATION_ENCRYPT, &op);

    rv = switch_token_session(key, &uniontmc_key);
    if(rv != CKR_OK)
        goto end;

    GCM128_Init(&ctx, (block128_f)tmc_cipher_128, uniontmc_key, param->iv, param->ivlen, card, op->mechanism.mechanism);

    GCM128_Encrypt(&ctx,param->aad, param->aadlen, pData, ulDataLen, pEncryptedData, &ulCipherLen, pEncryptedData + ulDataLen, &ulTagLen);
    if(rv != CKR_OK)
        return rv;

    *pEncryptedDataLen = ulCipherLen + ulTagLen;

/*    //IV等参数，需要更新
    rv = update_parameter(mech, pEncryptedData, *pEncryptedDataLen);*/
    end:

    if(uniontmc_key)
    {
        free(uniontmc_key);
    }
    return rv;

}
CK_RV tmc_decrypt_gcm(struct tmc_pkcs11_session * session, struct tmc_pkcs11_object * key, CK_MECHANISM_PTR mech, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                      CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    CK_RV rv;
    struct tmcse_key * uniontmc_key;
    struct tmc_pkcs11_operation * op;
    struct tmc_card * card = session->slot->p11card->card;
    GCM_CTX ctx;
    tmcse_gcm_param_t *param = (tmcse_gcm_param_t*)mech->pParameter;
    CK_ULONG ulCipherLen,ulTagLen;


    session_get_operation(session, SC_PKCS11_OPERATION_DECRYPT, &op);

    rv = switch_token_session(key, &uniontmc_key);
    if(rv != CKR_OK)
        goto end;

    GCM128_Init(&ctx, (block128_f)tmc_cipher_128, uniontmc_key, param->iv, param->ivlen, card, op->mechanism.mechanism);

    GCM128_Decrypt(&ctx,param->aad, param->aadlen, pEncryptedData, ulEncryptedDataLen - 16, pEncryptedData + ulEncryptedDataLen - 16, 16, pData, pulDataLen);
    if(rv != CKR_OK)
        return rv;

/*    //IV等参数，需要更新
    rv = update_parameter(mech, pEncryptedData, *pEncryptedDataLen);*/
    end:

    if(uniontmc_key)
    {
        free(uniontmc_key);
    }
    return rv;

}


static CK_RV tmc_encrypt(struct tmc_pkcs11_session * session, struct tmc_pkcs11_object * key, CK_MECHANISM_PTR mech,CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                          CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pEncryptedDataLen)
{
    CK_RV rv;
    struct tmcse_key * uniontmc_key;
    struct tmc_pkcs11_operation * op;
    struct tmc_card * card = session->slot->p11card->card;

    session_get_operation(session, SC_PKCS11_OPERATION_ENCRYPT, &op);

    rv = switch_token_session(key, &uniontmc_key);
    if(rv != CKR_OK)
        goto end;



    rv = card->ops->enc_data(card, op->mechanism.mechanism, uniontmc_key,
                   pData, ulDataLen,
                   (u8*)mech->pParameter, (u_int32_t)mech->ulParameterLen,
                   pEncryptedData, pEncryptedDataLen
          );
    if(rv != CKR_OK)
        return rv;

    //IV等参数，需要更新
    rv = update_parameter(mech, pEncryptedData, *pEncryptedDataLen);
    end:

    if(uniontmc_key)
    {
        free(uniontmc_key);
    }
    return rv;

}

static CK_RV tmc_asym_encrypt(struct tmc_pkcs11_session * session, struct tmc_pkcs11_object * key, CK_MECHANISM_PTR mech,CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                         CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pEncryptedDataLen)
{
    CK_RV rv;
    struct tmcse_key * uniontmc_key;
    struct tmc_pkcs11_operation * op;
    struct tmc_card * card = session->slot->p11card->card;
    CK_BYTE_PTR cache;

    session_get_operation(session, SC_PKCS11_OPERATION_ENCRYPT, &op);

    rv = switch_pub_asym_token_session(key, &uniontmc_key, op->mechanism.mechanism,
                                       &cache);
    if(rv != CKR_OK)
        goto end;



    rv = card->ops->encrypt(card, op->mechanism.mechanism,  key->keyType,
            uniontmc_key,
                             pData, ulDataLen,
                             pEncryptedData, pEncryptedDataLen
    );
    if(rv != CKR_OK)
        return rv;

    end:

    if(uniontmc_key)
    {
        free(uniontmc_key);
    }
    return rv;

}


static CK_RV
tmc_sign (struct tmc_pkcs11_session *session, void *sig_data,
CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature)
{
    CK_RV rv;
    struct tmc_card *card;
    struct signature_data * data = (struct signature_data *)sig_data;
    struct tmc_pkcs11_object *key = data->key;
    struct tmc_pkcs11_slot * slot;
    struct tmc_pkcs11_operation * op;
    CK_BYTE tmp_mem[512] = {0};

    CK_ULONG tmp = 0;
    struct tmcse_key *uniontmc_key = NULL;

    slot = session->slot;
    card = slot->p11card->card;

    rv = session_get_operation(session, SC_PKCS11_OPERATION_SIGN, &op);
    if(rv != CKR_OK)
        goto end;

    //rv = switch_token_session(key, &uniontmc_key);
    rv = switch_asym_token_session(key, &uniontmc_key, op->mechanism.mechanism);
    if(rv != CKR_OK)
        goto end;

    //区分对称密钥
    rv = card->ops->sign_data(card, op->mechanism.mechanism, key->keyType, uniontmc_key, pData,
                              ulDataLen, tmp_mem, &tmp);

    //rv = card->ops->sign_data(card, op->mechanism.mechanism, key->keyType, uniontmc_key, pData,
    //                          ulDataLen, tmp_mem, (CK_ULONG_PTR)&data);

    switch (op->mechanism.mechanism)
    {
        case CKM_ECDSA:
        case CKM_ECDSA_SHA1:
        case CKM_ECDSA_SHA256:
        case CKM_ECDSA_SHA384:
        case CKM_ECDSA_SHA512:
            //TBD:不同曲线签名长度不同，此处需要修改
            tmp = ec_curve_infos[0].size / 4;
            transASN1(tmp_mem, pSignature, FALSE,
                    &tmp);
            break;
        default:
            memcpy(pSignature, tmp_mem, tmp);
    }


    end:
    if(uniontmc_key)
    {
        free(uniontmc_key);
    }
    return rv;
}
static CK_RV
tmc_signVerify (struct tmc_pkcs11_session *session, struct tmc_pkcs11_object *key,
          CK_BYTE_PTR pData, CK_ULONG ulDataLen,
          CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    CK_RV rv;
    struct tmc_card *card;
    struct tmc_pkcs11_slot * slot;
    struct tmc_pkcs11_operation * op;
    struct tmcse_key *uniontmc_key = NULL;
    struct signature_data *data;
    CK_BYTE_PTR cache = NULL;
    CK_ULONG tmp_len = ulSignatureLen;
    CK_BYTE tmp_mem[512] = {0};

    slot = session->slot;
    card = slot->p11card->card;

    rv = session_get_operation(session, SC_PKCS11_OPERATION_VERIFY, &op);
    if(rv != CKR_OK)
        goto end;

    data = (struct signature_data *)op->priv_data;


    //rv = switch_token_session(key, &uniontmc_key);
    //rv = switch_asym_token_session(key, &uniontmc_key, op->mechanism.mechanism);
    rv = switch_pub_asym_token_session(key, &uniontmc_key, op->mechanism.mechanism,
            &cache);
    if(rv != CKR_OK)
        goto end;

    switch (op->mechanism.mechanism)
    {
        case CKM_ECDSA:
        case CKM_ECDSA_SHA1:
        case CKM_ECDSA_SHA256:
        case CKM_ECDSA_SHA384:
        case CKM_ECDSA_SHA512:
            //TBD:不同曲线签名长度不同，此处需要修改
            tmp_len = ec_curve_infos[0].size / 4;
            transASN1(pSignature, tmp_mem, TRUE,
                      &tmp_len);
            break;
        default:
            memcpy(tmp_mem, pSignature, tmp_len);
    }

    rv = card->ops->verify_sign(card, op->mechanism.mechanism, uniontmc_key, pData,
                              ulDataLen, tmp_mem, tmp_len);
    end:
    if(uniontmc_key)
    {
        free(uniontmc_key);
    }
    if(cache)
        free(cache);
    return rv;
}
static CK_RV
tmc_get_attribute(struct tmc_pkcs11_session *session, void *object, CK_ATTRIBUTE_PTR attr)
{
    struct tmc_pkcs11_object *key = (struct tmc_pkcs11_object*) object;
    CK_ATTRIBUTE_PTR attribute;

	//find the public exponent and modulus in key's value zone 
	if(attr->type == CKA_PUBLIC_EXPONENT) {
		CK_BYTE pub_exp[] = {0,1,0,1};
		
		attr->ulValueLen =  sizeof(pub_exp);
		
		if(attr->pValue == NULL) {
			return CKR_OK;
		}
		
		memcpy(attr->pValue, pub_exp, sizeof(pub_exp));
		return CKR_OK;
	}

	if(attr->type == CKA_MODULUS) {
		CK_ATTRIBUTE_TYPE type = CKA_MODULUS_BITS;
		attribute = list_seek(&key->attrs, &type);
		if(!attribute) {
			tmc_printf_t("[libsdk]: not found CKA_MODULUS_BITS in object's attributes list\n");
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}

		CK_ULONG modulus_bit = *((CK_ULONG_PTR)attribute->pValue);
		attr->ulValueLen = modulus_bit >> 3;

		if(attr->pValue == NULL) {
			return CKR_OK;
		}
		
		tmc_printf_t("[libsdk]: CKA_MODULUS_BITS = %d\n", modulus_bit);
		
		CK_RV rv = CKR_OK;
		struct tmc_card *card = session->slot->p11card->card;
		u16 pub_fid = key->fid & 0xFFFE;// even number fid is public fid, odd number fid is private fid
		
		if(card->ops->export_pubkey != NULL) {
			rv = card->ops->export_pubkey(card, pub_fid, attr->pValue, &attr->ulValueLen); 
			if (rv) {
				rv = card->ops->read_binary_sfi(card,card->manage_fid,(uint32_t)0x0,0x10,g_manageFile);
				tmc_printf("[libsdk]: g_manageFile: \n");
				for (int i = 0; i < sizeof(g_manageFile); i++) {
					if (i%4 == 0) {
						tmc_printf("\n\t");
					}
					tmc_printf("%02X",g_manageFile[i]);
				}
				tmc_printf("\n");
				
				tmc_printf_t("[libsdk]: Object's fid = 0x%04X\n", key->fid);

				CK_ATTRIBUTE_TYPE _class = CKA_CLASS;
				attribute = list_seek(&key->attrs, &_class);
				if(!attribute) {
					tmc_printf_t("[libsdk]: not found CKA_CLASS in object's attributes list\n");
					return CKR_ATTRIBUTE_TYPE_INVALID;
				}
				CK_OBJECT_CLASS class_type = *(CK_OBJECT_CLASS *)attribute->pValue;
				tmc_printf_t("[libsdk]: Object's CK_OBJECT_CLASS = 0x%08X\n", class_type);
			}
			return rv;
		}

	}

    attribute = list_seek(&key->attrs, &attr->type);
    if(!attribute)
        return CKR_ATTRIBUTE_TYPE_INVALID;
    switch (attribute->type)
    {
        case CKA_KEY_TYPE:
        case CKA_CLASS:
            *((CK_ULONG_PTR)attr->pValue) = *((CK_ULONG_PTR)attribute->pValue);
            break;
        case CKA_TOKEN:
        case CKA_PRIVATE:
        case CKA_SENSITIVE:
        case CKA_DECRYPT:
        case CKA_SIGN:
        case CKA_ENCRYPT:
        case CKA_VERIFY:
            *((CK_BBOOL *)attr->pValue) = *((CK_BBOOL *)attribute->pValue);
            break;
        case CKA_ID:
        case CKA_LABEL:
            if(attr->pValue == NULL) {
                attr->pValue = calloc(1, attribute->ulValueLen);
            }
            memcpy(attr->pValue, attribute->pValue, attribute->ulValueLen);

            break;
        default:
            if(attr->pValue == NULL) {
                attr->pValue = calloc(1, attribute->ulValueLen);
            }
            memcpy(attr->pValue, attribute->pValue, attribute->ulValueLen);
            break;
    }

    attr->ulValueLen = attribute->ulValueLen;
    return CKR_OK;
}
static CK_RV
tmc_set_attribute(struct tmc_pkcs11_session *session, void *object, CK_ATTRIBUTE_PTR attr)
{
    struct tmc_pkcs11_object *key = (struct tmc_pkcs11_object*) object;
    CK_ATTRIBUTE_PTR attribute;

    attribute = list_seek(&key->attrs, &attr->type);
    if(!attribute)
        return CKR_ATTRIBUTE_TYPE_INVALID;

    //若新的属性长度超过原有的,重新分配空间.
    if (attribute->ulValueLen < attr->ulValueLen) {
        attribute->pValue = realloc(attribute->pValue,attr->ulValueLen);
    }
    memcpy(attribute->pValue, attr->pValue, attribute->ulValueLen);

    return CKR_OK;
}
void tmc_release(void* obj)
{
    struct tmc_pkcs11_object *object;
    object = (struct tmc_pkcs11_object *)obj;
    if(object->attrs.numels)
    {
        list_destroy(&object->attrs);
    }
    memset(object, 0, sizeof*object);
    free(object);
}

CK_RV
tmc_set_object_state(uint16_t sfid, CK_BBOOL isFree) {

    CK_BYTE bfid = (CK_BYTE) sfid;
    CK_BYTE byteOff = (CK_BYTE)bfid/8;
    CK_BYTE bitOff = (CK_BYTE)bfid%8;
    CK_BYTE bitEnable = (CK_BYTE)(0xFF & (0x80>>bitOff));

    //读取管理文件.

    //设置FID对应的标志位.
    if (isFree) {
        g_manageFile[byteOff] &= ~bitEnable;
    } else {
        g_manageFile[byteOff] |= bitEnable;
    }

    return CKR_OK;
}

/* TMC Framework */
CK_RV
tmc_bind(struct tmc_pkcs11_card *p11card)
{
    CK_RV ck_rv;
    struct tmc_fw_data* fw_data;
    struct tmc_pkcs11_slot *slot = NULL;

    //we only support one slot by now,
    //if we need to support more slots
    //in the future, change this place
    slot = list_get_at(&virtual_slots, 0);

    if (!(fw_data = calloc(1, sizeof(*fw_data))))
        return CKR_HOST_MEMORY;

    p11card->fws_data = fw_data;
    ck_rv = tmc_internal_bind(p11card->card, &fw_data->inter_card);
    if(ck_rv == SC_SUCCESS)
        slot->token_info.flags |= CKF_TOKEN_PRESENT;
    else if(ck_rv != SC_ERROR_CARD_NOT_PRESENT)
        return ck_rv;

    /* Mechanisms are registered globally per card. Checking
     * p11card->nmechanisms avoids registering the same mechanisms twice for a
     * card with multiple slots. */
    if (!p11card->nmechanisms) {
        ck_rv = register_mechanisms(p11card);
        if (ck_rv != CKR_OK) {
            return ck_rv;
        }
    }

    return CKR_OK;
}

static CK_RV
tmc_init_p11card_slot(struct tmc_pkcs11_card *p11card, struct tmc_pkcs11_slot **out) 
{
    struct tmc_pkcs11_slot *slot = NULL;

    int rv;

    rv = slot_allocate(&slot, p11card);
    if (rv != CKR_OK)
        return rv;

    /* There's a token in this slot */
    //slot->slot_info.flags |= CKF_TOKEN_PRESENT;
    slot->token_info.flags |= CKF_TOKEN_INITIALIZED;
    slot->token_info.flags |= CKF_USER_PIN_INITIALIZED;
    slot->token_info.flags |= CKF_RNG;
    slot->token_info.ulMaxPinLen = 15;
    slot->token_info.ulMinPinLen = 6;

    *out = slot;
    return rv;
}


static CK_RV
tmc_create_tokens(struct tmc_pkcs11_card *p11card)
{
    struct tmc_fw_data *fw_data = NULL;
    struct tmc_pkcs11_slot *slot = NULL;

    /* Find out framework data corresponding to the given application */
    fw_data = p11card->fws_data;
    if (!fw_data)
    {
        return tmc_init_p11card_slot(p11card, &slot);
    }

    return CKR_OK;
}

CK_RV tmc_select(struct tmc_card* card, struct tmc_aid *aid)
{
    u8 cache[SC_MAX_APDU_BUFFER_SIZE] = {0x0};
    CK_ULONG * rLen = malloc(sizeof(CK_ULONG));

    return (CK_RV)card->ops->select_file(card, aid->value, (size_t)aid->len, cache, rLen);
}


#define slot_data(p) ((struct tmc_int_fw_data*)(p))
#define slot_data_check(p)  ((p && slot_data(p)) ? slot_data(p)->pin:0)

static CK_RV
tmc_login(struct tmc_pkcs11_slot *slot,CK_USER_TYPE usertype, CK_CHAR_PTR pin, CK_ULONG pinLen)
{
    CK_RV rv;
    struct tmc_card *card = slot->p11card->card;

    switch (usertype)
    {
        case CKU_USER:

            break;
        case CKU_SO:

            break;
        default:
            return CKR_USER_TYPE_INVALID;
    }

    rv = card->ops->verify_pin(card, usertype, pin, pinLen);
    if(rv != SC_SUCCESS) {
        if(usertype == CKU_USER) {
            slot->token_info.flags |= CKF_USER_PIN_COUNT_LOW;
        }
        else {
            slot->token_info.flags |= CKF_SO_PIN_COUNT_LOW;
        }
    }
    else {
        if(usertype == CKU_USER) {
            slot->token_info.flags &= ~CKF_USER_PIN_COUNT_LOW;
        }
        else {
            slot->token_info.flags &= ~CKF_SO_PIN_COUNT_LOW;
        }

    }

    return rv;
}

static CK_RV
tmc_logout(struct tmc_pkcs11_slot *slot)
{
    return CKR_OK;
}

static CK_RV
tmc_changepin(struct tmc_pkcs11_slot *slot, CK_USER_TYPE usertype, CK_CHAR_PTR pin, CK_ULONG pinlen)
{
    CK_RV rv;
    struct tmc_card *card = slot->p11card->card;

    rv = card->ops->change_pin(card, usertype, pin, pinlen);
    if(rv != SC_SUCCESS) {

    }
    else {

    }

    return rv;
}

static CK_RV
tmc_release_token(struct tmc_pkcs11_card *p11card, void *fw_token)
{
    free(fw_token);
    return CKR_FUNCTION_REJECTED;
}

static CK_RV
tmc_unbind(struct tmc_pkcs11_card *p11card)
{
    unsigned int i, idx;
    int rv = SC_SUCCESS;

    for (idx=0; idx<SC_PKCS11_FRAMEWORK_DATA_MAX_NUM; idx++)   {
        struct tmc_fw_data *fw_data = (struct tmc_fw_data *) p11card->fws_data;

        if (!fw_data)
            break;

        //unlock_card(fw_data);

        if (fw_data->inter_card) {
            if (idx == 0) {
                int rc = tmc_detect_card_presence(context);

            }
            free(fw_data->inter_card);
        }
        fw_data->inter_card = NULL;

        free(fw_data);
        p11card->fws_data = NULL;
    }

    return CKR_FUNCTION_FAILED;
}

static CK_RV
tmc_get_free_object(tmc_card_t *card,uint16_t *fid) {
    CK_RV rv;

    CK_ULONG length = 0x10;
    CK_BYTE  byte,bit;
    uint16_t tFID = (uint16_t)0;

    //解析文件内容，找到占用位为0
    for (uint32_t i = 0; i<0x10;i++) {
        byte = g_manageFile[i];
        for (bit = 0; bit < 8; bit++) {
            if (((byte>>(7-bit)) & 0x01) == 0) {
                tFID = (uint16_t)( (i*8 + bit) | 0xEF00);
                goto out;
            }
        }
    }

    out:
    if (tFID == 0) {
        rv = CKR_HOST_MEMORY;
    } else {
    		card->ops->delete_file(card, tFID);	//防止在创建文件成功后掉电，未更新管理文件的情况
        *fid = tFID;
        rv = CKR_OK;
    }
    return rv;
}
static CK_RV
tmc_initialize(struct tmc_pkcs11_slot *slot,
               CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
               CK_UTF8CHAR_PTR pLabel)
{
    CK_RV rc;
    struct tmc_card *card;
    u8 mf_aid[10] = {"PolarisApp"};
    u8 tmp_resp[SC_MAX_APDU_BUFFER_SIZE] = {0x0};
    CK_ULONG reLen = sizeof(tmp_resp);
    u8 lifecycle = 0;

    card = slot->p11card->card;
    tmc_lock(card);

    //Select applet
    rc = card->ops->select_file(card, mf_aid, sizeof(mf_aid), tmp_resp, &reLen);
    if (rc != CKR_OK) {
        rc = CKR_TOKEN_NOT_PRESENT;
        goto error;
    }



    //Select MF
    rc = card->ops->select_MF(card);
    if ((rc != CKR_OK) && (rc != CKR_OBJECT_HANDLE_INVALID)) {
        rc = CKR_TOKEN_NOT_PRESENT;
        goto error;
    }

    //MF Exist
    if (rc == CKR_OK) {
        rc = card->ops->get_card_state(card, &lifecycle);
        if(rc != CKR_OK) {
            rc = CKR_FUNCTION_FAILED;
            goto error;
        }
		
        if (lifecycle == 0x01) {//使用阶段需要校验SO PIN
            //Verify SO PIN
            rc = card->ops->verify_pin(card, CKU_SO, pPin, ulPinLen);
            if (rc != CKR_OK) {
                rc = CKR_USER_NOT_LOGGED_IN;
                goto error;
            }
        }
		
        //Delete MF
        rc = card->ops->delete_file(card, (u16)0x3F00);
        if (rc != CKR_OK) {
            rc = CKR_FUNCTION_FAILED;
            goto error;
        }
		

    }
    rc = card->ops->create_alg(card, 0x0001);//AES
    if (rc != CKR_OK) {
       rc = CKR_FUNCTION_FAILED;
       goto error;
    }

    rc = card->ops->create_alg(card, 0x0002);//DES
    if (rc != CKR_OK) {
       rc = CKR_FUNCTION_FAILED;
       goto error;
    }

    rc = card->ops->create_alg(card, 0x0003);//SM1
    if (rc != CKR_OK) {
       rc = CKR_FUNCTION_FAILED;
       goto error;
    }

    rc = card->ops->create_alg(card, 0x0004);//SM4
    if (rc != CKR_OK) {
       rc = CKR_FUNCTION_FAILED;
       goto error;
    }

    rc = card->ops->create_alg(card, 0x0010);//RSA
    if (rc != CKR_OK) {
       rc = CKR_FUNCTION_FAILED;
       goto error;
    }

    rc = card->ops->create_alg(card, 0x0030);//SM2
    if (rc != CKR_OK) {
       rc = CKR_FUNCTION_FAILED;
       goto error;
    }

    rc = card->ops->create_alg(card, 0x0040);//ECC
    if (rc != CKR_OK) {
       rc = CKR_FUNCTION_FAILED;
       goto error;
    }

    //Verify TK
    rc = card->ops->verify_tk(card, pPin, ulPinLen);
    if (rc != CKR_OK) {
        rc = CKR_USER_NOT_LOGGED_IN;
        goto error;
    }

    //Create MF
    rc = card->ops->create_df(card, (u16)0x3F00, mf_aid, sizeof(mf_aid));
    if (rc != CKR_OK) {
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }

    //Create Key File
    rc = card->ops->create_pin(card, (u16)0x0000);
    if (rc != CKR_OK) {
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }

    //Write SO PIN
    rc = card->ops->write_pin(card, CKU_SO, (u8)15, pPin, ulPinLen);
    if (rc != CKR_OK) {
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }

    //Update TK
    rc = card->ops->change_tk(card, pPin, ulPinLen);
    if (rc != CKR_OK) {
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }

    //Create ManageFile
    rc = card->ops->create_bin(card, (u16)0xEE01, (CK_ULONG)0x10);
    if (rc != CKR_OK) {
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }

    //End Personal
    rc = card->ops->end_personal(card);
    if (rc != CKR_OK) {
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }

    tmc_unlock(card);
    return CKR_OK;

    error:
    tmc_unlock(card);
    return rc;
}

static CK_RV
tmc_add_atr(list_t * attr_list, CK_ATTRIBUTE_TYPE  type,
        void* pValue, CK_ULONG size, CK_ULONG_PTR p_attr_len)
{
    CK_RV rv = CKR_OK;
    CK_ATTRIBUTE_PTR attr = NULL;
    CK_ULONG attr_len = *p_attr_len;
    attr = calloc(1, sizeof(CK_ATTRIBUTE));
    if(!attr)
    {
        rv = CKR_HOST_MEMORY;
        goto error;
    }

    attr->type = type;
    attr_len += sizeof(CK_ULONG);
    attr->pValue = calloc(1, size);
    if(!attr->pValue)
    {
        rv = CKR_HOST_MEMORY;
        goto error;
    }
    memcpy(attr->pValue, pValue, size);
    attr_len += size;
    attr->ulValueLen = size;
    list_append(attr_list, attr);
    attr_len += sizeof(CK_ULONG);
    *p_attr_len = attr_len;
    return rv;
    error:
    if(attr)
        free(attr);
    return rv;
}

static CK_RV tmc_derive(struct tmc_pkcs11_session * session, void * data,
                        CK_MECHANISM_TYPE mech, CK_MECHANISM_TYPE kdf,
                        CK_BYTE_PTR pSeedData, CK_ULONG ulSeedDataLen,
                        CK_OBJECT_HANDLE_PTR phKey)
{
    CK_RV rv;
    CK_BYTE_PTR attrsValue = NULL, attrKey = NULL;
    struct tmc_pkcs11_object *key, *object = NULL;
    struct tmc_card *card;
    CK_KEY_TYPE _key_type;
    CK_BBOOL _token, _private = TRUE;
    CK_ULONG attrLen, keyValLen, transCount = 0;
    CK_ATTRIBUTE_PTR attr = NULL;
    struct agreement_data *my_data;
    CK_ULONG _tmp_size = 0;
    uint16_t fid = 0xFFFF;
    CK_ULONG_PTR tmp = NULL;

    card = session->slot->p11card->card;
    my_data = (struct agreement_data *)data;
    key = my_data->key;

    object = calloc(1, sizeof(struct tmc_pkcs11_object));
    if(!object)
    {
        rv = CKR_HOST_MEMORY;
        goto err;
    }

    list_init(&object->attrs);

    rv = attr_storage(TRUE,my_data->pTemplate,my_data->ulAttrbuteCount,
                      &object->attrs,&attrLen);
    if(rv != CKR_OK)
        return rv;

    _tmp_size = sizeof(CK_ULONG);
    rv = attr_find(my_data->pTemplate, my_data->ulAttrbuteCount,
                   CKA_KEY_TYPE, &_key_type, &_tmp_size);
    if(rv != CKR_OK)
    {
        _key_type = CKK_AES;
        rv = tmc_add_atr(&object->attrs, CKA_KEY_TYPE,
                &_key_type, sizeof(CK_ULONG), &attrLen);
        if(rv != CKR_OK)
            return rv;

    }

    rv = attr_find(my_data->pTemplate, my_data->ulAttrbuteCount,
                   CKA_TOKEN, &_token, &_tmp_size);
    if(rv != CKR_OK)
    {
        _token = CK_TRUE;
        rv = tmc_add_atr(&object->attrs, CKA_TOKEN,
                    &_token, sizeof(CK_BBOOL), &attrLen);
        if(rv != CKR_OK)
            return rv;
    }

    rv = attr_find(my_data->pTemplate, my_data->ulAttrbuteCount,
                   CKA_PRIVATE, &_private, &_tmp_size);
    if(rv != CKR_OK)
    {
        _private = CK_TRUE;
        rv = tmc_add_atr(&object->attrs, CKA_PRIVATE,
                    &_private, sizeof(CK_BBOOL), &attrLen);
        if(rv != CKR_OK)
            return rv;
    }

    switch(_key_type)
    {
        case CKK_AES:
            keyValLen = 16;
            break;
        case CKK_DES:
            keyValLen = 8;
            break;
        case CKK_DES2:
            keyValLen = 16;
            break;
        case CKK_DES3:
            keyValLen = 24;
            break;
        case CKK_SM1:
            keyValLen = 16;
            break;
        case CKK_SM4:
            keyValLen = 16;
            break;
        default:
            return CKR_KEY_TYPE_INCONSISTENT;
    }


    if(_token)
    {
        //找到一个空闲的FID
        rv = card->ops->read_binary_sfi(card,card->manage_fid,(uint32_t)0x0,0x10,g_manageFile);
        if (rv != CKR_OK) {
            return rv;
        }

        rv = tmc_get_free_object(card,&fid);
        if (rv != CKR_OK) {
            goto err;
        }
        //创建对象文件
        rv = card->ops->create_object(card,fid,(u_int8_t)CKO_SECRET_KEY,_private,attrLen+SE_OBJ_SIZE_RESERVE,keyValLen);

        if (rv != CKR_OK)
            goto err;
        transCount |= 0x1UL;

        //保存属性到SE中
        rv = attribute_list_to_array(&object->attrs,attrLen);
        if (rv != CKR_OK)
            goto err;

        rv = card->ops->update_object(card,fid,SE_OBJ_FLAG_ATTR,0x0,attrLen,g_attrArr);
        if (rv != CKR_OK)
            goto err;
        //生成协商密钥

        switch (mech)
        {
            case CKM_ECDH1_DERIVE:
                rv = card->ops->ecc_exchangekey(card, _key_type,key->fid,pSeedData,
                                                ulSeedDataLen, fid);
                if (rv != CKR_OK)
                    goto err;
                break;
            case CKM_DH_PKCS_DERIVE:

                rv = card->ops->dh_exchangekey(card, _key_type,key->fid,pSeedData,
                                                ulSeedDataLen, fid);
                if (rv != CKR_OK)
                    goto err;
                break;
            default:
                goto err;
        }


        //更新管理文件：FID被占用
        rv = tmc_set_object_state(fid,CK_FALSE);
        if (rv != CKR_OK)
            goto err;
        transCount |= (0x1UL << 1);
        rv = card->ops->update_binary_sfi(card,card->manage_fid,0x0,g_manageFile,(uint32_t)0x10);
        if (rv != CKR_OK)
            goto err;
        transCount |= (0x1UL << 2);
        
        free(attrsValue);
        free(attrKey);
    }
    else
    {

        switch (mech)
        {
            case CKM_ECDH1_DERIVE:
                rv = card->ops->ecc_exchangekey_ex(card, _key_type,key->fid, pSeedData,
                                                   ulSeedDataLen, NULL, &keyValLen);
                if (rv != CKR_OK)
                    goto erro;
                break;
            case CKM_DH_PKCS_DERIVE:
                rv = card->ops->dh_exchangekey_ex(card, _key_type,key->fid, pSeedData,
                                                   ulSeedDataLen, NULL, &keyValLen);
                if (rv != CKR_OK)
                    goto erro;
                break;
            default:
                goto erro;
        }
        
        //SE加密session密钥
        attrKey = calloc(1,keyValLen);
        if (attrKey == NULL) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }

        switch (mech)
        {
            case CKM_ECDH1_DERIVE:
                rv = card->ops->ecc_exchangekey_ex(card,_key_type,key->fid, pSeedData,
                                                   ulSeedDataLen, attrKey, &keyValLen);
                if (rv != CKR_OK)
                    goto erro;
                break;
            case CKM_DH_PKCS_DERIVE:
                rv = card->ops->dh_exchangekey_ex(card,_key_type,key->fid, pSeedData,
                                                   ulSeedDataLen, attrKey, &keyValLen);
                if (rv != CKR_OK)
                    goto erro;
                break;
            default:
                break;
        }


        attr = calloc(1, sizeof(CK_ATTRIBUTE));
        if (attr == NULL) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }
        attr->type = CKA_VALUE;
        attr->ulValueLen = keyValLen;
        attr->pValue = attrKey;

        rv = list_append(&object->attrs,attr);
        if (rv != CKR_OK) {
            rv = CKR_HOST_MEMORY;
            goto erro;
        }
        
        attr = calloc(1, sizeof(CK_ATTRIBUTE));
        if (attr == NULL) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }
        attr->type = CKA_VALUE_LEN;
        attr->ulValueLen = sizeof(CK_ULONG);
        tmp = calloc(1 , sizeof(CK_ULONG));
        if(!tmp)
        {
            rv = CKR_HOST_MEMORY;
            goto erro;
        }    
        *tmp = keyValLen;
        attr->pValue = tmp;

        object->hSession = session->handle;
        rv = list_append(&object->attrs,attr);
        if (rv != CKR_OK) {
            rv = CKR_HOST_MEMORY;
            goto erro;
        }
    }
    
    object->fid = fid;
    object->ops = &secret_ops;

    list_attributes_seeker(&object->attrs, attribute_list_seeker);
    tmc_add_object(session->slot, object, phKey);
    
    rv = tmc_unlock(session->slot->p11card->card);
    if (rv != CKR_OK) {
        goto err;
    }
    
    return rv;
    err:
    if(transCount & (1UL << 1))
        tmc_set_object_state(fid,CK_TRUE);
    if(transCount & 1UL)
        card->ops->delete_file(card,fid);
    if(transCount & (1UL << 2))
        card->ops->update_binary_sfi(card,card->manage_fid,0x0,g_manageFile,(uint32_t)0x10);
    erro:
        if(object)
            free(object);
    if(attr)
        free(attr);
    if(attrKey)
        free(attrKey);
    if(attrsValue)
        free(attrsValue);
    if(tmp)
        free(tmp);
    return rv;
}
static CK_RV
tmc_create_token_object (tmc_card_t *card, tmc_pkcs11_object_t *obj, tmc_object_t *tmcObj) {
    CK_RV rv;
    CK_ULONG keySize = 0;
    uint16_t objFid;

    if (!card || !obj || !tmcObj) {
        rv = CKR_ARGUMENTS_BAD;
        return rv;
    }
    u32 attrZoneSize = tmcObj->attrsLen + SE_OBJ_SIZE_RESERVE;
    //锁定
    rv = tmc_lock(card);
    if (rv != CKR_OK)
        goto err;

    //找到一个空闲的FID
    rv = card->ops->read_binary_sfi(card,card->manage_fid,(uint32_t)0x0,0x10,g_manageFile);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = tmc_get_free_object(card,&objFid);
    if (rv != CKR_OK) {
        return rv;
    }
    //创建对象文件
    if (tmcObj->objClass == CKO_PUBLIC_KEY || tmcObj->objClass == CKO_PRIVATE_KEY ) {
        if ((tmcObj->keyType == CKK_EC) || (tmcObj->keyType == CKK_DH)) {
            keySize = tmcObj->valueLen + tmcObj->keyParamLen;//密钥 = 密钥值 + 参数
        }
        else {
            keySize = tmcObj->valueLen;
        }
    }
    else {
        keySize = tmcObj->valueLen;
    }

    rv = card->ops->create_object(card,objFid,tmcObj->objClass,tmcObj->isPriv,attrZoneSize,keySize);
    if (rv != CKR_OK) {
        goto err;
    }

    //保存属性到SE中
    rv = attribute_list_to_array(&obj->attrs,tmcObj->attrsLen);
    if (rv != CKR_OK) {
        goto err;
    }

    rv = card->ops->update_object(card,objFid,SE_OBJ_FLAG_ATTR,0x0,tmcObj->attrsLen,g_attrArr);
    if (rv != CKR_OK)
        goto err;

//    printf ("tmc_create_token_object(type is 0x%lx): length of value is 0x%lx：\n",tmcObj->objClass,tmcObj->valueLen);
    switch (tmcObj->objClass) {
        case CKO_CERTIFICATE:
        case CKO_DATA:
            rv = card->ops->update_object(card,objFid,SE_OBJ_FLAG_VALUE,0x0,tmcObj->valueLen,tmcObj->pValue);
            if (rv != CKR_OK)
                goto err;
            break;
        case CKO_PUBLIC_KEY:
            rv = card->ops->import_pubkey(card,tmcObj->keyType,tmcObj->pKeyParam,tmcObj->keyParamLen,
                                          tmcObj->pValue,tmcObj->valueLen,objFid);
            if (rv != CKR_OK)
                goto err;
            break;
        case CKO_PRIVATE_KEY:
            rv = card->ops->import_prikey(card,tmcObj->keyType,obj->keyType,tmcObj->pKeyParam,tmcObj->keyParamLen,
                                          tmcObj->pValue,tmcObj->valueLen,objFid);
            if (rv != CKR_OK)
                goto err;
            break;
        case CKO_SECRET_KEY:
            rv = card->ops->import_key(card, tmcObj->keyType, tmcObj->pValue, tmcObj->valueLen, objFid);
            if (rv != CKR_OK)
                goto err;
            break;
        default:
            return CKR_ARGUMENTS_BAD;
    }


    //更新管理文件：FID被占用
    rv = tmc_set_object_state(objFid,CK_FALSE);
    rv = card->ops->update_binary_sfi(card,card->manage_fid,0x0,g_manageFile,(uint32_t)0x10);
    if (rv != CKR_OK)
        goto err;

    obj->fid = objFid;

    tmc_unlock(card);

    return CKR_OK;

    err:
    //TBD: 处理卡片被锁定的情况

    if (card->ops->delete_file(card,objFid) != CKR_OK) {
        return rv;
    }
    tmc_set_object_state(objFid,CK_TRUE);//恢复管理文件中的FID占用状态为空闲

    tmc_unlock(card);
    return rv;

}
static CK_RV
tmc_create_public_object(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                         CK_OBJECT_HANDLE_PTR phObject) {

    struct tmc_pkcs11_slot *slot;
    struct tmc_card *card;
    struct tmc_pkcs11_object *obj;
    CK_BBOOL isToken = CK_TRUE;
    CK_BYTE_PTR attrN = NULL_PTR,attrE = NULL_PTR,pTemp = NULL_PTR,pTemp2 = NULL_PTR,pTemp3 = NULL_PTR;
    CK_ULONG attrNLen = 0,attrELen = 0;
    CK_ULONG tempLen = 0,tempLen2 = 0;
    CK_RV rv;

    struct tmc_object tmcObj;
    tmcObj.isPriv = CK_TRUE;
    tmcObj.pValue = NULL_PTR;
    tmcObj.pKeyParam = NULL_PTR;
    tmcObj.objClass = CKO_PUBLIC_KEY;

    rv = get_slot_from_session(hSession, &slot);
    if (rv != CKR_OK) {
        return rv;
    }
    card = slot->p11card->card;
    rv = attr_find(pTemplate, ulCount, CKA_KEY_TYPE, &(tmcObj.keyType), NULL);
    if (rv != CKR_OK) {
        goto err;
    }

    //新建对象
    obj = (struct tmc_pkcs11_object *) calloc(1,sizeof(struct tmc_pkcs11_object));
    if (obj == NULL) {
        rv = CKR_HOST_MEMORY;
        goto err;
    }
    if (0 != list_init(&obj->attrs)) {
        rv = CKR_HOST_MEMORY;
        goto err;
    }
    list_attributes_seeker(&obj->attrs,attribute_list_seeker);
    //在SDK内保存对象属性(不包含密钥值)
    rv = attr_storage(FALSE,pTemplate,ulCount,&obj->attrs,&tmcObj.attrsLen);
    if (rv != CKR_OK) {
        goto err;
    }

    if (attr_find(pTemplate, ulCount, CKA_TOKEN, &isToken, NULL) != CKR_OK) {
        rv = add_new_attribute(obj,CKA_TOKEN,(CK_BBOOL*)&isToken,&tmcObj.attrsLen);
        if (rv != CKR_OK) {
            goto err;
        }
    }
    //arrtibute - CKA_PRIVATE.
    if (attr_find(pTemplate,ulCount,CKA_PRIVATE,&(tmcObj.isPriv),NULL) != CKR_OK) {
        rv = add_new_attribute(obj, CKA_PRIVATE, (CK_BBOOL *) &(tmcObj.isPriv), &tmcObj.attrsLen);
        if (rv != CKR_OK) {
            goto err;
        }
    }

    switch (tmcObj.keyType)
    {
        case CKK_RSA:
            //查找密钥值-N
            rv = attr_find_ptr(pTemplate, ulCount, CKA_MODULUS,(void **)&attrN, &attrNLen);
            if (rv == CKR_TEMPLATE_INCOMPLETE) {
                rv = attr_find_ptr(pTemplate, ulCount, CKA_VALUE, (void **)&attrN, &attrNLen);
                if (rv != CKR_OK) {
                    goto err;
                }
            } else if (rv != CKR_OK) {
                goto err;
            }
            if (attrNLen > 512) {
                rv = CKR_DATA_LEN_RANGE;//the length of key should be  <= 4096 bits.
                goto err;
            }

            //查找密钥值-E
            rv = attr_find_ptr(pTemplate, ulCount, CKA_PUBLIC_EXPONENT, (void **)&attrE, &attrELen);
            if (rv == CKR_TEMPLATE_INCOMPLETE) {
                goto err;
            }
            if (attrELen != 4) {
                rv = CKR_ATTRIBUTE_VALUE_INVALID;
                goto err;
            }

            //Token对象组织密钥值
            if (isToken) {
                tmcObj.valueLen = attrNLen+attrELen;
                if (tmcObj.valueLen > sizeof(g_tempBuff)) {
                    rv = CKR_HOST_MEMORY;
                    goto err;
                }
                memset(g_tempBuff,0, sizeof(g_tempBuff));
                tmcObj.pValue = g_tempBuff;
                memcpy(tmcObj.pValue,attrN,attrNLen);
                memcpy((tmcObj.pValue + attrNLen),attrE,attrELen);
            }

            break;

        case CKK_SM2:
            rv = attr_find_ptr(pTemplate, ulCount, CKA_VALUE, (void **)&tmcObj.pValue, &tmcObj.valueLen);
            if (rv != CKR_OK) {
                goto err;
            }

            if (tmcObj.valueLen != 64) {
                rv = CKR_DATA_LEN_RANGE;
                goto err;
            }
            break;
        case CKK_EC:
            rv = attr_find_ptr(pTemplate, ulCount, CKA_EC_POINT, (void **)&tmcObj.pValue, &tmcObj.valueLen);
            if (rv != CKR_OK) {
                goto err;
            }

            rv = attr_find_ptr(pTemplate, ulCount, CKA_EC_PARAMS, (void **)&pTemp, NULL);
            if (rv != CKR_OK) {
                goto err;
            }

            rv = tmc_find_alloc_ec_param(pTemp,&(tmcObj.pKeyParam),&(tmcObj.keyParamLen),NULL_PTR);
            if (rv != CKR_OK) {
                goto err;
            }
            break;
        case CKK_DH:
            rv = attr_find_ptr(pTemplate, ulCount, CKA_VALUE, (void **)&tmcObj.pValue, &tmcObj.valueLen);
            if (rv != CKR_OK) {
                goto err;
            }
            //P
            rv = attr_find_ptr(pTemplate, ulCount, CKA_PRIME, (void **)&pTemp, &tempLen);
            if (rv != CKR_OK) {
                goto err;
            }
            //G
            rv = attr_find_ptr(pTemplate, ulCount, CKA_BASE, (void **)&pTemp2, &tempLen2);
            if (rv != CKR_OK) {
                goto err;
            }
            if (isToken) {
                tmcObj.keyParamLen = 4 + tempLen + tempLen2 + 2;//L(P)+P+L(G)+G+0000(L(Q))
                if (tmcObj.keyParamLen > sizeof(g_tempBuff)) {
                    rv = CKR_HOST_MEMORY;
                    goto err;
                }
                memset(g_tempBuff,0,sizeof(g_tempBuff));
                g_tempBuff[0] = (u8)(tempLen>>8 & 0xFF);
                g_tempBuff[1] = (u8)(tempLen & 0xFF);
                memcpy(g_tempBuff + 2,pTemp,tempLen);
                g_tempBuff[tempLen+2] = (u8)(tempLen2>>8 & 0xFF);
                g_tempBuff[tempLen+3] = (u8)(tempLen2 & 0xFF);
                memcpy(g_tempBuff+ 4 + tempLen,pTemp2,tempLen2);
                tmcObj.pKeyParam = g_tempBuff;
            }
            break;
        default:
            rv = CKR_ATTRIBUTE_TYPE_INVALID;
            return rv;
    }

    if (isToken) {
        rv = tmc_create_token_object(card,obj,&tmcObj);
        if (rv != CKR_OK) {
            goto err;
        }
    }
    else {

        obj->hSession = hSession;
        obj->fid = 0xFFFF;

    }
    obj->ops = &pub_ops;

    tmc_add_object(slot,obj,phObject);

    return CKR_OK;

    err:

    if (obj) {
        tmc_delete_object_attrs(obj);
        list_delete(&slot->objects,obj);
        free(obj);
    }
    return rv;
}
static CK_RV
tmc_create_private_object(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                         CK_OBJECT_HANDLE_PTR phObject) {
    struct tmc_pkcs11_slot *slot;
    struct tmc_card *card;
    struct tmc_pkcs11_object *obj = NULL_PTR;
    CK_BBOOL isToken = CK_TRUE;//默认密钥存在SE上.
    CK_BBOOL isAllowedSesKey = CK_TRUE,isAddTokenAttr = CK_FALSE;
    CK_BYTE_PTR encKeyValue = NULL_PTR, attrN = NULL_PTR, attrD = NULL_PTR,pTemp = NULL_PTR,pTemp2 = NULL_PTR;
    CK_ATTRIBUTE_PTR attr = NULL_PTR;
    CK_ULONG attrNLen = 0,attrDLen = 0,rsaKeyType = RSA_KEY_TYPE_ND;
    CK_ULONG tempLen = 0, tempLen2 = 0;
    CK_RV rv;
    struct tmc_object tmcObj;
    tmcObj.isPriv = CK_TRUE;
    tmcObj.pValue = NULL_PTR;
    tmcObj.pKeyParam = NULL_PTR;
    tmcObj.objClass = CKO_PRIVATE_KEY;

    rv = get_slot_from_session(hSession, &slot);
    if (rv != CKR_OK) {
        return rv;
    }
    card = slot->p11card->card;
    rv = attr_find(pTemplate, ulCount, CKA_KEY_TYPE, &(tmcObj.keyType), NULL);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = attr_find(pTemplate, ulCount, CKA_TOKEN, &isToken, NULL);
    if (rv == CKR_TEMPLATE_INCOMPLETE) {
        isAddTokenAttr = CK_TRUE;
    }

    //Key value.
    switch (tmcObj.keyType) {
        case CKK_RSA:
            //先找CKA_PRIVATE_EXPONENT,若有则认为ND模式,将D作为密钥值保存
            rv = attr_find_ptr(pTemplate, ulCount, CKA_PRIVATE_EXPONENT, (void **)&attrD, &attrDLen);
            if (rv == CKR_TEMPLATE_INCOMPLETE) {

                //RSA密钥给5个分量时,不支持session类型
                isAllowedSesKey = CK_FALSE;
                //查找CRT分量P
                CK_ATTRIBUTE_PTR attrCRTVal[5];
                CK_ULONG attrPLen = 0, attrLen = 0, i;
                rv = attr_find_ptr(pTemplate, ulCount, CKA_PRIME_1, (void **)&attrCRTVal[0], &attrPLen);

                if (rv == CKR_OK) {
                    if (attrPLen > 256) {
                        rv = CKR_DATA_LEN_RANGE;
                        goto err;
                    }

                    for (i = 1; i < 5; i++) {
                        rv = attr_find_ptr(pTemplate, ulCount, CKA_PRIME_1 + i, (void **)&attrCRTVal[i], &attrLen);
                        if (rv != CKR_OK || (attrLen != attrPLen))
                            goto err;
                    }

                    //保存RSA 5个分量,依次为P+Q+DP+DQ+PQ
                    tmcObj.valueLen = (CK_ULONG)(attrPLen * 5);
                    tmcObj.pValue = calloc(1, tmcObj.valueLen);
                    for (i = 0; i < 5; i++) {
                        memcpy(tmcObj.pValue  + i * attrPLen, attrCRTVal[i], attrPLen);
                    }
                    rsaKeyType = RSA_KEY_TYPE_CRT;
                } else {
                    goto err;
                }

            } else if (rv == CKR_OK) {
                rv = attr_find_ptr(pTemplate, ulCount, CKA_MODULUS, (void **)&attrN, &attrNLen);
                if (rv != CKR_OK) {
                    goto err;
                }
                if ((attrDLen > 512) || (attrNLen != attrDLen)) {
                    rv = CKR_DATA_LEN_RANGE;
                    goto err;
                }

                tmcObj.valueLen = attrNLen + attrDLen;
                tmcObj.pValue = calloc(1, tmcObj.valueLen);
                memcpy(tmcObj.pValue, attrN, attrNLen);
                memcpy(tmcObj.pValue + attrNLen, attrD, attrDLen);

            }
            break;
        case CKK_SM2:
            rv = attr_find_ptr(pTemplate, ulCount, CKA_VALUE, (void **)&tmcObj.pValue, &tmcObj.valueLen);
            if (rv != CKR_OK) {
                goto err;
            }
            if (tmcObj.valueLen != 32) {
                rv = CKR_DATA_LEN_RANGE;
                goto err;
            }
            break;
        case CKK_EC:
            rv = attr_find_ptr(pTemplate, ulCount, CKA_VALUE, (void **)&tmcObj.pValue, &tmcObj.valueLen);
            if (rv != CKR_OK) {
                goto err;
            }
            rv = attr_find_ptr(pTemplate, ulCount, CKA_EC_PARAMS, (void **)&pTemp, NULL);
            if (rv != CKR_OK) {
                goto err;
            }
            rv = tmc_find_alloc_ec_param(pTemp,&(tmcObj.pKeyParam),&(tmcObj.keyParamLen),NULL_PTR);
            if (rv != CKR_OK) {
                goto err;
            }
            break;
        case CKK_DH:
            rv = attr_find_ptr(pTemplate, ulCount, CKA_VALUE, (void **)&tmcObj.pValue, &tmcObj.valueLen);
            if (rv != CKR_OK) {
                goto err;
            }
            //P
            rv = attr_find_ptr(pTemplate, ulCount, CKA_PRIME, (void **)&pTemp, &tempLen);
            if (rv != CKR_OK) {
                goto err;
            }
            //G
            rv = attr_find_ptr(pTemplate, ulCount, CKA_BASE, (void **)&pTemp2, &tempLen2);
            if (rv != CKR_OK) {
                goto err;
            }
            if (isToken) {
                tmcObj.keyParamLen = 4 + tempLen + tempLen2 + 2;//L(P)+P+L(G)+G+0000(L(Q))
                if (tmcObj.keyParamLen > sizeof(g_tempBuff)) {
                    rv = CKR_HOST_MEMORY;
                    goto err;
                }
                memset(g_tempBuff,0,sizeof(g_tempBuff));
                g_tempBuff[0] = (u8)(tempLen>>8 & 0xFF);
                g_tempBuff[1] = (u8)(tempLen & 0xFF);
                memcpy(g_tempBuff + 2,pTemp,tempLen);
                g_tempBuff[tempLen+2] = (u8)(tempLen2>>8 & 0xFF);
                g_tempBuff[tempLen+3] = (u8)(tempLen2 & 0xFF);
                memcpy(g_tempBuff+ 4 + tempLen,pTemp2,tempLen2);
                tmcObj.pKeyParam = g_tempBuff;
            }
            break;
        default:
            rv = CKR_ATTRIBUTE_VALUE_INVALID;
            return rv;
    }

    //新建对象
    obj = (struct tmc_pkcs11_object *) calloc(1,sizeof(struct tmc_pkcs11_object));
    if (obj == NULL) {
        rv = CKR_HOST_MEMORY;
        goto err;
    }
    if (0 != list_init(&obj->attrs)) {
        rv = CKR_HOST_MEMORY;
        goto err;
    }
    list_attributes_seeker(&obj->attrs,attribute_list_seeker);

    //rsaKeyType
    obj->keyType = rsaKeyType;

    //在SDK内保存对象属性(不包含密钥值),session类型的密钥值加密后添加.
    rv = attr_storage(CK_TRUE,pTemplate,ulCount,&obj->attrs,&tmcObj.attrsLen);
    if (rv != CKR_OK) {
        goto err;
    }

    if (isAddTokenAttr) {
       rv = add_new_attribute(obj,CKA_TOKEN,(CK_BBOOL*)&isToken,&tmcObj.attrsLen);
       if (rv != CKR_OK) {
           goto err;
       }
    }
    //arrtibute - CKA_PRIVATE.
    if (attr_find(pTemplate,ulCount,CKA_PRIVATE,&(tmcObj.isPriv),NULL) != CKR_OK) {
        rv = add_new_attribute(obj, CKA_PRIVATE, (CK_BBOOL *) &(tmcObj.isPriv), &tmcObj.attrsLen);
        if (rv != CKR_OK) {
            goto err;
        }
    }


    if (isToken) {

        rv = tmc_create_token_object(card,obj,&tmcObj);
        if (rv != CKR_OK) {
            goto err;
        }
    }
    else {
        if (!isAllowedSesKey) {
            return CKR_ATTRIBUTE_VALUE_INVALID;//不支持5个分量的session类型对象.属性值不好处理.TBD
        }
        //SE加密session密钥
        CK_ULONG encKeyLen = 0;
        if (tmcObj.valueLen%ENC_KEY_BLOCK_SIZE) {
            encKeyLen = tmcObj.valueLen + (ENC_KEY_BLOCK_SIZE - tmcObj.valueLen%ENC_KEY_BLOCK_SIZE);
        }
        else {
            //强制填充.
            encKeyLen = tmcObj.valueLen + ENC_KEY_BLOCK_SIZE;
        }
        encKeyValue = calloc(1,encKeyLen);
        if (encKeyValue == NULL) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }
        rv = card->ops->enc_key(card,tmcObj.pValue,tmcObj.valueLen,encKeyValue,&encKeyLen);
        if (rv != CKR_OK) {
            goto err;
        }

        attr = calloc(1,sizeof(CK_ATTRIBUTE));
        if (attr == NULL) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }
        attr->type = CKA_VALUE;
        attr->ulValueLen = pTemplate->ulValueLen;
        attr->pValue = encKeyValue;

        obj->fid = 0xFFFF;
        obj->hSession = hSession;

        if (0 > list_append(&obj->attrs,attr)) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }
    }
    obj->ops = &priv_ops;

    tmc_add_object(slot,obj,phObject);

    if ((tmcObj.keyType == CKK_RSA) && tmcObj.pValue) {
        free(tmcObj.pValue);
    }
    return CKR_OK;

    err:

    //释放内存空间
    if (encKeyValue != NULL_PTR) {
        free(encKeyValue);
    }
    if (attr != NULL_PTR) {
        free(attr);
    }

    if ((tmcObj.keyType == CKK_RSA) && tmcObj.pValue) {
        free(tmcObj.pValue);
    }

    if (obj) {
        tmc_delete_object_attrs(obj);
        list_delete(&slot->objects,obj);
        free(obj);
    }
    return rv;
}
static CK_RV
tmc_create_secret_object(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                         CK_OBJECT_HANDLE_PTR phObject) {
    struct tmc_pkcs11_slot *slot;
    struct tmc_card *card;
    struct tmc_pkcs11_object *obj = NULL_PTR;
    CK_BBOOL isToken = CK_FALSE,isAddTokenAttr = CK_FALSE;
    CK_BYTE_PTR encKeyValue = NULL_PTR;
    CK_ATTRIBUTE_PTR attr = NULL_PTR;
    CK_ULONG attrsLen = 0, keyLength = 0,encKeyLen = 0;
    CK_RV rv;
    struct tmc_object tmcObj;
    tmcObj.isPriv = CK_TRUE;
    tmcObj.pValue = NULL_PTR;
    tmcObj.pKeyParam = NULL_PTR;
    tmcObj.objClass = CKO_SECRET_KEY;

    rv = get_slot_from_session(hSession, &slot);
    if (rv != CKR_OK) {
        return rv;
    }
    card = slot->p11card->card;
    rv = attr_find(pTemplate, ulCount, CKA_KEY_TYPE, &tmcObj.keyType, NULL);
    if (rv != CKR_OK) {
        goto err;
    }
    switch (tmcObj.keyType) {
        case CKK_DES:
            keyLength = 8;
            break;
        case CKK_DES2:
            keyLength = 16;
            break;
        case CKK_DES3:
            keyLength = 24;
            break;
        case CKK_AES:
            keyLength = 16;
            break;
        case CKK_SM1:
            keyLength = 16;
	        break;
        case CKK_SM4:
            keyLength = 16;
            break;
            
        default:
            rv = CKR_ATTRIBUTE_VALUE_INVALID;
            return rv;
    }

    //查找Private
    rv = attr_find(pTemplate, ulCount, CKA_PRIVATE, &tmcObj.isPriv, NULL);
    if (rv != CKR_TEMPLATE_INCOMPLETE && rv != CKR_OK) {
        return rv;
    }

    rv = attr_find(pTemplate, ulCount, CKA_TOKEN, &isToken, NULL);
    if (rv == CKR_TEMPLATE_INCOMPLETE) {
        isAddTokenAttr = CK_TRUE;
    }

    //save the key value
    rv = attr_find_ptr(pTemplate, ulCount, CKA_VALUE, (void **)&tmcObj.pValue, &tmcObj.valueLen);
    if (rv != CKR_OK) {
        goto err;
    }

    if (tmcObj.keyType == CKK_AES) {
        if ((tmcObj.valueLen != 16)&&(tmcObj.valueLen != 24)&&(tmcObj.valueLen != 32)) {
            rv = CKR_DATA_LEN_RANGE;
            goto err;
        }
    }
    else {
        if (tmcObj.valueLen != keyLength) {
            rv = CKR_DATA_LEN_RANGE;
            goto err;
        }
    }

    //新建对象
    obj = (struct tmc_pkcs11_object *) calloc(1,sizeof(struct tmc_pkcs11_object));
    if (obj == NULL) {
        rv = CKR_HOST_MEMORY;
        goto err;
    }
    if (0 != list_init(&obj->attrs)) {
        rv = CKR_HOST_MEMORY;
        goto err;
    }
    list_attributes_seeker(&obj->attrs,attribute_list_seeker);

    //在SDK内保存对象属性(不包含密钥值),session对象的值加密后再添加
    rv = attr_storage(CK_TRUE,pTemplate,ulCount,&obj->attrs,&tmcObj.attrsLen);
    if (rv != CKR_OK)
        goto err;

    if (isAddTokenAttr) {
        rv = list_append(&obj->attrs,&gAttrToken[(u8)isToken]);
        if (rv < 0) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }
        tmcObj.attrsLen += (CK_ULONG)(SIZE_CKA_TYPE  + SIZE_CK_ULONG + sizeof(CK_BBOOL));
    }

    if (isToken) {
        rv = tmc_create_token_object(card,obj,&tmcObj);
        if (rv != CKR_OK) {
            goto err;
        }
    }
    else {
        //SE加密session密钥
        encKeyLen = tmcObj.valueLen + ENC_KEY_BLOCK_SIZE;
        encKeyValue = calloc(1,encKeyLen);
        if (encKeyValue == NULL) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }
        rv = card->ops->enc_key(card,tmcObj.pValue,tmcObj.valueLen,encKeyValue,&encKeyLen);
        if (rv != CKR_OK) {
            goto err;
        }

        attr = calloc(1,sizeof(CK_ATTRIBUTE));
	    if (attr == NULL) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }
        attr->type = CKA_VALUE;
        attr->ulValueLen = pTemplate->ulValueLen;
        attr->pValue = encKeyValue;

        obj->fid = 0xFFFF;
        obj->hSession = hSession;

        if (0 > list_append(&obj->attrs,attr)) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }
    }


    obj->ops = &secret_ops;
    tmc_add_object(slot,obj,phObject);

    return CKR_OK;

    err:
    if (encKeyValue != NULL_PTR) {
        free(encKeyValue);
    }

    if (attr != NULL_PTR) {
        free(attr);
    }

    if (obj) {
        tmc_delete_object_attrs(obj);
        list_delete(&slot->objects,obj);
        free(obj);
    }
    return rv;
}
static CK_RV
tmc_create_cert_data_object(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                         CK_OBJECT_HANDLE_PTR phObject) {
    struct tmc_pkcs11_slot *slot;
    struct tmc_card *card;
    struct tmc_pkcs11_object *obj = NULL_PTR;
    CK_BBOOL isToken = CK_FALSE,isAddTokenAttr = CK_FALSE;
    CK_ULONG attrsLen = 0;
    CK_RV rv;
    struct tmc_object tmcObj;
    tmcObj.isPriv = CK_TRUE;
    tmcObj.pValue = NULL_PTR;
    tmcObj.pKeyParam = NULL_PTR;

    rv = get_slot_from_session(hSession, &slot);
    if (rv != CKR_OK) {
        return rv;
    }
    card = slot->p11card->card;
    rv = attr_find(pTemplate, ulCount, CKA_CLASS, &tmcObj.objClass, NULL);
    if (rv != CKR_OK) {
        return rv;
    }

    rv = attr_find(pTemplate, ulCount, CKA_TOKEN, &isToken, NULL);
    if (rv == CKR_TEMPLATE_INCOMPLETE) {
        isAddTokenAttr = CK_TRUE;
    }

    //查找Private
    rv = attr_find(pTemplate, ulCount, CKA_PRIVATE, &tmcObj.isPriv, NULL);
    if (rv != CKR_OK && rv != CKR_TEMPLATE_INCOMPLETE) {
        return rv;
    }

    //新建对象
    obj = (struct tmc_pkcs11_object *) calloc(1,sizeof *obj);
    if (obj == NULL) {
        rv = CKR_HOST_MEMORY;
        goto err;
    }
    if (0 != list_init(&obj->attrs)) {
        rv = CKR_HOST_MEMORY;
        goto err;
    }
    list_attributes_seeker(&obj->attrs,attribute_list_seeker);
    //存储证书和数据对象属性时，CK_VALUE属性也需要存储在SDK上
    rv = attr_storage(CK_FALSE,pTemplate,ulCount,&obj->attrs,&tmcObj.attrsLen);
    if (rv != CKR_OK) {
        goto err;
    }

    if (isAddTokenAttr) {
        rv = list_append(&obj->attrs,&gAttrToken[(u8)isToken]);
        if (rv < 0) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }
        tmcObj.attrsLen += (CK_ULONG)(SIZE_CKA_TYPE  + SIZE_CK_ULONG + sizeof(CK_BBOOL));
    }

    if (isToken) {
        rv = attr_find_ptr(pTemplate,ulCount,CKA_VALUE, (void **)&tmcObj.pValue, &tmcObj.valueLen);
        if (rv != CKR_OK) {
            goto err;
        }
        rv = tmc_create_token_object(card,obj,&tmcObj);
        if (rv != CKR_OK) {
            goto err;
        }
    }
    else {
        obj->fid = (unsigned short) 0xFFFF;
        //session类型需要保存句柄
        obj->hSession = hSession;
    }

    obj->ops = &data_cert_ops;

    tmc_add_object(slot,obj,phObject);

    return CKR_OK;

    err:
    if (obj) {

        tmc_delete_object_attrs(obj);
        list_delete(&slot->objects,obj);
        free(obj);
    }
    return rv;
}
static CK_RV
tmc_create_object(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                  CK_OBJECT_HANDLE_PTR phObject) {
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_slot *slot;
    CK_OBJECT_CLASS _class;
    CK_RV rv;

    rv = get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    //对象数量检查
    slot = session->slot;
    if (list_size(&slot->objects) == MAX_OBJECTS) {
        return CKR_HOST_MEMORY;
    }

    rv = attr_find(pTemplate, ulCount, CKA_CLASS, &_class, NULL);
    if (rv != CKR_OK)
        return rv;

    switch (_class) {
        case CKO_PUBLIC_KEY:
            rv = tmc_create_public_object(hSession, pTemplate, ulCount,phObject);
        break;
        case CKO_PRIVATE_KEY:
            rv = tmc_create_private_object(hSession, pTemplate, ulCount,phObject);
        break;
        case CKO_CERTIFICATE:
        case CKO_DATA:
            rv = tmc_create_cert_data_object(hSession, pTemplate, ulCount,phObject);
            break;
        case CKO_SECRET_KEY:
            rv = tmc_create_secret_object(hSession, pTemplate, ulCount,phObject);
        break;
        default:
            return CKR_ATTRIBUTE_TYPE_INVALID;

    }

    return rv;
}

static
CK_RV
tmc_get_token_object(struct tmc_pkcs11_slot* slot) {
	struct tmc_card *card;
	struct tmc_pkcs11_object *obj;
	struct tmc_pkcs11_session *session;

	CK_RV rv;
	CK_BYTE byte,bit;
	uint16_t objFID;
	CK_ULONG attrLen,tmp;
	CK_ATTRIBUTE_PTR attribute,attr_value = NULL_PTR;
	CK_ATTRIBUTE_TYPE _class = CKA_CLASS;
	CK_OBJECT_CLASS class_type;

	//rv = get_session(hSession, &session);
	card = slot->p11card->card;

	//read manageFile
	rv = card->ops->read_binary_sfi(card,card->manage_fid,(uint32_t)0x0,0x10,g_manageFile);
	if (rv != CKR_OK) {
		return rv;
	}

	//find vaild file in manage file 
	for (uint32_t i = 0; i<0x10;i++) {
		byte = g_manageFile[i];
		for (uint8_t j = 0; j < 8; j++) {
			bit = (CK_BYTE)(7-j);
			if ((byte>>bit) & 0x01) {
				objFID = (uint16_t)( (i*8 + (7-bit)) | 0xEF00);
				//read file attribute 
				attrLen = sizeof(g_attrArr);
				rv = card->ops->read_object(card,objFID,SE_OBJ_FLAG_ATTR,g_attrArr,&attrLen);
				if (rv == CKR_OBJECT_HANDLE_INVALID) {
					g_manageFile[i] &= (CK_BYTE)(~(1 << bit));//if File not exist, then clear the bit in manageFile
					card->ops->update_binary_sfi(card,card->manage_fid,0x0,g_manageFile,(uint32_t)0x10);
					continue;
				}

				obj = (struct tmc_pkcs11_object *) calloc(1,sizeof(struct tmc_pkcs11_object));
				if (!obj) {
					rv = CKR_HOST_MEMORY;
					goto err;
				}
				if (0 != list_init(&obj->attrs)) {
					rv = CKR_HOST_MEMORY;
					goto err;
				}
				list_attributes_seeker(&obj->attrs,attribute_list_seeker);

				rv = array_to_attr_list(g_attrArr,attrLen,obj);
				if (rv != CKR_OK)
					goto err;

				attribute = list_seek(&obj->attrs, &_class);
				if(!attribute)
					return CKR_ATTRIBUTE_TYPE_INVALID;

				class_type = *(CK_OBJECT_CLASS *)attribute->pValue;

				//ensure relevant file is exist
				if ((class_type == CKO_PUBLIC_KEY)||(class_type== CKO_PRIVATE_KEY)) {
					if (class_type == CKO_PUBLIC_KEY) {
						//ensure the private key is exist
						rv = card->ops->select_fid(card, objFID+1);
					}
					else {
						//ensure the public key is exist
						rv = card->ops->select_fid(card, objFID-1);
					}
					if (rv == CKR_OBJECT_HANDLE_INVALID) {
						g_manageFile[i] &= (CK_BYTE)(~(1 << bit));//if relevant file not exist, then clear the file in manageFile
						card->ops->update_binary_sfi(card,card->manage_fid,0x0,g_manageFile,(uint32_t)0x10);
						free(obj);
						continue;
					}
				}

				if ((class_type == CKO_DATA) || (class_type == CKO_CERTIFICATE)) {
					//read the value if the file is CKO_DATA & CKO_CERTIFICATE 
					rv = card->ops->read_object(card,objFID,SE_OBJ_FLAG_VALUE,NULL_PTR,&attrLen);
					if (rv == CKR_USER_NOT_LOGGED_IN || rv == CKR_VENDOR_DEFINED) {
						switch (class_type)
						{
							case CKO_CERTIFICATE:
							case CKO_DATA:
								obj->ops = &data_cert_ops;
								break;
							default:
								return CKR_FUNCTION_FAILED;
						}
						obj->fid = objFID;
						tmc_add_object(slot,obj,&tmp);
						continue;
					}
					else if (rv != CKR_OK) {
						goto err;
					}

					attr_value = calloc(1,sizeof(CK_ATTRIBUTE));
					if (!attr_value) {
						rv = CKR_HOST_MEMORY;
						goto err;
					}
					attr_value->type = CKA_VALUE;
					attr_value->pValue = calloc(1,attrLen);

					attr_value->ulValueLen = attrLen;
					rv = card->ops->read_object(card,objFID,SE_OBJ_FLAG_VALUE,attr_value->pValue,&attrLen);
					if (rv != CKR_OK) {
						goto err;
					}

					if (0 > list_append(&obj->attrs,attr_value)) {
						rv = CKR_HOST_MEMORY;
						goto err;
					}
				}
				//add the object to objectlists
				switch (class_type)
				{
					case CKO_PUBLIC_KEY:
						obj->ops = &pub_ops;
						break;
					case CKO_PRIVATE_KEY:
						obj->ops = &priv_ops;
						break;
					case CKO_SECRET_KEY:
						obj->ops = &secret_ops;
						break;
					case CKO_CERTIFICATE:
					case CKO_DATA:
						obj->ops = &data_cert_ops;
						break;
					default:
						return CKR_FUNCTION_FAILED;
				}
				obj->fid = objFID;
				tmc_add_object(slot,obj,&tmp);
			}
		}
	}

	return CKR_OK;

	err:
	if (attr_value != NULL_PTR) {
		free(attr_value->pValue);
		free(attr_value);
	}

	//TBD: 有可能在读了n个对象后出错,应回收整个对象列表,回收已有的对象属性表.
	free(obj);
	return rv;
}

static CK_RV
tmc_destroy_object(struct tmc_pkcs11_session *session, void *object) {
    struct tmc_pkcs11_object *obj = (struct tmc_pkcs11_object *)object;
    struct tmc_card *card;
    CK_BBOOL is_token;
    CK_ULONG keyType;
    CK_ATTRIBUTE token_attribure = {CKA_TOKEN, &is_token, sizeof(is_token)};
    CK_ATTRIBUTE key_type = {CKA_KEY_TYPE, &keyType, sizeof(keyType)};

    CK_RV rv = CKR_OK;

    card = session->slot->p11card->card;

    obj->ops->get_attribute(session, obj, &token_attribure);

    //token 对象需在SE上删除
    if (is_token == TRUE) {
        rv = card->ops->delete_file(card,obj->fid);
        if (rv != CKR_OK)
            return  rv;
        rv = tmc_set_object_state(obj->fid,CK_TRUE);
        rv = card->ops->update_binary_sfi(card,card->manage_fid,0x0,g_manageFile,(uint32_t)0x10);
    }

    if (obj) {
    	tmc_delete_object_attrs(obj);
    	list_delete(&session->slot->objects, obj);
    	free(obj);
    }
    
    return rv;
}
CK_RV tmc_init_pin(struct tmc_pkcs11_slot * slot,
                   CK_UTF8CHAR_PTR pin, CK_ULONG pLen){
    struct tmc_card *card;
    card = slot->p11card->card;
    struct tmc_int_fw_data* dat;
    CK_RV rv;

    rv = card->ops->change_pin(card, CKU_USER, pin, pLen);
    if(rv == CKR_USER_PIN_NOT_INITIALIZED) {
        rv = card->ops->write_pin(card, CKU_USER, 3, pin, pLen);
        if(rv == SC_SUCCESS)
        {
            dat = malloc(sizeof(struct tmc_int_fw_data));
            slot->token_info.flags |= CKF_USER_PIN_INITIALIZED;
            dat->pin = TRUE;
            slot->fw_data = dat;
        }
    }

    return rv;
}

CK_RV tmc_verify_pin(struct tmc_pkcs11_slot * slot,
                  CK_UTF8CHAR_PTR pin, CK_ULONG pLen){
    struct tmc_card *card;
    card = slot->p11card->card;
    //int * retryLeft = (int *)malloc(sizeof(int));
    CK_RV rv;
    rv = card->ops->verify_pin(card, CKU_USER, pin, pLen);
    if(rv != SC_SUCCESS)
        slot->token_info.flags |= CKF_USER_PIN_COUNT_LOW;
    else
        slot->token_info.flags &= ~CKF_USER_PIN_COUNT_LOW;
    //if(*retryLeft == 1)
    //    slot->token_info.flags |= CKF_USER_PIN_FINAL_TRY;
    //else if(*retryLeft == 0)
    //    slot->token_info.flags |= CKF_USER_PIN_LOCKED;
    return rv;
}
static CK_RV
tmc_gen_key(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
            CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
            CK_OBJECT_HANDLE_PTR phObject) {
    CK_RV  rv;
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_slot *slot;
    struct tmc_card *card;
    struct tmc_pkcs11_object *obj;
    CK_ATTRIBUTE_PTR attrTemp[ulCount];
    CK_OBJECT_CLASS _class;
    CK_BBOOL _token = CK_FALSE,isKey = CK_TRUE,isCreateKey = CK_FALSE;
    CK_BBOOL _private = CK_TRUE;
    CK_KEY_TYPE keyType,_keytype;
    uint8_t *encKey = NULL_PTR;
    CK_ATTRIBUTE_PTR attr = NULL_PTR;
    CK_ULONG  keyAttrLen,keyValLen;

    rv = get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    slot = session->slot;
    if (list_size(&slot->objects) == MAX_OBJECTS) {
        return CKR_HOST_MEMORY;
    }

    //检查机制类型.
    switch (pMechanism->mechanism) {
        case CKM_AES_KEY_GEN:
            keyType = CKK_AES;
            keyValLen = 16;
            break;
        case CKM_DES2_KEY_GEN:
            keyType = CKK_DES2;
            keyValLen = 16;
            break;
        case CKM_DES3_KEY_GEN:
            keyType = CKK_DES3;
            keyValLen = 24;
            break;
        case CKM_SM4_128_KEY_GEN:
            keyType = CKK_SM4;
            keyValLen = 16;
            break;
        default:
            return CKR_MECHANISM_INVALID;
    }
    //属性模板
    if (pTemplate != NULL_PTR) {

        rv = attr_find(pTemplate, ulCount, CKA_CLASS, &_class, NULL);
        if (rv != CKR_OK) {
            return rv;
        }
        if (_class != CKO_SECRET_KEY) {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

    } else {
        CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
        CK_BBOOL true = CK_TRUE;
        ulCount = 4UL;
        CK_ATTRIBUTE pTemplate[] = {
                {CKA_CLASS, &keyClass, sizeof(keyClass)},
                {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                {CKA_TOKEN, &true, sizeof(true)},
                {CKA_VALUE_LEN, &keyValLen, keyValLen},
        };
    }

    rv= tmc_lock(slot->p11card->card);
    if (rv != CKR_OK) {
        return rv;
    }

    //查找card
    card = session->slot->p11card->card;
    if (card == NULL_PTR) {
        return CKR_TOKEN_NOT_PRESENT;
    }

    //新建对象
    obj = (struct tmc_pkcs11_object *) calloc(1,sizeof *obj);
    if (obj == NULL) {
        rv = CKR_HOST_MEMORY;
        goto err;
    }
    if (0 != list_init(&obj->attrs)) {
        rv = CKR_HOST_MEMORY;
        goto err;
    }
    list_attributes_seeker(&obj->attrs,attribute_list_seeker);

    //在SDK内保存对象属性
    rv = attr_storage(isKey,pTemplate,ulCount,&obj->attrs,&keyAttrLen);
    if (rv != CKR_OK)
        goto err;

    rv = attr_find(pTemplate, ulCount, CKA_TOKEN, &_token, NULL);
    if (rv == CKR_TEMPLATE_INCOMPLETE) {
        rv = add_new_attribute(obj,CKA_TOKEN,(CK_BBOOL*)&_token,&keyAttrLen);
        if (rv != CKR_OK) {
            goto err;
        }
    }

    rv = attr_find(pTemplate, ulCount, CKA_PRIVATE, &_private, NULL);
    if (rv == CKR_TEMPLATE_INCOMPLETE) {
        rv = add_new_attribute(obj,CKA_TOKEN,(CK_BBOOL*)&_private,&keyAttrLen);
        if (rv != CKR_OK) {
            goto err;
        }
    }
    rv = attr_find(pTemplate, ulCount, CKA_KEY_TYPE, &_keytype, NULL);
    if (rv == CKR_OK) {
        if (_keytype != keyType) {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }
    else if (rv == CKR_TEMPLATE_INCOMPLETE) {
        rv = add_new_attribute(obj,CKA_KEY_TYPE,(CK_ULONG *)&_keytype,&keyAttrLen);
        if (rv != CKR_OK) {
            goto err;
        }
    }

    if (_token) {
        //查找SE上空闲的对象FID.
        rv = card->ops->read_binary_sfi(card,card->manage_fid,(uint32_t)0x0,0x10,g_manageFile);
        if (rv != CKR_OK) {
            return rv;
        }

        rv = tmc_get_free_object(card,&obj->fid);
        if (rv != CKR_OK) {
            goto err;
        }
        //创建对象文件.

        rv = card->ops->create_object(card,obj->fid,CKO_SECRET_KEY,(uint8_t)_private,keyAttrLen+32,keyValLen);
        if (rv != CKR_OK) {
            goto err;
        }
        isCreateKey = CK_TRUE;
        //在SE上生成密钥对象.
        rv = card->ops->generate_key(card,pMechanism->mechanism,keyValLen,obj->fid);
        if (rv != CKR_OK) {
            goto err;
        }
        //更新管理文件，将对象文件的占用情况更改为"占用".
        rv = tmc_set_object_state(obj->fid,CK_FALSE);
        rv = card->ops->update_binary_sfi(card,card->manage_fid,0x0,g_manageFile,(uint32_t)0x10);
        if (rv != CKR_OK) {
            goto err;
        }

    } else {
        //在SE上生成密钥对象,将返回的密文密钥值.
        encKey = calloc(1,keyValLen);
        if (encKey == NULL) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }
        rv = card->ops->generate_key_ex(card,pMechanism->mechanism,keyValLen,encKey,&keyValLen);
        if (rv != CKR_OK) {
            goto err;
        }
        attr->type = CKA_VALUE;
        attr->ulValueLen = keyValLen;
        attr->pValue = encKey;
        if (0 > list_append(&obj->attrs,attr)) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }
        obj->fid = (unsigned short) 0xFFFF;
        obj->hSession = hSession;
    }


    obj->ops = &secret_ops;
    tmc_add_object(slot,obj,phObject);



    return CKR_OK;

    err:
    if (attr) {
        free(attr);
    }
    if (encKey) {
        free(encKey);

    }
    if (isCreateKey) {
        card->ops->delete_file(card,obj->fid);
    }
    if (obj != NULL_PTR) {
        list_destroy(&obj->attrs);
        free(obj);
        list_delete(&session->slot->objects,obj);
    }

    tmc_unlock(slot->p11card->card);
    return rv;
}

static CK_RV
tmc_gen_keypair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                CK_ATTRIBUTE_PTR pPubTpl, CK_ULONG ulPubCnt,
                CK_ATTRIBUTE_PTR pPrivTpl, CK_ULONG ulPrivCnt,
                CK_OBJECT_HANDLE_PTR phPubKey, CK_OBJECT_HANDLE_PTR phPrivKey) {

    CK_RV rv = CKR_OK;
    struct tmc_pkcs11_session *session;
    struct tmc_pkcs11_slot *slot;
    struct tmc_card *card;
    struct tmc_pkcs11_object *privObj = NULL, *pubObj = NULL;
    CK_ULONG keybits = 0;
    uint16_t pubFID = 0xFFFF,priFID = 0xFFFF;
    CK_ULONG pubKeyLen = 0,privKeyLen = 0, ParamLen = 0;
    CK_BYTE_PTR pubKeyValue = NULL_PTR,privKeyValue = NULL_PTR;
    CK_ATTRIBUTE_PTR pPubVal = NULL_PTR,pPriVal = NULL_PTR;
    CK_BBOOL isToken = CK_TRUE, isKey = CK_TRUE,isPriv = CK_TRUE;
    CK_BYTE_PTR pParam = NULL_PTR,pTemp = NULL_PTR;
    CK_ULONG pubAttrLen,privAttrLen,rsaKeyType = RSA_KEY_TYPE_CRT;
    CK_KEY_TYPE keyType;
    CK_OBJECT_CLASS pub_type,pri_type;
    CK_BYTE objFileFlag = 0;

    rv = get_session(hSession, &session);
    if (rv != CKR_OK) {
        return rv;
    }

    slot = session->slot;
    //确保可以再生成两个密钥
    if (list_size(&slot->objects) >= (MAX_OBJECTS-1)) {
        return CKR_HOST_MEMORY;
    }

    card = slot->p11card->card;

    switch (pMechanism->mechanism) {
        case CKM_RSA_PKCS_KEY_PAIR_GEN:
            rv = attr_find(pPubTpl, ulPubCnt, CKA_MODULUS_BITS, &keybits, NULL);
            if (rv != CKR_OK) {
                return rv;
            }
            //key type.
            keyType = CKK_RSA;

            //获取公私钥长度.
            pubKeyLen = (CK_ULONG)(keybits/8);
            privKeyLen = (CK_ULONG)((keybits/8/2)*5);//ND模式

            break;
        case CKM_SM2_KEY_PAIR_GEN:

            //key type.
            rv = attr_find2(pPrivTpl,ulPrivCnt,pPubTpl,ulPubCnt,CKA_KEY_TYPE,&keyType,NULL);
            keyType = CKK_SM2;

            //获取公私钥长度.
            pubKeyLen = (CK_ULONG)64;
            privKeyLen = (CK_ULONG)32;
            keybits = 256;

            break;
        case CKM_EC_KEY_PAIR_GEN:
            keyType = CKK_EC;

            rv = attr_find_ptr(pPubTpl, ulPubCnt, CKA_EC_PARAMS, (void **)&pTemp, NULL);
            if (rv != CKR_OK) {
                rv = attr_find_ptr(pPrivTpl, ulPrivCnt, CKA_EC_PARAMS, (void **)&pTemp, NULL);
                if (rv != CKR_OK)
                    return CKR_TEMPLATE_INCOMPLETE;
            }

            //key type.
            keyType = CKK_EC;

            rv = tmc_find_alloc_ec_param(pTemp,&pParam,&ParamLen,&keybits);
            if (rv != CKR_OK) {
                return rv;
            }

            if (keybits%8) {
                pubKeyLen = (uint32_t)(keybits/4 + 1 + 1);
                privKeyLen = (uint32_t)(keybits/8 + 1);
            }
            else {
                pubKeyLen = (uint32_t)(keybits/4 + 1);
                privKeyLen = (uint32_t)(keybits/8);
            }

            pubKeyLen += ParamLen;
            privKeyLen += ParamLen;
            break;
        default:
            return CKR_MECHANISM_INVALID;
    }

    privObj = (struct tmc_pkcs11_object *) calloc(1,sizeof(*privObj));
    pubObj = (struct tmc_pkcs11_object *) calloc(1,sizeof(*pubObj));

    if ((privObj == NULL) || (pubObj == NULL)) {
        rv = CKR_HOST_MEMORY;
        goto err;
    }

    //初始化属性列表
    if (0 != list_init(&pubObj->attrs) || 0 != list_init(&privObj->attrs)) {
        rv = CKR_HOST_MEMORY;
        goto err;
    }

    list_attributes_seeker(&pubObj->attrs,attribute_list_seeker);
    list_attributes_seeker(&privObj->attrs,attribute_list_seeker);

    //在SDK内保存对象属性
    rv = attr_storage(isKey,pPubTpl,ulPubCnt,&pubObj->attrs,&pubAttrLen);
    if (rv != CKR_OK) {
        goto err;
    }
    rv = attr_storage(isKey,pPrivTpl,ulPrivCnt,&privObj->attrs,&privAttrLen);
    if (rv != CKR_OK) {
        goto err;
    }

    //arrtibute - CKA_TOKEN.
    if (attr_find(pPubTpl,ulPubCnt,CKA_TOKEN,&isToken,NULL) != CKR_OK) {
        rv = add_new_attribute(pubObj,CKA_TOKEN,(CK_BBOOL*)&isToken,&pubAttrLen);
        if (rv != CKR_OK) {
            goto err;
        }
    }
    if (attr_find(pPrivTpl,ulPrivCnt,CKA_TOKEN,&isToken,NULL) != CKR_OK) {
        rv = add_new_attribute(privObj,CKA_TOKEN,(CK_BBOOL*)&isToken,&privAttrLen);
        if (rv != CKR_OK) {
            goto err;
        }
    }
	
    //arrtibute - CKA_PRIVATE.    
    if (attr_find(pPrivTpl,ulPrivCnt,CKA_PRIVATE,&isPriv,NULL) != CKR_OK) {
        rv = add_new_attribute(privObj,CKA_PRIVATE,(CK_BBOOL *)&isPriv,&privAttrLen);
        if (rv != CKR_OK) {
            goto err;
        }
    }

    //arrtibute - CKA_MODULUS_BITS.    
    if (attr_find(pPrivTpl,ulPrivCnt,CKA_MODULUS_BITS,&keybits,NULL) != CKR_OK) {
        rv = add_new_attribute(privObj,CKA_MODULUS_BITS,(CK_ULONG *)&keybits,&privAttrLen);
        if (rv != CKR_OK) {
            goto err;
        }
    }

    //arrtibute - CKA_KEY_TYPE.
    if (attr_find(pPubTpl,ulPubCnt,CKA_KEY_TYPE,&keyType,NULL) != CKR_OK) {
        rv = add_new_attribute(pubObj, CKA_KEY_TYPE, (CK_ULONG *) &keyType, &pubAttrLen);
        if (rv != CKR_OK) {
            goto err;
        }
    }
    if (attr_find(pPrivTpl,ulPrivCnt,CKA_KEY_TYPE,&keyType,NULL) != CKR_OK) {
        rv = add_new_attribute(privObj,CKA_KEY_TYPE,(CK_ULONG *)&keyType,&privAttrLen);
        if (rv != CKR_OK) {
            goto err;
        }
    }
    //arrtibute - CKA_CLASS.
    if(attr_find(pPubTpl,ulPubCnt,CKA_CLASS,&pub_type,NULL) != CKR_OK)
    {
        pub_type = CKO_PUBLIC_KEY;
        rv = add_new_attribute(pubObj,CKA_CLASS,(CK_ULONG *)&pub_type,&pubAttrLen);
        if (rv != CKR_OK) {
            goto err;
        }
    }
    if(attr_find(pPrivTpl,ulPrivCnt,CKA_CLASS,&pri_type,NULL) != CKR_OK)
    {
        pri_type = CKO_PRIVATE_KEY;
        rv = add_new_attribute(privObj,CKA_CLASS,(CK_ULONG *)&pri_type,&privAttrLen);
        if (rv != CKR_OK) {
            goto err;
        }
    }


    //锁定
    rv = tmc_lock(card);
    if (rv != CKR_OK)
        goto err;
    //SE上生成密钥对
    if (isToken) {

        //找到一个空闲的FID
        rv = card->ops->read_binary_sfi(card,card->manage_fid,(uint32_t)0x0,0x10,g_manageFile);
        if (rv != CKR_OK) {
            return rv;
        }

        rv = tmc_get_free_object(card,&pubFID);
        if (rv != CKR_OK) {
            goto err;
        }
        rv = tmc_set_object_state(pubFID,CK_FALSE);

        //创建公钥对象文件
        rv = card->ops->create_object(card,pubFID,CKO_PUBLIC_KEY, 0,
                                      pubAttrLen+SE_OBJ_SIZE_RESERVE,pubKeyLen);
        if (rv != CKR_OK) {
            goto err;
        }
        objFileFlag = 0x01;//public object file is created.
        rv = tmc_get_free_object(card,&priFID);
        if (rv != CKR_OK) {
            goto err;
        }
        rv = tmc_set_object_state(priFID,CK_FALSE);

        //创建私钥对象文件：私钥为CRT模式.
        rv = card->ops->create_object(card,priFID,CKO_PRIVATE_KEY,(u8)isPriv,
                                      privAttrLen+SE_OBJ_SIZE_RESERVE,privKeyLen);
        if (rv != CKR_OK) {
            goto err;
        }
        objFileFlag = 0x02;//private object file is created.

        //生成密钥对,rsaKetType参数在其他机制下不使用.
        rv = card->ops->generate_keypair(card,pMechanism->mechanism,keybits,rsaKeyType,pParam,ParamLen,pubFID,priFID);
        if (rv != CKR_OK) {
            goto err;
        }

        //保存属性
        rv = attribute_list_to_array(&pubObj->attrs,pubAttrLen);
        if (rv != CKR_OK) {
            goto err;
        }
        rv = card->ops->update_object(card,pubFID,SE_OBJ_FLAG_ATTR,0x0,pubAttrLen,g_attrArr);
        if (rv != CKR_OK) {
            goto err;
        }
        rv = attribute_list_to_array(&privObj->attrs,privAttrLen);
        if (rv != CKR_OK) {
            goto err;
        }
        rv = card->ops->update_object(card,priFID,SE_OBJ_FLAG_ATTR,0x0,privAttrLen,g_attrArr);
        if (rv != CKR_OK) {
            goto err;
        }

        //更新管理文件，将对象文件标记为被占用
        rv = card->ops->update_binary_sfi(card,card->manage_fid,0x0,g_manageFile,(uint32_t)0x10);
        if (rv != CKR_OK) {
            goto err;
        }

        //object FID
        pubObj->fid = pubFID;
        privObj->fid = priFID;

        //rsa key type
        pubObj->keyType = rsaKeyType;
        privObj->keyType = rsaKeyType;

    } else {

        pubKeyValue = calloc(1,pubKeyLen);
        privKeyValue = calloc(1,privKeyLen);

        pPubVal = calloc(1,sizeof(CK_ATTRIBUTE));
        pPriVal = calloc(1,sizeof(CK_ATTRIBUTE));

        rsaKeyType = RSA_KEY_TYPE_ND;

        //获取公私钥值.
        rv = card->ops->generate_keypair_ex(card, pMechanism->mechanism,keybits, rsaKeyType,pParam,ParamLen,
                                            pubKeyValue,&pubKeyLen, privKeyValue,&privKeyLen);
        if (rv != CKR_OK) {
            goto err;
        }
        //保存属性value.
        pPubVal->type = CKA_MODULUS;
        pPubVal->ulValueLen = pubKeyLen;
        pPubVal->pValue = privKeyValue;
        pPriVal->type = CKA_PRIVATE_EXPONENT;
        pPriVal->ulValueLen = privKeyLen;
        pPriVal->pValue = pubKeyValue;
        if (0 > list_append(&pubObj->attrs,pPubVal)) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }
        if (0> list_append(&privObj->attrs,pPriVal)) {
            rv = CKR_HOST_MEMORY;
            goto err;
        }

        pubObj->keyType = rsaKeyType;
        privObj->keyType = rsaKeyType;

        pubObj->hSession = hSession;
        privObj->hSession = hSession;
    }


    //add object into list
    privObj->ops = &priv_ops;
    pubObj->ops = &pub_ops;

    tmc_add_object(slot,privObj,phPrivKey);
    tmc_add_object(slot,pubObj,phPubKey);


    if (pubKeyValue != NULL_PTR || pubKeyValue != NULL_PTR) {
        free(pubKeyValue);
        free(privKeyValue);
    }
    tmc_unlock(card);
    return CKR_OK;

    err:

    if (objFileFlag == 0x01) {
        tmc_set_object_state(pubFID,TRUE);
        card->ops->delete_file(card,pubFID);
    }

    if (objFileFlag == 0x02) {
        tmc_set_object_state(pubFID,TRUE);
        card->ops->delete_file(card,pubFID);

        tmc_set_object_state(priFID,TRUE);
        card->ops->delete_file(card,priFID);
    }

    if (privObj != NULL) {
        free(privObj);
    }

    if(pubObj != NULL) {
        free(pubObj);
    }

    if (pPubVal) {
        free(pPubVal);
        free(pubKeyValue);
    }

    if(pPriVal)
    {
        free(pPriVal);
        free(privKeyValue);
    }

    tmc_unlock(card);
    return rv;

}

static void
tmc_find_release(tmc_pkcs11_operation_t *operation)
{
    struct tmc_pkcs11_find_operation *fop = (struct tmc_pkcs11_find_operation *)operation;

    if (fop->handles) {
        free(fop->handles);
        fop->handles = NULL;
    }
}

static CK_RV
array_to_list(CK_BYTE_PTR array, CK_ULONG array_len,
        list_t list)
{
    CK_ATTRIBUTE_PTR attr;
    CK_ULONG current_offset = 0;

    while (current_offset < array_len)
    {
        attr = calloc(1, sizeof(CK_ATTRIBUTE));
        if(!attr)
            return CKR_HOST_MEMORY;
        attr->type = *((CK_ULONG_PTR)array);
        array += sizeof(CK_ULONG);
        current_offset += sizeof(CK_ULONG);
        attr->ulValueLen = *((CK_ULONG_PTR)array);
        array += sizeof(CK_ULONG);
        current_offset += sizeof(CK_ULONG);
        attr->pValue = array;
        array += attr->ulValueLen;
        current_offset += attr->ulValueLen;

        list_append(&list, attr);
    }

    return CKR_OK;
}

CK_RV tmc_create_head_object(struct tmc_pkcs11_object ** obj)
{
    struct tmc_pkcs11_object * object;
    object = calloc(1, sizeof *object);
    if(!object)
        return CKR_HOST_MEMORY;
    object->ops = &secret_ops;
    * obj = object;
    return CKR_OK;
}

CK_RV ecdsa_get_sig_length(struct tmc_pkcs11_object *key, CK_ULONG_PTR plength)
{
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE_TYPE type = CKA_EC_PARAMS;
    attr = list_seek(&key->attrs, &type);
    if(!attr)
        return CKR_KEY_TYPE_INCONSISTENT;
    return CKR_OK;
}

#define TAG_BMP_STR 0x30
#define TAG_INT 0x02
#define EC_SIG_HEADER_LEN 0x02

CK_RV transASN1(CK_BYTE_PTR in, CK_BYTE_PTR out, CK_BBOOL isWrap,
        CK_ULONG_PTR psigLength) {
    CK_ULONG sOff = 0;
    CK_ULONG totaLen;
    CK_ULONG tmpOff = 0;
    CK_ULONG sigLen = *psigLength;
    CK_ULONG halfLen = sigLen / 2;
    CK_BYTE tmpBuff[200];

    memset(tmpBuff, 0x00, 128);
    //sOff = 0;
    if (isWrap) {

        //tag BMP
        tmpBuff[sOff++] = (CK_BYTE)TAG_BMP_STR;
        tmpOff = (sOff++);
        //超过127字节的数据预留两个字节表示长度
        if (sigLen > 127) {
            sOff++;
        }
        //tag INT
        tmpBuff[sOff++] = (CK_BYTE)TAG_INT;
        //如果最高bit为1，需要补一个0
        if (in[0] & 0x80) {
            tmpBuff[sOff++] = (CK_BYTE) (halfLen + 1);
            tmpBuff[sOff++] = 0;
            totaLen = EC_SIG_HEADER_LEN + halfLen + 1;
        } else {
            tmpBuff[sOff++] = (CK_BYTE) halfLen;
            totaLen = EC_SIG_HEADER_LEN + halfLen;
        }
        memcpy((u8 *) (tmpBuff + sOff), in, halfLen);
        sOff += halfLen;
        //tag INT
        tmpBuff[sOff++] = (CK_BYTE) TAG_INT;
        //如果最高bit为1，需要补一个0
        if (in[halfLen] & 0x80) {
            tmpBuff[sOff++] = (u8) (halfLen + 1);
            tmpBuff[sOff++] = 0;
            totaLen += EC_SIG_HEADER_LEN + halfLen + 1;
        } else {
            tmpBuff[sOff++] = (CK_BYTE) halfLen;
            totaLen += EC_SIG_HEADER_LEN + halfLen;
        }
        memcpy((u8 *) (tmpBuff + sOff), (u8 *) (in + halfLen), halfLen);
        //超过127字节预留两个字节表示长度
        if (sigLen > 127) {
            tmpBuff[tmpOff++] = 0x81;
            tmpBuff[tmpOff++] = (u8) totaLen;
        } else {
            tmpBuff[tmpOff++] = (u8) totaLen;
        }
        sOff += halfLen;
        memcpy(out, tmpBuff, sOff);
        *psigLength = sOff;
    } else {
        if (in[sOff++] != TAG_BMP_STR) {
            return CKR_DATA_INVALID;
        }
        if (in[sOff] == 0x81) {
            sOff++;
            if (!(in[sOff++] & 0x80))
                return CKR_DATA_INVALID;
        } else if (in[sOff] & 0x80) {
            return CKR_DATA_INVALID;
        } else {
            sOff++;
        }

        if (in[sOff++] != TAG_INT) {
            return CKR_DATA_INVALID;
        }
        totaLen = in[sOff++];

        //底层要求R,S传入N的长度，不足补0，多余去0
        if (totaLen > (halfLen + 1)) {
            return CKR_DATA_INVALID;
        }

        if ((totaLen > (halfLen + 1)) && (in[sOff] != 0)) {
            return CKR_DATA_INVALID;
        }

        if (totaLen >= halfLen) {
            sOff += (totaLen - halfLen);
            memcpy((u8 *) tmpBuff, (in + sOff), halfLen);
            sOff += halfLen;
        } else {
            memset(tmpBuff, 0x00, (halfLen - totaLen));
            memcpy((u8 *) (tmpBuff + halfLen - totaLen), (in + sOff), totaLen);
            sOff += totaLen;
        }
        if (in[sOff++] != TAG_INT) {
            return CKR_DATA_INVALID;
        }
        totaLen = in[sOff++];

        if ((totaLen - halfLen) > 1) {
            return CKR_DATA_INVALID;
        }

        if ((totaLen - halfLen) == 1 && in[sOff] != 0) {
            return CKR_DATA_INVALID;
        }
        if (totaLen >= halfLen) {
            sOff += (totaLen - halfLen);
            memcpy((u8 *) (tmpBuff + halfLen), (in + sOff), halfLen);
            sOff += halfLen;
        } else {
            memset(tmpBuff, 0x00, (halfLen - totaLen));
            memcpy((u8 *) (tmpBuff + halfLen * 2 - totaLen), (in + sOff), totaLen);
            sOff += totaLen;
        }
        memcpy(out, tmpBuff, sigLen);

    }

    return CKR_OK;

}

CK_RV tmc_export_pub(struct tmc_pkcs11_session * session,
        struct tmc_pkcs11_object * key, CK_BYTE_PTR * p_pub_value, CK_ULONG_PTR p_pub_len)
{
    struct tmc_card * card;
    CK_BYTE_PTR pub_value = NULL;
    CK_ULONG pub_len= 0;
    struct tmcse_key * uniontmc_key = NULL_PTR;
    CK_RV rv = CKR_OK;

    card = session->slot->p11card->card;

    uniontmc_key = calloc(1, sizeof(struct tmcse_key));
    if(!uniontmc_key)
    {
        rv = CKR_HOST_MEMORY;
        goto out;
    }

    rv = switch_token_session(key, &uniontmc_key);
    if(rv != CKR_OK)
    {
        goto out;
    }

    if(uniontmc_key->isToken)
    {
        rv = card->ops->export_pubkey(card, uniontmc_key->key.fid,
                NULL, &pub_len);
        if(rv != CKR_OK)
        {
            goto out;
        }

        pub_value = calloc(1, pub_len);
        if(!pub_value)
        {
            rv = CKR_HOST_MEMORY;
            goto out;
        }

        rv = card->ops->export_pubkey(card, uniontmc_key->key.fid,
                                      pub_value, &pub_len);
        if(rv != CKR_OK)
        {
            goto out;
        }
    } else {
        pub_value = uniontmc_key->key.value.data;
        pub_len = uniontmc_key->key.value.length;
    }

    *p_pub_len = pub_len;
    *p_pub_value = pub_value;

    out:
    if(uniontmc_key)
        free(uniontmc_key);
    return rv;
}


static struct tmc_pkcs11_object_ops secret_ops = {
        tmc_release,
        tmc_set_attribute,
        tmc_get_attribute,
        tmc_cmp_attribute,
        tmc_destroy_object,
        NULL,
        NULL,
        NULL,
        tmc_decrypt,
        tmc_encrypt,
        NULL,
        NULL,
        NULL,
        NULL

};

static struct tmc_pkcs11_object_ops data_cert_ops = {
        tmc_release,
        tmc_set_attribute,
        tmc_get_attribute,
        tmc_cmp_attribute,
        tmc_destroy_object,
        NULL,
        tmc_sign,
        NULL,
        tmc_decrypt,
        tmc_encrypt,
        NULL,
        NULL,
        tmc_signVerify,
        NULL

};
static struct tmc_pkcs11_object_ops priv_ops = {
        tmc_release,
        tmc_set_attribute,
        tmc_get_attribute,
        tmc_cmp_attribute,
        tmc_destroy_object,
        NULL,
        tmc_sign,
        NULL,
        tmc_asym_decrypt,
        tmc_asym_encrypt,
        tmc_derive,
        NULL,
        tmc_signVerify,
        NULL

};
static struct tmc_pkcs11_object_ops pub_ops = {
        tmc_release,
        tmc_set_attribute,
        tmc_get_attribute,
        tmc_cmp_attribute,
        tmc_destroy_object,
        NULL,
        tmc_sign,
        NULL,
        tmc_asym_decrypt,
        tmc_asym_encrypt,
        NULL,
        NULL,
        tmc_signVerify,
        tmc_export_pub

};
/* Pseudo mechanism for the Find operation */
struct tmc_pkcs11_mechanism_type find_mechanism = {
        0,		/* mech */
        {0,0,0},	/* mech_info */
        0,		/* key_type */
        sizeof(struct tmc_pkcs11_find_operation),	/* obj_size */
        tmc_find_release,				/* release */
        NULL,		/* md_init */
        NULL,		/* md_update */
        NULL,		/* md_final */
        NULL,		/* sign_init */
        NULL,		/* sign_update */
        NULL,		/* sign_final */
        NULL,		/* sign_size */
        NULL,		/* verif_init */
        NULL,		/* verif_update */
        NULL,		/* verif_final */
        NULL,		/* decrypt_init */
        NULL,		/* decrypt */
        NULL,		/* derive */
        NULL,		/* mech_data */
        NULL,		/* free_mech_data */
};


struct tmc_pkcs11_framework_ops framework_tmc = {
        tmc_bind,
        tmc_unbind,
        tmc_create_tokens,
        tmc_release_token,
        tmc_login,//pkcs15_login,
        tmc_logout,//pkcs15_logout,
        tmc_changepin, //pkcs15_change_pin
        tmc_initialize,
        tmc_init_pin,
        tmc_create_object,
        tmc_gen_keypair,
        tmc_gen_key,
        tmc_get_token_object
};

struct tmc_pkcs11_framework_ops *tmc_get_framework_ops(void) {
    return &framework_tmc;
}
