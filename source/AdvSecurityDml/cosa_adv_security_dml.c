/*
 *
 * Copyright 2016 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * SPDX-License-Identifier: Apache-2.0
*/
   
#include "cosa_adv_security_dml.h"

/* Legacy platform includes commented out for JSON-driven RBUS approach */
/* #include "ansc_platform.h" */
#include "cosa_adv_security_internal.h"
#include "cosa_adv_security_webconfig.h"
#include "syslog.h"
/* Legacy ccsp_trace macros replaced by advsec_compat_types.h */
/* #include "ccsp_trace.h" */
#include "msgpack.h"
#include "advsecurity_param.h"
#include "base64.h"
/* Legacy common-library includes commented out for JSON-driven RBUS approach */
/* #include "safec_lib_common.h" */

#define MIN_AGENT_MEMORY_HARD_LIMIT 45
#define MAX_RABID_MACCACHE_SIZE 32768
#define MAX_RABID_DNSCACHE_SIZE 32768

extern COSA_DATAMODEL_AGENT* g_pAdvSecAgent;
extern pthread_mutex_t logMutex;

#ifdef WIFI_DATA_COLLECTION
static char *g_AdvWifiDataCollection = "Adv_WifiDataCollectionRFCEnable";
#endif

static int urlStartsWith(const char *haystack, const char *needle)
{
   if(strncmp(haystack, needle, strlen(needle)) == 0)
       return 0;
   return 1;
}

ANSC_STATUS isValidUrl( char *inputparam )
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;

    if(urlStartsWith(inputparam, "https://"))
    {
        returnStatus = ANSC_STATUS_FAILURE;
    }
    if(strstr(inputparam,";")) // check for possible command injection 
    {
        returnStatus = ANSC_STATUS_FAILURE;
    }
    else if(strstr(inputparam,"&"))
    {
        returnStatus = ANSC_STATUS_FAILURE;
    }
    else if(strstr(inputparam,"|"))
    {
        returnStatus = ANSC_STATUS_FAILURE;
    }
    else if(strstr(inputparam,"'"))
        returnStatus = ANSC_STATUS_FAILURE;

    return returnStatus;
}

/***********************************************************************

 APIs for Object:

	X_RDKCENTRAL-COM_DeviceFingerPrint.

    *  DeviceFingerPrint_GetParamBoolValue
    *  DeviceFingerPrint_SetParamBoolValue
    *  DeviceFingerPrint_GetParamUlongValue
    *  DeviceFingerPrint_SetParamUlongValue
    *  DeviceFingerPrint_GetParamStringValue
    *  DeviceFingerPrint_SetParamStringValue

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        DeviceFingerPrint_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DeviceFingerPrint_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
       return FALSE;

    rc = strcmp_s("Enable", strlen("Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        *pBool = pMyObject->bEnable;
        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DeviceFingerPrint_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DeviceFingerPrint_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("Enable", strlen("Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if(bValue == pMyObject->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaAdvSecInit(pMyObject);
        else
                returnStatus = CosaAdvSecDeInit(pMyObject);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }

        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DeviceFingerPrint_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve Unsigned Long parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned unsigned long value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DeviceFingerPrint_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
       return FALSE;

    rc = strcmp_s("LoggingPeriod", strlen("LoggingPeriod"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        pthread_mutex_lock(&logMutex);
        *puLong = g_pAdvSecAgent->ulLoggingPeriod;
        pthread_mutex_unlock(&logMutex);
        return TRUE;
    }

    rc = strcmp_s("LogLevel", strlen("LogLevel"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
#if !(defined(_COSA_INTEL_XB3_ARM_) || defined(_COSA_BCM_MIPS_))
        *puLong = g_pAdvSecAgent->ulLogLevel;
        return TRUE;
#else
        UNREFERENCED_PARAMETER(puLong);
        return FALSE;
#endif
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DeviceFingerPrint_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       bValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DeviceFingerPrint_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("LoggingPeriod", strlen("LoggingPeriod"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( bValue < ADVSEC_MIN_LOG_TIMEOUT || bValue > ADVSEC_MAX_LOG_TIMEOUT )
        {
            CcspTraceInfo(("%s Values out of range\n", __FUNCTION__));
            return FALSE;
        }

        pthread_mutex_lock(&logMutex);
        if(bValue == g_pAdvSecAgent->ulLoggingPeriod) {
            pthread_mutex_unlock(&logMutex);
            return TRUE;
        }
        pthread_mutex_unlock(&logMutex);

        returnStatus = CosaAdvSecSetLoggingPeriod(bValue);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return FALSE;
        }

        return TRUE;
    }

    rc = strcmp_s("LogLevel", strlen("LogLevel"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
#if !(defined(_COSA_INTEL_XB3_ARM_) || defined(_COSA_BCM_MIPS_))
        if ( bValue < ADVSEC_LogLevel_ERROR || bValue > ADVSEC_LogLevel_VERBOSE )
        {
            CcspTraceInfo(("%s Values Log Level: Out of range\n", __FUNCTION__));
            return FALSE;
        }

        if(bValue == g_pAdvSecAgent->ulLogLevel)
                return TRUE;

        returnStatus = CosaAdvSecSetLogLevel(bValue);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return FALSE;
        }

        return TRUE;
#else
     UNREFERENCED_PARAMETER(bValue);
     UNREFERENCED_PARAMETER(returnStatus);
     return FALSE;
#endif
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        DeviceFingerPrint_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );

    description:

        This function is called to retrieve string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.

**********************************************************************/
ULONG
DeviceFingerPrint_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
       return -1;

    /* check the parameter name and return the corresponding value */
    rc = strcmp_s("EndpointURL", strlen("EndpointURL"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        returnStatus = CosaAdvSecGetCustomURL(pValue, pUlSize);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }
        return 0;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return -1;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        DeviceFingerPrint_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DeviceFingerPrint_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    /* check the parameter name and set the corresponding value */
    rc = strcmp_s("EndpointURL", strlen("EndpointURL"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if(ANSC_STATUS_SUCCESS == isValidUrl(pString))
        {
            returnStatus = CosaAdvSecSetCustomURL(pString);

            if ( returnStatus != ANSC_STATUS_SUCCESS )
            {
                CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
                return FALSE;
            }
            return TRUE;
        }
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AdvancedSecurity_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pString
            );

    description:

        This function is called to set string parameter value; 

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pString
                The updated string value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvancedSecurity_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pString
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;
    /* check the parameter name and set the corresponding value */
    rc = strcmp_s("Data", strlen("Data"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        advsecuritydoc_t *ad = NULL;
        int err;
        char * decodeMsg =NULL;
        int decodeMsgSize =0;
        int size =0;
        BOOL ret_val = TRUE;

        msgpack_zone mempool;
        msgpack_object deserialized;
        msgpack_unpack_return unpack_ret;

        decodeMsgSize = b64_get_decoded_buffer_size(strlen(pString));
        decodeMsg = (char *) AnscAllocateMemory(sizeof(char) * decodeMsgSize);
        size = b64_decode((uint8_t *) pString, strlen(pString),(uint8_t *) decodeMsg );
        CcspTraceInfo(("base64 decoded data contains %d bytes\n",size));

        msgpack_zone_init(&mempool, 2048);
        unpack_ret = msgpack_unpack(decodeMsg, size, NULL, &mempool, &deserialized);
        switch(unpack_ret)
        {
            case MSGPACK_UNPACK_SUCCESS:
                CcspTraceInfo(("MSGPACK_UNPACK_SUCCESS :%d\n",unpack_ret));
                break;
            case MSGPACK_UNPACK_EXTRA_BYTES:
                CcspTraceInfo(("MSGPACK_UNPACK_EXTRA_BYTES :%d\n",unpack_ret));
                break;
            case MSGPACK_UNPACK_CONTINUE:
                CcspTraceInfo(("MSGPACK_UNPACK_CONTINUE :%d\n",unpack_ret));
                break;
            case MSGPACK_UNPACK_PARSE_ERROR:
                CcspTraceError(("MSGPACK_UNPACK_PARSE_ERROR :%d\n",unpack_ret));
                break;
            case MSGPACK_UNPACK_NOMEM_ERROR:
                CcspTraceError(("MSGPACK_UNPACK_NOMEM_ERROR :%d\n",unpack_ret));
            break;
            default:
                CcspTraceError(("Message Pack decode failed with error: %d\n", unpack_ret));
        }
        msgpack_zone_destroy(&mempool);

        CcspTraceInfo(("---------------End of b64 decode--------------\n"));

        if(unpack_ret == MSGPACK_UNPACK_SUCCESS)
        {
            CcspTraceInfo(("Msg unpack success\n"));
            ad = advsecuritydoc_convert(decodeMsg, size);//used to process the incoming msgobject
            err = errno;
            CcspTraceInfo(("errno: %s\n", advsecuritydoc_strerror(err)));

            if(ad != NULL)
            {
                CcspTraceInfo(("ad->subdoc_name is %s\n", ad->subdoc_name));
                CcspTraceInfo(("ad->version is %lu\n", (long)ad->version));
                CcspTraceInfo(("ad->transaction_id %lu\n",(long) ad->transaction_id));
                CcspTraceInfo(("fingerprint_enable:[%d], softflowd_enable[%d], safebrowsing_enable[%d], parental_control_activate[%d], privacy_protection_activate[%d]\n",
                    ad->param->fingerprint_enable,ad->param->softflowd_enable,ad->param->safebrowsing_enable,
                    ad->param->parental_control_activate,ad->param->privacy_protection_activate));

                execData *execDataAdvsec = NULL ;
                execDataAdvsec = (execData*) AnscAllocateMemory (sizeof(execData));

                if ( execDataAdvsec != NULL )
                {
                    rc = memset_s(execDataAdvsec, sizeof(execData), 0, sizeof(execData));
                    ERR_CHK(rc);

                    execDataAdvsec->txid = ad->transaction_id;
                    execDataAdvsec->version = ad->version;
                    execDataAdvsec->numOfEntries = 1;

                    rc = strcpy_s(execDataAdvsec->subdoc_name, sizeof(execDataAdvsec->subdoc_name), ad->subdoc_name);
                    if(rc != EOK)
                    {
                       ERR_CHK(rc);
                       if(execDataAdvsec)
                       {
                           AnscFreeMemory(execDataAdvsec);
                           execDataAdvsec = NULL;
                       }
                       if(decodeMsg)
                       {
                            AnscFreeMemory(decodeMsg);
                            decodeMsg = NULL;
                       }
                       return FALSE;
                    }

                    execDataAdvsec->user_data = (void*) ad;
                    execDataAdvsec->calcTimeout = NULL ;
                    execDataAdvsec->executeBlobRequest = advsec_webconfig_process_request;
                    execDataAdvsec->rollbackFunc = advsec_webconfig_rollback;
                    execDataAdvsec->freeResources = advsec_webconfig_free_resources;
                    PushBlobRequest(execDataAdvsec);
                    CcspTraceInfo(("PushBlobRequest complete\n"));
                }
                else
                {
                    CcspTraceError(("execData AnscAllocateMemory failed\n"));
                    advsecuritydoc_destroy(ad);
                    ret_val = FALSE;
                }
            }
        }
        else
        {
            CcspTraceError(("Failed to unpack megpack\n"));
            ret_val = FALSE;
        }

        if ( decodeMsg )
        {
                AnscFreeMemory (decodeMsg);
                decodeMsg = NULL;
        }
        return ret_val;
    }

    /* CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName)); */
    return FALSE;
}

/***********************************************************************

 APIs for Object:

	X_RDKCENTRAL-COM_AdvancedSecurity.SafeBrowsing.

    *  SafeBrowsing_GetParamBoolValue
    *  SafeBrowsing_SetParamBoolValue
    *  SafeBrowsing_GetParamUlongValue
    *  SafeBrowsing_SetParamUlongValue
    *  SafeBrowsing_GetParamStringValue
    *  SafeBrowsing_Validate
    *  SafeBrowsing_Commit
    *  SafeBrowsing_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        SafeBrowsing_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
SafeBrowsing_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    errno_t rc = -1;
    int ind = -1;
    if(ParamName == NULL)
        return FALSE;
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    rc = strcmp_s("Enable", strlen("Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        *pBool = g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable;
        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        SafeBrowsing_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
SafeBrowsing_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    errno_t rc = -1;
    int ind = -1;

    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("Enable", strlen("Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        if(bValue == g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaAdvSecStartFeatures(ADVSEC_SAFEBROWSING);
        else
                returnStatus = CosaAdvSecStopFeatures(ADVSEC_SAFEBROWSING);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  FALSE;
        }

        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        SafeBrowsing_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      puLong
            );

    description:

        This function is called to retrieve Unsigned Long parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      puLong
                The buffer of returned unsigned long value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
SafeBrowsing_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      puLong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    errno_t rc1 = -1;
    int ind1 = -1;
#if !(defined(_COSA_INTEL_XB3_ARM_) || defined(_COSA_BCM_MIPS_))
    errno_t rc2 = -1, rc3 = -1, rc4 = -1, rc5 = -1;
    int ind2 = -1, ind3 = -1, ind4 = -1, ind5 = -1;
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
#endif
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;

    if(ParamName == NULL)
        return FALSE;

    rc1 = strcmp_s("LookupTimeout", strlen("LookupTimeout"), ParamName, &ind1);
    ERR_CHK(rc1);
    if((rc1 == EOK) && (!ind1))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        *puLong = g_pAdvSecAgent->pAdvSec->pSafeBrows->ulLookupTimeout;
        return TRUE;
    }

    rc1 = strcmp_s("LookupTimeoutExceededCount", strlen("LookupTimeoutExceededCount"), ParamName, &ind1);
    ERR_CHK(rc1);
    if((rc1 == EOK) && (!ind1))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        *puLong = CosaAdvSecGetLookupTimeoutExceededCount();
        return TRUE;
    }

#if !(defined(_COSA_INTEL_XB3_ARM_) || defined(_COSA_BCM_MIPS_))
    rc1 = strcmp_s("Threshold", strlen("Threshold"), ParamName, &ind1);
    ERR_CHK(rc1);
    rc2 = strcmp_s("Timeout", strlen("Timeout"), ParamName, &ind2);
    ERR_CHK(rc2);
    rc3 = strcmp_s("Cachettl", strlen("Cachettl"), ParamName, &ind3);
    ERR_CHK(rc3);
    rc4 = strcmp_s("Ttl", strlen("Ttl"), ParamName, &ind4);
    ERR_CHK(rc4);
    rc5 = strcmp_s("WhitelistMaxEntries", strlen("WhitelistMaxEntries"), ParamName, &ind5);
    ERR_CHK(rc5);

    if( ((rc1 == EOK) && (!ind1)) || ((rc2 == EOK) && (!ind2)) || ((rc3 == EOK) && (!ind3)) ||
        ((rc4 == EOK) && (!ind4)) || ((rc5 == EOK) && (!ind5)) )
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }
        returnStatus = CosaAdvSecFetchSbConfig(ParamName, NULL, NULL, puLong);
        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceError(("%s EXIT Error\n", __FUNCTION__));
            return FALSE;
        }

        return TRUE;
    }
#endif

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        SafeBrowsing_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       bValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
SafeBrowsing_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    int ind = -1;
    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("LookupTimeout", strlen("LookupTimeout"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        if ( bValue < ADVSEC_DEFAULT_LOOKUP_TIMEOUT || bValue > ADVSEC_MAX_LOOKUP_TIMEOUT )
        {
            CcspTraceWarning(("%s Values out of range\n", __FUNCTION__));
            return FALSE;
        }

        if(bValue == g_pAdvSecAgent->pAdvSec->pSafeBrows->ulLookupTimeout)
                return TRUE;

        returnStatus = CosaAdvSecSetLookupTimeout(bValue);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceError(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }

        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        SafeBrowsing_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue
            );

    description:

        This function is called to retrieve Unsigned Int parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                char*                       pValue,
                The string value buffer;

                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;

    return:     TRUE if succeeded;

                FALSE if not supported.

**********************************************************************/
ULONG
SafeBrowsing_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
#if (defined(_COSA_INTEL_XB3_ARM_) || defined(_COSA_BCM_MIPS_))
    UNREFERENCED_PARAMETER(ParamName);
    UNREFERENCED_PARAMETER(pValue);
    UNREFERENCED_PARAMETER(pUlSize);
#else
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    /* check the parameter name and return the corresponding value */
    errno_t rc1 = -1, rc2 = -1, rc3 = -1, rc4 = -1, rc5 = -1;
    int ind1 = -1, ind2 = -1, ind3 = -1, ind4 = -1, ind5 = -1;
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    rc1 = strcmp_s("Endpoint", strlen("Endpoint"), ParamName, &ind1);
    ERR_CHK(rc1);
    rc2 = strcmp_s("Blockpage", strlen("Blockpage"), ParamName, &ind2);
    ERR_CHK(rc2);
    rc3 = strcmp_s("Warnpage", strlen("Warnpage"), ParamName, &ind3);
    ERR_CHK(rc3);
    rc4 = strcmp_s("Cacheurl", strlen("Cacheurl"), ParamName, &ind4);
    ERR_CHK(rc4);
    rc5 = strcmp_s("OtmDedupFqdn", strlen("OtmDedupFqdn"), ParamName, &ind5);
    ERR_CHK(rc5);

    if( ((rc1 == EOK) && (!ind1)) || ((rc2 == EOK) && (!ind2)) || ((rc3 == EOK) && (!ind3)) ||
        ((rc4 == EOK) && (!ind4)) || ((rc5 == EOK) && (!ind5)) )
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return -1;
        }
        returnStatus = CosaAdvSecFetchSbConfig(ParamName, pValue, pUlSize, NULL);
        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceError(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }
        return returnStatus;
    }
#endif
    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return -1;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        SafeBrowsing_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
SafeBrowsing_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        SafeBrowsing_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
SafeBrowsing_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        SafeBrowsing_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation error found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
SafeBrowsing_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

/***********************************************************************

 APIs for Object:

	X_RDKCENTRAL-COM_AdvancedSecurity.Softflowd.

    *  Softflowd_GetParamBoolValue
    *  Softflowd_SetParamBoolValue
    *  Softflowd_Validate
    *  Softflowd_Commit
    *  Softflowd_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Softflowd_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Softflowd_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("Enable", strlen("Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        *pBool = g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable;
        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        Softflowd_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Softflowd_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
       return FALSE;

    rc = strcmp_s("Enable", strlen("Enable"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        if(bValue == g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaAdvSecStartFeatures(ADVSEC_SOFTFLOWD);
        else
                returnStatus = CosaAdvSecStopFeatures(ADVSEC_SOFTFLOWD);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceError(("%s EXIT Error\n", __FUNCTION__));
            return  FALSE;
        }

        return TRUE;
    }

    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}


/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        Softflowd_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
Softflowd_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Softflowd_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
Softflowd_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        Softflowd_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation error found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
Softflowd_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

/***********************************************************************

 APIs for Object:

        X_RDKCENTRAL-COM_AdvancedParentalControl.

    *  AdvancedParentalControl_GetParamBoolValue
    *  AdvancedParentalControl_SetParamBoolValue
    *  AdvancedParentalControl_Validate
    *  AdvancedParentalControl_Commit
    *  AdvancedParentalControl_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AdvancedParentalControl_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvancedParentalControl_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("Activate", strlen("Activate"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        *pBool = g_pAdvSecAgent->pAdvPC->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AdvancedParentalControl_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvancedParentalControl_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
       return FALSE;

    rc = strcmp_s("Activate", strlen("Activate"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        if(bValue == g_pAdvSecAgent->pAdvPC->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaStartAdvParentalControl(TRUE);
        else
                returnStatus = CosaStopAdvParentalControl(TRUE);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  FALSE;
        }

        return TRUE;
    }
    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AdvancedParentalControl_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
AdvancedParentalControl_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(puLength);
    UNREFERENCED_PARAMETER(pReturnParamName);
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        AdvancedParentalControl_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
AdvancedParentalControl_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        AdvancedParentalControl_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation error found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
AdvancedParentalControl_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

/***********************************************************************

 APIs for Object:

        X_RDKCENTRAL-COM_PrivacyProtection.

    *  PrivacyProtection_GetParamBoolValue
    *  PrivacyProtection_SetParamBoolValue
    *  PrivacyProtection_Validate
    *  PrivacyProtection_Commit
    *  PrivacyProtection_Rollback

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PrivacyProtection_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PrivacyProtection_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("Activate", strlen("Activate"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        *pBool = g_pAdvSecAgent->pPrivProt->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PrivacyProtection_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PrivacyProtection_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    PCOSA_DATAMODEL_AGENT       pMyObject     = (PCOSA_DATAMODEL_AGENT)g_pAdvSecAgent;
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    int ind = -1;

    if(ParamName == NULL)
        return FALSE;

    rc = strcmp_s("Activate", strlen("Activate"), ParamName, &ind);
    ERR_CHK(rc);
    if((rc == EOK) && (!ind))
    {
        if ( !pMyObject->bEnable )
        {
            CcspTraceInfo(("%s: Advsec: Device Finger Printing is disabled\n", __FUNCTION__));
            return FALSE;
        }

        if(bValue == g_pAdvSecAgent->pPrivProt->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaStartPrivacyProtection(TRUE);
        else
                returnStatus = CosaStopPrivacyProtection(TRUE);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceError(("%s EXIT Error\n", __FUNCTION__));
            return  FALSE;
        }

        return TRUE;
    }
    CcspTraceWarning(("%s: Unsupported parameter '%s'\n", __FUNCTION__, ParamName));
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PrivacyProtection_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
PrivacyProtection_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    UNREFERENCED_PARAMETER(pReturnParamName);
    UNREFERENCED_PARAMETER(puLength);
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        PrivacyProtection_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
PrivacyProtection_Commit
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        PrivacyProtection_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a
        validation error found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
PrivacyProtection_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    return 0;
}
/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RFC.Feature.RabidFramework.

    *  RabidFramework_GetParamUlongValue
    *  RabidFramework_SetParamUlongValue

***********************************************************************/

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        RabidFramework_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      pUlong
            );

    description:

        This function is called to retrieve unsigned long parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                       pUlong
                The buffer of returned unsigned long value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
RabidFramework_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pUlong
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    if( AnscEqualString(ParamName, "MemoryLimit", TRUE))
    {
        *pUlong = g_pAdvSecAgent->pRabid->uMemoryLimit;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "MacCacheSize", TRUE))
    {
        *pUlong = g_pAdvSecAgent->pRabid->uMacCacheSize;
        return TRUE;
    }
    if( AnscEqualString(ParamName, "DNSCacheSize", TRUE))
    {
        *pUlong = g_pAdvSecAgent->pRabid->uDNSCacheSize;
        return TRUE;
    }

    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        RabidFramework_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set unsigned long parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                        uValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
RabidFramework_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    if( AnscEqualString(ParamName, "MemoryLimit", TRUE))
    {
        if(uValue == g_pAdvSecAgent->pRabid->uMemoryLimit)
                return TRUE;

        if (uValue <= MIN_AGENT_MEMORY_HARD_LIMIT)
                return FALSE;

        returnStatus = CosaRabidSetMemoryLimit(g_pAdvSecAgent->pRabid, uValue);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }

        return TRUE;
    }
    if( AnscEqualString(ParamName, "MacCacheSize", TRUE))
    {
        if(uValue == g_pAdvSecAgent->pRabid->uMacCacheSize)
                return TRUE;

        if (uValue > MAX_RABID_MACCACHE_SIZE)
                return FALSE;

        returnStatus = CosaRabidSetMacCacheSize(g_pAdvSecAgent->pRabid, uValue);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }

        return TRUE;
    }
    if( AnscEqualString(ParamName, "DNSCacheSize", TRUE))
    {
        if(uValue == g_pAdvSecAgent->pRabid->uDNSCacheSize)
                return TRUE;

        if (uValue > MAX_RABID_DNSCACHE_SIZE)
                return FALSE;

        returnStatus = CosaRabidSetDNSCacheSize(g_pAdvSecAgent->pRabid, uValue);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }

        return TRUE;
    }

    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/***********************************************************************

 APIs for Object:

    DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvancedParentalControl.

    *  AdvancedParentalControl_RFC_GetParamBoolValue
    *  AdvancedParentalControl_RFC_SetParamBoolValue

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        AdvancedParentalControl_RFC_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvancedParentalControl_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pAdvSecAgent->pAdvPC_RFC->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvancedParentalControl_RFC_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvancedParentalControl_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        if(bValue == g_pAdvSecAgent->pAdvPC_RFC->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaAdvPCInit(g_pAdvSecAgent->pAdvPC_RFC);
        else
                returnStatus = CosaAdvPCDeInit(g_pAdvSecAgent->pAdvPC_RFC);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }

        return TRUE;
    }

    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RFC.Feature.PrivacyProtection.

    *  PrivacyProtection_RFC_GetParamBoolValue
    *  PrivacyProtection_RFC_SetParamBoolValue

***********************************************************************/
/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        PrivacyProtection_RFC_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PrivacyProtection_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pAdvSecAgent->pPrivProt_RFC->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}


/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        PrivacyProtection_RFC_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
PrivacyProtection_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        if(bValue == g_pAdvSecAgent->pPrivProt_RFC->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaPrivacyProtectionInit(g_pAdvSecAgent->pPrivProt_RFC);
        else
                returnStatus = CosaPrivacyProtectionDeInit(g_pAdvSecAgent->pPrivProt_RFC);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }

        return TRUE;
    }

    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RFC.Feature.DeviceFingerPrintICMPv6.

    *  DeviceFingerPrintICMPv6_RFC_GetParamBoolValue
    *  DeviceFingerPrintICMPv6_RFC_SetParamBoolValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DeviceFingerPrintICMPv6_RFC_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DeviceFingerPrintICMPv6_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
#if !(defined(_COSA_INTEL_XB3_ARM_) || defined(_COSA_BCM_MIPS_))
        *pBool = g_pAdvSecAgent->pDFIcmpv6_RFC->bEnable;
        return TRUE;
#else
        UNREFERENCED_PARAMETER(pBool);
        return FALSE;
#endif
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        DeviceFingerPrintICMPv6_RFC_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
DeviceFingerPrintICMPv6_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
#if !(defined(_COSA_INTEL_XB3_ARM_) || defined(_COSA_BCM_MIPS_))
        if(bValue == g_pAdvSecAgent->pDFIcmpv6_RFC->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaAdvDFIcmpv6Init(g_pAdvSecAgent->pDFIcmpv6_RFC);
        else
                returnStatus = CosaAdvDFIcmpv6DeInit(g_pAdvSecAgent->pDFIcmpv6_RFC);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }
        return TRUE;
#else
     UNREFERENCED_PARAMETER(bValue);
     UNREFERENCED_PARAMETER(returnStatus);
     return FALSE;
#endif
    }

    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RFC.Feature.WS-Discovery_Analysis.

    *  WS_Discovery_Analysis_RFC_GetParamBoolValue
    *  WS_Discovery_Analysis_RFC_SetParamBoolValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        WS_Discovery_Analysis_RFC_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
WS_Discovery_Analysis_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pAdvSecAgent->pWSDiscoveryAnalysis_RFC->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        WS_Discovery_Analysis_RFC_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
WS_Discovery_Analysis_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        if(bValue == g_pAdvSecAgent->pWSDiscoveryAnalysis_RFC->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaWSDisInit(g_pAdvSecAgent->pWSDiscoveryAnalysis_RFC);
        else
                returnStatus = CosaWSDisDeInit(g_pAdvSecAgent->pWSDiscoveryAnalysis_RFC);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }
        return TRUE;
    }

    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RFC.Feature.AdvancedSecurityOTM.

    *  AdvancedSecurityOTM_RFC_GetParamBoolValue
    *  AdvancedSecurityOTM_RFC_SetParamBoolValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvancedSecurityOTM_RFC_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvancedSecurityOTM_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pAdvSecAgent->pAdvSecOTM_RFC->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvancedSecurityOTM_RFC_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvancedSecurityOTM_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        if(bValue == g_pAdvSecAgent->pAdvSecOTM_RFC->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaAdvSecOTMInit(g_pAdvSecAgent->pAdvSecOTM_RFC);
        else
                returnStatus = CosaAdvSecOTMDeInit(g_pAdvSecAgent->pAdvSecOTM_RFC);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }
        return TRUE;
    }

    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RFC.Feature.AdvSecAgentRaptr.

    *  AdvSecAgentRaptr_RFC_GetParamBoolValue
    *  AdvSecAgentRaptr_RFC_SetParamBoolValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvSecAgentRaptr_RFC_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvSecAgentRaptr_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pAdvSecAgent->pRaptr_RFC->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvSecAgentRaptr_RFC_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvSecAgentRaptr_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        if(bValue == g_pAdvSecAgent->pRaptr_RFC->bEnable)
                return TRUE;
        if( bValue )
        {
            returnStatus = CosaAdvSecAgentRaptrInit(g_pAdvSecAgent->pRaptr_RFC);
        }
        else
        {
            CcspTraceWarning(("AdvSecAgentRaptr_RFC can't be disabled from agent\n"));
            return FALSE;
        }

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  FALSE;
        }
        return TRUE;
    }

    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RFC.Feature.AdvanceSecurityUserSpace.

    *  AdvanceSecurityUserSpace_RFC_GetParamBoolValue
    *  AdvanceSecurityUserSpace_RFC_SetParamBoolValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvanceSecurityUserSpace_RFC_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvanceSecurityUserSpace_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvanceSecurityUserSpace_RFC_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvanceSecurityUserSpace_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        if ((TRUE == g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable) && (TRUE == g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable) && (FALSE == bValue))
        {
            CcspTraceInfo(("Unable to set the AdvSecUserSpace_RFC to FALSE since the AdWifiDataCollection_RFC is TRUE \n"));
            CcspTraceInfo(("AdvSecUserSpace_RFCEnable:%d|AdvWifiDataCollection_RFC:%d\n", g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable, g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable));
            return FALSE;
        }
        if(bValue == g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaAdvSecUserSpaceInit(g_pAdvSecAgent->pAdvSecUserSpace_RFC);
        else
        {
                //returnStatus = CosaAdvSecUserSpaceDeInit(g_pAdvSecAgent->pAdvSecUserSpace_RFC);
                CcspTraceInfo(("AdvSecUserSpace_RFC is defaulted to TRUE, cannot be set to FALSE \n"));
                return FALSE;
        }

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }
        return TRUE;
    }

    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RFC.Feature.Levl.

    *  Levl_RFC_GetParamBoolValue
    *  Levl_RFC_SetParamBoolValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        Levl_RFC_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Levl_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
#ifdef WIFI_DATA_COLLECTION
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pAdvSecAgent->pLevl_RFC->bEnable;
        return TRUE;
    }
#else
    UNREFERENCED_PARAMETER(pBool);
#endif
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        Levl_RFC_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
Levl_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
#ifdef WIFI_DATA_COLLECTION
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;

    if(AnscEqualString(ParamName, "Enable", TRUE))
    {
        if(bValue == g_pAdvSecAgent->pLevl_RFC->bEnable)
                return TRUE;
        if(bValue)
                returnStatus = CosaLevlInit(g_pAdvSecAgent->pLevl_RFC);
        else
                returnStatus = CosaLevlDeInit(g_pAdvSecAgent->pLevl_RFC);

        if (returnStatus != ANSC_STATUS_SUCCESS)
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return FALSE;
        }
        return TRUE;
    }
#else
    UNREFERENCED_PARAMETER(bValue);
#endif
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RFC.Feature.AdvSecAgent.

    *  AdvSecAgent_RFC_GetParamBoolValue
    *  AdvSecAgent_RFC_SetParamBoolValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvSecAgent_RFC_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvSecAgent_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pAdvSecAgent->pAdvSecAgent_RFC->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvSecAgent_RFC_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvSecAgent_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;

    if(AnscEqualString(ParamName, "Enable", TRUE))
    {
        if(bValue == g_pAdvSecAgent->pAdvSecAgent_RFC->bEnable)
                return TRUE;
        if(bValue)
                returnStatus = CosaAdvSecAgentInit(g_pAdvSecAgent->pAdvSecAgent_RFC);
        else
                returnStatus = CosaAdvSecAgentDeInit(g_pAdvSecAgent->pAdvSecAgent_RFC);

        if (returnStatus != ANSC_STATUS_SUCCESS)
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return FALSE;
        }
        return TRUE;
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RFC.Feature.AdvSecSafeBrowsing.

    *  AdvSecSafeBrowsing_RFC_GetParamBoolValue
    *  AdvSecSafeBrowsing_RFC_SetParamBoolValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvSecSafeBrowsing_RFC_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvSecSafeBrowsing_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pAdvSecAgent->pAdvSecSafeBrowsing_RFC->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvSecSafeBrowsing_RFC_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvSecSafeBrowsing_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;

    if(AnscEqualString(ParamName, "Enable", TRUE))
    {
        if(bValue == g_pAdvSecAgent->pAdvSecSafeBrowsing_RFC->bEnable)
                return TRUE;
        if (g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable)
        {
            if(bValue)
                returnStatus = CosaAdvSecSafeBrowsingInit(g_pAdvSecAgent->pAdvSecSafeBrowsing_RFC);
            else
                returnStatus = CosaAdvSecSafeBrowsingDeInit(g_pAdvSecAgent->pAdvSecSafeBrowsing_RFC);
        }
        else
        {
             CcspTraceWarning(("AdvSecUserSpace_RFC is not enabled..\n"));
             returnStatus = ANSC_STATUS_FAILURE;
        }
        if (returnStatus != ANSC_STATUS_SUCCESS)
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return FALSE;
        }
        return TRUE;
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RFC.Feature.AdvSecCujoTelemetryWiFiFP.

    *  AdvSecCujoTelemetryWiFiFP_RFC_GetParamBoolValue
    *  AdvSecCujoTelemetryWiFiFP_RFC_SetParamBoolValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvSecCujoTelemetryWiFiFP_RFC_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvSecCujoTelemetryWiFiFP_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pAdvSecAgent->pAdvSecCujoTelemetryWiFiFP_RFC->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvSecCujoTelemetryWiFiFP_RFC_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvSecCujoTelemetryWiFiFP_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;

    if(AnscEqualString(ParamName, "Enable", TRUE))
    {
        if(bValue == g_pAdvSecAgent->pAdvSecCujoTelemetryWiFiFP_RFC->bEnable)
                return TRUE;
        if (g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable)
        {
            if(bValue)
                returnStatus = CosaAdvSecCujoTelemetryWiFiFPInit(g_pAdvSecAgent->pAdvSecCujoTelemetryWiFiFP_RFC);
            else
                returnStatus = CosaAdvSecCujoTelemetryWiFiFPDeInit(g_pAdvSecAgent->pAdvSecCujoTelemetryWiFiFP_RFC);
        }
        else
        {
             CcspTraceWarning(("AdvSecUserSpace_RFC is not enabled..\n"));
             returnStatus = ANSC_STATUS_FAILURE;
        }
        if (returnStatus != ANSC_STATUS_SUCCESS)
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return FALSE;
        }
        return TRUE;
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RFC.Feature.AdvanceSecurityCujoTracer.

    *  AdvanceSecurityCujoTracer_RFC_GetParamBoolValue
    *  AdvanceSecurityCujoTracer_RFC_SetParamBoolValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvanceSecurityCujoTracer_RFC_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvanceSecurityCujoTracer_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pAdvSecAgent->pAdvSecCujoTracer_RFC->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvanceSecurityCujoTracer_RFC_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvanceSecurityCujoTracer_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        if(bValue == g_pAdvSecAgent->pAdvSecCujoTracer_RFC->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaAdvSecCujoTracerInit(g_pAdvSecAgent->pAdvSecCujoTracer_RFC);
        else
                returnStatus = CosaAdvSecCujoTracerDeInit(g_pAdvSecAgent->pAdvSecCujoTracer_RFC);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }
        return TRUE;
    }

    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RFC.Feature.AdvanceSecurityCujoTelemetry.

    *  AdvanceSecurityCujoTelemetry_RFC_GetParamBoolValue
    *  AdvanceSecurityCujoTelemetry_RFC_SetParamBoolValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvanceSecurityCujoTelemetry_RFC_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvanceSecurityCujoTelemetry_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pAdvSecAgent->pAdvSecCujoTelemetry_RFC->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvanceSecurityCujoTelemetry_RFC_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvanceSecurityCujoTelemetry_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        if(bValue == g_pAdvSecAgent->pAdvSecCujoTelemetry_RFC->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaAdvSecCujoTelemetryInit(g_pAdvSecAgent->pAdvSecCujoTelemetry_RFC);
        else
                returnStatus = CosaAdvSecCujoTelemetryDeInit(g_pAdvSecAgent->pAdvSecCujoTelemetry_RFC);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return  returnStatus;
        }
        return TRUE;
    }

    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RFC.Feature.AdvSecSentryAtTheEdge.

    *  AdvSecSentryAtTheEdge_RFC_GetParamBoolValue
    *  AdvSecSentryAtTheEdge_RFC_SetParamBoolValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvSecSentryAtTheEdge_RFC_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

***********************************************************************/
BOOL
AdvSecSentryAtTheEdge_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pAdvSecAgent->pAdvSecSATE_RFC->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvSecSentryAtTheEdge_RFC_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvSecSentryAtTheEdge_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{

    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        if(bValue == g_pAdvSecAgent->pAdvSecSATE_RFC->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaAdvSecSATEInit(g_pAdvSecAgent->pAdvSecSATE_RFC);
        else
                returnStatus = CosaAdvSecSATEDeInit(g_pAdvSecAgent->pAdvSecSATE_RFC);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return FALSE;
        }
        return TRUE;
    }

    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RFC.Feature.AdvSecTCPTrackerFilterDevices.

    *  AdvSecTCPTrackerFilterDevices_RFC_GetParamBoolValue
    *  AdvSecTCPTrackerFilterDevices_RFC_SetParamBoolValue

***********************************************************************/

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvSecTCPTrackerFilterDevices_RFC_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

***********************************************************************/
BOOL
AdvSecTCPTrackerFilterDevices_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pAdvSecAgent->pAdvSecTCPTrackerFilterDevices_RFC->bEnable;
        return TRUE;
    }
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        AdvSecTCPTrackerFilterDevices_RFC_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
AdvSecTCPTrackerFilterDevices_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */

    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    if( AnscEqualString(ParamName, "Enable", TRUE))
    {
        if(bValue == g_pAdvSecAgent->pAdvSecTCPTrackerFilterDevices_RFC->bEnable)
                return TRUE;
        if( bValue )
                returnStatus = CosaAdvSecTCPTrackerFilterDevicesInit(g_pAdvSecAgent->pAdvSecTCPTrackerFilterDevices_RFC);
        else
                returnStatus = CosaAdvSecTCPTrackerFilterDevicesDeInit(g_pAdvSecAgent->pAdvSecTCPTrackerFilterDevices_RFC);

        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return FALSE;
        }
        return TRUE;
    }

    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}

/***********************************************************************

 APIs for Object:

    X_RDKCENTRAL-COM_RFC.Feature.WifiDataCollection.

    *  WifiDataCollection_RFC_GetParamBoolValue
    *  WifiDataCollection_RFC_SetParamBoolValue

***********************************************************************/
/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        WifiDataCollection_RFC_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );

    description:

        This function is called to retrieve Boolean parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL*                       pBool
                The buffer of returned boolean value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
WifiDataCollection_RFC_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
#ifdef WIFI_DATA_COLLECTION
    if(AnscEqualString(ParamName, "Enable", TRUE))
    {
        *pBool = g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable;
        return TRUE;
    }
#else
    UNREFERENCED_PARAMETER(pBool);
#endif
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));

    return FALSE;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        WifiDataCollection_RFC_SetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL                        bValue
            );

    description:

        This function is called to set BOOL parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                BOOL                        bValue
                The updated BOOL value;

    return:     TRUE if succeeded.

**********************************************************************/
BOOL
WifiDataCollection_RFC_SetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL                        bValue
    )
{
    UNREFERENCED_PARAMETER(hInsContext);
    /* check the parameter name and return the corresponding value */
#ifdef WIFI_DATA_COLLECTION
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    ULONG SysCfg_ASWIFIDCL_RFC = 0;
    if(AnscEqualString(ParamName, "Enable", TRUE))
    {
        if ((FALSE == g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable) && (FALSE == g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable) && (TRUE == bValue))
        {
            CcspTraceInfo(("Unable to set the AdvWifiDataCollection_RFC to TRUE since the AdvSecUserSpace_RFC is FALSE \n"));
            CcspTraceInfo(("AdvSecUserSpace_RFCEnable:%d|AdvWifiDataCollection_RFC:%d\n", g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable, g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable));
            return FALSE;
        }
        CosaGetSysCfgUlong(g_AdvWifiDataCollection, &SysCfg_ASWIFIDCL_RFC);
        if ((bValue == g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable) && (bValue == SysCfg_ASWIFIDCL_RFC))
                return TRUE;
        if(bValue)
                returnStatus = CosaAdvWifiDataCollectionInit(g_pAdvSecAgent->pAdvWifiDataCollection_RFC);
        else
                returnStatus = CosaAdvWifiDataCollectionDeInit(g_pAdvSecAgent->pAdvWifiDataCollection_RFC);

        if (returnStatus != ANSC_STATUS_SUCCESS)
        {
            CcspTraceInfo(("%s EXIT Error\n", __FUNCTION__));
            return FALSE;
        }
        return TRUE;
    }
#else
    UNREFERENCED_PARAMETER(bValue);
#endif
    CcspTraceWarning(("Unsupported parameter '%s'\n", ParamName));
    return FALSE;
}
