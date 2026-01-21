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

/**************************************************************************

    module: cosa_adv_security_internal.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file implements back-end apis for the COSA Data Model Library

**************************************************************************/

#include "cosa_adv_security_internal.h"
#include "cosa_adv_security_dml.h"
#include "cosa_adv_security_webconfig.h"
/* Legacy CCSP dependencies commented out for JSON-driven RBUS approach */
/* Legacy CCSP PSM helper commented out for JSON-driven RBUS approach */
/* #include "ccsp_psm_helper.h" */
#include <sysevent/sysevent.h>
#include <time.h>
#include "cJSON.h"
/* Legacy HAL dependencies commented out for JSON-driven RBUS approach */
#include <ccsp/platform_hal.h> 
#include <syscfg/syscfg.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/types.h>
/* Legacy common-library includes commented out for JSON-driven RBUS approach */
/* #include "safec_lib_common.h" */
#include <safec_lib.h>
#include "secure_wrapper.h"
#include <rbus/rbus.h>
#if defined(_COSA_BCM_MIPS_)
/* Legacy HAL dependencies commented out for JSON-driven RBUS approach */
#include <ccsp/dpoe_hal.h>
#else
/* Legacy HAL dependencies commented out for JSON-driven RBUS approach */
#include <ccsp/cm_hal.h>
#endif
#if !(_COSA_BCM_MIPS_ || _COSA_DRG_TPG_ || CONFIG_CISCO)
/* #include <autoconf.h> */  /* Not available in RBUS environment */
#if defined(_XB8_PRODUCT_REQ_)
        #define CONFIG_VENDOR_NAME "Technicolor"
        #define CONFIG_VENDOR_ID "28BE9B"
        #define CONFIG_TI_GW_DESCRIPTION "DOCSIS 3.1 2-port Voice Gateway"
#endif
#endif

#ifdef WIFI_DATA_COLLECTION
#include "cujoagent_dcl_api.h"
#endif

/* sysevent definations */
#define ADVSEC_SYSEVENT_BRIDGE_MODE_EVENT "bridge_mode"
#define ADVSEC_SYSEVENT_CLOUD_HOST_IP "advsec_host_ip"
#define ADVSEC_SYSEVENT_MAP_T_CONFIG_CHANGED_EVENT "mapt_config_flag"
#define ADVSEC_SYSEVENT_CURRENT_WAN_IFNAME_EVENT "current_wan_ifname"

#define LEVL_DML "Device.WiFi.Levl"

#define ADVSEC_WAIT_FOR_TIMEOUT (60 * 60)
#define MAX_VALUE 32
#define MAX_INTERFACE_SIZE 16
#define COMMAND_MAX 256
#define BUFFERSIZE_MAX  256
#define ADVSEC_LOOKUP_EXCEED_COUNT_FILE "/tmp/advsec_lkup_exceed_cnt"

#ifdef DOWNLOADMODULE_ENABLE
#define TEMP_DOWNLOAD_LOCATION "/tmp/cujo_dnld"
#else
#define TEMP_DOWNLOAD_LOCATION ""
#endif

#define ADVSEC_CONFIG_PARAMS_DIR_PATH "/tmp/advsec_config_params"
#define ADVSEC_CONFIG_PARAMS_MODEL_PATH "/tmp/advsec_config_params/MODEL"
#define ADVSEC_CONFIG_PARAMS_MNCF_PATH "/tmp/advsec_config_params/MANUFACTURER"
#define ADVSEC_CONFIG_PARAMS_FW_PATH "/tmp/advsec_config_params/FWVER"
#define ADVSEC_CONFIG_PARAMS_HW_PATH "/tmp/advsec_config_params/HWVER"
#define ADVSEC_CONFIG_PARAMS_CM_MAC_PATH "/tmp/advsec_config_params/CMMAC"
#define ADVSEC_INITIALIZED_FILE_PATH "/tmp/advsec_initialized"
#define ADVSEC_WIFIDCL_INIT_FILE_PATH "/tmp/advsec_wifidcl_init"
#define ADVSEC_CLOUD_HOST "/tmp/advsec_cloud_host"
#define ADVSEC_CLOUD_IP "/tmp/advsec_cloud_ipv4"
#define ADVSEC_DEFAULT_CM_MAC "00:1A:2B:11:22:33"
#define SAFEBRO_CONFIG_FILE_PATH "/tmp/safebro.json"
#define ADVSEC_PRIMARY_WAN_IF_NAME "erouter0"

#ifdef CONFIG_CISCO
#define CONFIG_VENDOR_NAME  "Cisco"
#endif

#if (_COSA_BCM_MIPS_ || _COSA_DRG_TPG_)
#define CONFIG_VENDOR_NAME "ARRIS Group, Inc."
#endif

#define NUM_SYSEVENT_TYPES (sizeof(advSysEvent_type_table)/sizeof(advSysEvent_type_table[0]))

#if defined(_PLATFORM_RASPBERRYPI_) || defined(_PLATFORM_TURRIS_) || defined(_XER5_PRODUCT_REQ_) || defined(_PLATFORM_BANANAPI_R4_)
# Legacy code commented out for JSON-based RBUS approach
/* Legacy CCSP vendor header commented out for JSON-driven RBUS approach */
/* #include "ccsp_vendor.h" */
*/
#endif

rbusHandle_t rbus_handle;
rbusHandle_t g_rbusHandle; /* Global RBUS handle for Advanced Security */

extern ANSC_HANDLE bus_handle;
extern char g_Subsystem[32];
extern COSA_DATAMODEL_AGENT* g_pAdvSecAgent;

static char *g_DeviceFingerPrintEnabled = "Advsecurity_DeviceFingerPrint";
static char *g_AdvSecuritySBEnabled       = "Advsecurity_SafeBrowsing";
static char *g_AdvSecuritySFEnabled       = "Advsecurity_Softflowd";
static char *g_DeviceFingerPrintLogginPeriod = "Advsecurity_LoggingPeriod";
static char *g_DeviceFingerPrintLogLevel = "Advsecurity_LogLevel";
static char *g_AdvSecCustomEndpointURL = "Advsecurity_CustomEndpointURL";
static char *g_AdvSecDefaultEndpointURL = "Advsecurity_DefaultEndpointURL";
static char *g_AdvSecurityLookupTimeout = "Advsecurity_LookupTimeout";
static char *g_AdvParentalControl = "Adv_PCActivate";
static char *g_PrivacyProtection = "Adv_PPActivate";

static char *g_RabidMemoryLimit = "Advsecurity_RabidMemoryLimit";
static char *g_RabidMacCacheSize = "Advsecurity_RabidMacCacheSize";
static char *g_RabidDNSCacheSize = "Advsecurity_RabidDNSCacheSize";

static char *g_PrivacyProtectionEnabled = "Adv_PrivProtRFCEnable";
static char *g_AdvParentalControlEnabled = "Adv_PCRFCEnable";
static char *g_DeviceFingerPrintICMPv6Enabled = "Adv_DFICMPv6RFCEnable";
static char *g_WSDiscoveryAnalysisEnabled = "Adv_WSDisAnaRFCEnable";
static char *g_AdvSecOTMEnabled = "Adv_AdvSecOTMRFCEnable";
static char *g_AdvSecUserSpaceEnabled = "Adv_AdvSecUserSpaceRFCEnable";
static char *g_RaptrEnabled = "Adv_RaptrRFCEnable";
#ifdef WIFI_DATA_COLLECTION
static char *g_AdvWifiDataCollection = "Adv_WifiDataCollectionRFCEnable";
static char *g_LevlEnabled = "Adv_LevlRFCEnable";
#endif
static char *g_AdvSecAgentEnabled = "Adv_AdvSecAgentRFCEnable";
static char *g_AdvSecSafeBrowsingEnabled = "Adv_AdvSecSafeBrowsingRFCEnable";
static char *g_AdvSecCujoTelemetryWiFiFPEnabled = "Adv_AdvSecCujoTelemetryWiFiFPRFCEnable";
static char *g_AdvSecCujoTracerEnabled = "Adv_AdvSecCujoTracerRFCEnable";
static char *g_AdvSecCujoTelemetryEnabled = "Adv_AdvSecCujoTelemetryRFCEnable";
// SATE - Sentry at the Edge
static char *g_AdvSecSATEEnabled = "Adv_SATERFCEnable";
static char *g_AdvSecTCPTrackerFilterDevicesEnabled = "Adv_TCPTrackerFilterDevicesRFCEnable";

/* Platform synchronization primitives */
pthread_mutex_t logMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t logCond = PTHREAD_COND_INITIALIZER;
key_t pubEventKey = 0;  /* Global event key for Advanced Security IPC */

static BOOL logReady = FALSE;
static char prevWanIfname[MAX_INTERFACE_SIZE] = {0};

void advsec_handle_sysevent_async(void);
static void advsec_start_logger_thread(void);
static BOOL WaitForLoggerTimeout(ULONG period);
enum advSysEvent_e{
    SYSEVENT_BRIDGE_MODE_EVENT,
    SYSEVENT_CLOUD_HOST_IP,
    SYSEVENT_MAP_T_CONFIG_CHANGED_EVENT,
    SYSEVENT_CURRENT_WAN_IFNAME_EVENT,
};

/*Structure defined to get the AdvSysEvent Noti type from the given Event names */

typedef struct advSysEvent_pair{
  char                 *name;
  enum advSysEvent_e   event;
} ADV_SYSEVENT_PAIR;

ADV_SYSEVENT_PAIR advSysEvent_type_table[] = {
  { ADVSEC_SYSEVENT_BRIDGE_MODE_EVENT,              SYSEVENT_BRIDGE_MODE_EVENT            },
  { ADVSEC_SYSEVENT_CLOUD_HOST_IP,                  SYSEVENT_CLOUD_HOST_IP                },
  { ADVSEC_SYSEVENT_MAP_T_CONFIG_CHANGED_EVENT,     SYSEVENT_MAP_T_CONFIG_CHANGED_EVENT   },
  { ADVSEC_SYSEVENT_CURRENT_WAN_IFNAME_EVENT,       SYSEVENT_CURRENT_WAN_IFNAME_EVENT   },
};

int get_advSysEvent_type_from_name(char *name, enum advSysEvent_e *type_ptr)
{
  errno_t rc = -1;
  int ind = -1;
  unsigned int i = 0;
  size_t str_size = 0;

  if((name == NULL) || (type_ptr == NULL))
     return 0;

  str_size = strlen(name);

  for (i = 0 ; i < NUM_SYSEVENT_TYPES ; ++i)
  {
      rc = strcmp_s(name, str_size, advSysEvent_type_table[i].name, &ind);
      ERR_CHK(rc);
      if((rc == EOK) && (!ind))
      {
          *type_ptr = advSysEvent_type_table[i].event;
          return 1;
      }
  }
  return 0;
}

/* Function to get Partner-based URL using RBUS */
static BOOL Advsec_getPartnerBasedURL(char *url)
{
    rbusError_t ret = RBUS_ERROR_SUCCESS;
    rbusValue_t value;
    extern rbusHandle_t g_rbus_handle;
    errno_t rc = -1;
    
    CcspTraceInfo(("Fetching the Redirector URL based on partnerID using RBUS\n"));

    /* Reuse global RBUS handle instead of opening a new connection */
    if (!g_rbus_handle) {
        CcspTraceError(("%s RBUS handle not initialized\n", __FUNCTION__));
        return false;
    }

    /* Get parameter using RBUS */
    ret = rbus_get(g_rbus_handle, PARTNER_REDIRECTORURL_PARAMNAME, &value);
    if (ret != RBUS_ERROR_SUCCESS) {
        CcspTraceError(("%s rbus_get %s error %d\n", __FUNCTION__, PARTNER_REDIRECTORURL_PARAMNAME, ret));
        return false;
    }

    const char* paramValue = rbusValue_GetString(value, NULL);
    if (paramValue && strlen(paramValue) > 0) {
        rc = strcpy_s(url, BUFFERSIZE_MAX-1, paramValue);
        ERR_CHK(rc);
        CcspTraceInfo(("%s Returned URL for the partner = %s\n", __FUNCTION__, url));
        rbusValue_Release(value);
        return true;
    } else {
        CcspTraceError(("%s Empty URL, go with defaults\n", __FUNCTION__));
        rbusValue_Release(value);
        return false;
    }
}

static BOOL Is_Device_Finger_Print_Enabled()
{
    return (g_pAdvSecAgent->bEnable);
}

static BOOL Is_Device_Finger_Print_Enabled_Completed()
{
    FILE *file = NULL;
    if ((file = fopen("/tmp/advsec_initialized", "r")))
    {
        fclose(file);
        return 1;
    }
    return 0;
}

static BOOL Is_Agent_Initialization_Completed()
{
    FILE *file = NULL;
    if ((file = fopen(ADVSEC_INITIALIZED_FILE_PATH, "r")))
    {
        fclose(file);
        return 1;
    }
    return 0;
}

static void advsec_create_dir(char *path)
{
    int ret =0;
    /* CID 135545: Time of check time of use  */
    ret = mkdir(path, 0777);
    if (ret < 0 && errno != EEXIST)
    {
        CcspTraceError(("%s:Folder Not created. Error %d\n", __FUNCTION__,errno));
    }
}

static BOOL advsec_write_to_file(char *fpath, char *str)
{
    FILE *file = NULL;

    if ( !fpath || !str )
    {
        return 0;
    }

    if ((file = fopen(fpath, "w")))
    {
        fprintf(file,"%s",str);
        fclose(file);
        return 1;
    }
    return 0;
}

static BOOL advsec_read_from_file(char *fpath, char *str, int size)
{
    FILE *file = NULL;

    if ( !fpath || !str || size <= 1)
    {
        return 0;
    }

    if ((file = fopen(fpath, "r")))
    {
        CcspTraceDebug(("%s: size: %d\n", __FUNCTION__, size));
        /* CID 162508: Calling risky function */
        char format[20] = {'\0'};
        int count = 0;
        errno_t rc = -1;
        count = snprintf(format,sizeof(format),"%%%ds", size-1);
        if (count < 0 || count >= (int)sizeof(format)) {
            CcspTraceError(("snprintf failed or output is truncated\n"));
            fclose(file);
            return 0;
        }
        /* CID 162506: Unchecked return value from library */
        rc = fscanf(file, format, str);
        ERR_CHK(rc);
        fclose(file);
        return 1;
    }
    return 0;
}

ANSC_STATUS CosaGetSysCfgString(char* setting, char* pValue, PULONG pulSize )
{
    char buf[1024] = {0};
    errno_t rc = -1;

    if(ANSC_STATUS_SUCCESS == syscfg_get( NULL, setting, buf, sizeof(buf)))
    {
        rc = strcpy_s(pValue, *pulSize, buf);
        if(rc != EOK)
        {
            ERR_CHK(rc);
            return ANSC_STATUS_FAILURE;
        }
        *pulSize = AnscSizeOfString(pValue);
        return ANSC_STATUS_SUCCESS;
    }
    else
            return ANSC_STATUS_FAILURE;
}

ANSC_STATUS CosaSetSysCfgString( char* setting, char* pValue )
{
        if ((syscfg_set(NULL, setting, pValue) != 0))
        {
            AnscTraceWarning(("syscfg_set failed\n"));
            return ANSC_STATUS_FAILURE;
        }
        else
        {
            if (syscfg_commit() != 0)
            {
                AnscTraceWarning(("setPartnerId : syscfg_commit failed\n"));
                return ANSC_STATUS_FAILURE;
            }

            return ANSC_STATUS_SUCCESS;
        }
}

static void Advsec_SetDefaultsUrl()
{
   /* CID 278549: Calling risky function */
   char out_val[BUFFERSIZE_MAX] = {'\0'};

   if( Advsec_getPartnerBasedURL(out_val) )
   {
       CosaSetSysCfgString(g_AdvSecDefaultEndpointURL, out_val);
       CcspTraceInfo(("%s : SysCfg SetDefault AdvSec EndPointURL from AdvsecRedirectorURL DataModel\n", __FUNCTION__));
   }
   else
   {
       CcspTraceError(("%s : Unable to retrieve Advsec EndPointUrl from Advsec_getPartnerBasedURL DataModel & DefaultEndpointURL SysCfg \n", __FUNCTION__));
   }
}

#ifdef WAN_FAILOVER_SUPPORTED
static void eventReceiveHandler(
    rbusHandle_t handle,
    rbusEvent_t const* event,
    rbusEventSubscription_t* subscription)
{
    (void)handle;
    (void)subscription;

    const char* eventName = event->name;
    rbusValue_t valBuff;
    valBuff = rbusObject_GetValue(event->data, NULL );
    if(!valBuff)
    {
        CcspTraceWarning(("AdvSecurityEventConsumer : FAILED , value is NULL\n"));
    }
    else
    {
        const char* newValue = rbusValue_GetString(valBuff, NULL);
        if ( strcmp(eventName,"Device.X_RDK_WanManager.CurrentActiveInterface") == 0 )
        {
            CcspTraceWarning(("AdvSecurityEventConsumer : New value of CurrentActiveInterface is = %s\n",newValue));
        }
    }
}
#endif

#ifdef WIFI_DATA_COLLECTION
static void wifiEventReceiveHandler(
    rbusHandle_t handle,
    rbusEvent_t const* event,
    rbusEventSubscription_t* subscription)
{
    (void)handle;
    (void)subscription;

    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    const char* eventName = event->name;
    rbusValue_t valBuff;
    valBuff = rbusObject_GetValue(event->data, NULL);
    if(!valBuff)
    {
        CcspTraceWarning(("AdvSecurityEventConsumer : FAILED, value is NULL\n"));
    }
    else
    {
        BOOL newValue = rbusValue_GetBoolean(valBuff);
        if ((strcmp(eventName, LEVL_DML) == 0))
        {
            CcspTraceWarning(("AdvSecurityEventConsumer : New value of WiFi Levl is %s\n", newValue ? "true" : "false"));
            if (g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable && !newValue)
            {
                CcspTraceWarning(("Disabling WifiDataCollection RFC\n"));
                returnStatus = CosaAdvWifiDataCollectionDeInit(g_pAdvSecAgent->pAdvWifiDataCollection_RFC);
                if (returnStatus != ANSC_STATUS_SUCCESS)
                {
                    CcspTraceError(("%s EXIT Error\n", __FUNCTION__));
                }
            }
        }
    }
}

int wifidcl_init_precheck()
{
    char *s = NULL;
    char const *name = WIFI_WEBCONFIG_INIT_DATA_NAMESPACE;
    int returnStatus = ANSC_STATUS_FAILURE;
    int i = 0, retry_count = 0, retry_delay = 0;
    struct sysinfo info = {0};
    unsigned long uptime_seconds = 0;

    if(rbus_handle == NULL)
    {
        CcspTraceError(("%s:%d rbus_handle is NULL\n", __FUNCTION__, __LINE__));
        return returnStatus;
    }

    if (sysinfo(&info) != 0) {
        CcspTraceError(("sysinfo fetch failed\n"));
        returnStatus = ANSC_STATUS_FAILURE;
        return returnStatus;
    }

    uptime_seconds = info.uptime;
    if (uptime_seconds > 600) {
        retry_count = 1;
        retry_delay = 0;
    }
    else {
        retry_count = 5;
        retry_delay = 15;
    }

    for (i = 0; i < retry_count; i++) {
        returnStatus = rbus_getStr(rbus_handle, name, &s);
        if (returnStatus != RBUS_ERROR_SUCCESS) {
            CcspTraceError(("%s:%d Failed to get [%s] over RBUS: [%d]\n", __FUNCTION__, __LINE__, name, returnStatus));
            CcspTraceInfo(("%s:%d Retry get WiFi webconfig init data in %d seconds\n", __FUNCTION__, __LINE__, retry_delay));
            sleep(retry_delay);
            continue;
        }

        CcspTraceInfo(("%s:%d WiFi webconfig init data get SUCCESS\n", __FUNCTION__, __LINE__));

        if (strlen(s) == 0) {
            CcspTraceError(("%s:%d WiFi webconfig init data is empty\n", __FUNCTION__, __LINE__));
            returnStatus = ANSC_STATUS_FAILURE;
        }
        else {
            break;
        }

        /* rbus_getStr() return is strdup()'ed, free it */
        free(s);
        CcspTraceInfo(("%s:%d Retry get WiFi webconfig init data in %d seconds\n", __FUNCTION__, __LINE__, retry_delay));
        sleep(retry_delay);
    }
    return returnStatus;
}
#endif

BOOL Wifi_Get_Status(const char *pParamName)
{
   ANSC_STATUS ret = ANSC_STATUS_SUCCESS;
   char Value[128] = {0};
   errno_t      rc = -1;
   int ind         = -1;

   ret = Wifi_GetParameterValue(pParamName, Value);

   if (ret == ANSC_STATUS_SUCCESS)
   {
       if (Value[0] != '\0')
       {
           CcspTraceInfo(("%s: %s Status : %s\n", __FUNCTION__, pParamName, Value));
           rc = strcmp_s("true", strlen("true"), Value, &ind);
           ERR_CHK(rc);
           if((!ind) && (rc == EOK))
           {
             return TRUE;
           }
       }
   }
   return FALSE;
}

/* Get parameter value API */
ANSC_STATUS Wifi_GetParameterValue(const char *pParamName, char *pReturnVal)
{
    int                    ret = -1;
    rbusValue_t            value;
    rbusValueType_t        rbusValueType ;
    char                   *pStrVal            = NULL;

    /* rbus get parameter value */
    if(rbus_handle == NULL)
    {
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s Rbus Invoke\n", __FUNCTION__));
    /* Init rbus variable */
    rbusValue_Init(&value);

    /* Get the value of a single parameter */
    ret = rbus_get(rbus_handle, pParamName, &value);

    if(ret != RBUS_ERROR_SUCCESS )
    {
        CcspTraceError(("%s-%d Rbus Error code:%d\n", __FUNCTION__, __LINE__, ret));
        rbusValue_Release(value);
        return ANSC_STATUS_FAILURE;
    }

    rbusValueType = rbusValue_GetType(value);

    /* Update the parameter value */
    if(rbusValueType == RBUS_BOOLEAN)
    {
        if (rbusValue_GetBoolean(value)){
            pStrVal= "true";
        } else {
            pStrVal = "false";
        }
        strncpy( pReturnVal, pStrVal, strlen( pStrVal ) + 1 );
    }
    else
    {
        pStrVal = rbusValue_ToString(value, NULL, 0);
        if (pStrVal)
        {
            strncpy( pReturnVal, pStrVal, strlen( pStrVal ) + 1 );
            free(pStrVal);
            pStrVal = NULL;
        }
    }

    /* release rbus variable */
    rbusValue_Release(value);
    return ANSC_STATUS_SUCCESS;
}

/* Set parameter value API */
ANSC_STATUS Wifi_SetParameterValue(const char *paramName, bool bValue)
{
    int ret = -1;
    rbusValue_t value;

    /* rbus set parameter value */
    if(rbus_handle == NULL)
    {
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s Rbus Invoke\n", __FUNCTION__));
    /* Init rbus variable */
    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, bValue);

    /* Set the value of a single parameter */
    ret = rbus_set(rbus_handle, paramName, value, NULL);
    if(ret != RBUS_ERROR_SUCCESS) {
        CcspTraceError(("%s-%d Rbus Error code:%d\n", __FUNCTION__, __LINE__, ret));
        rbusValue_Release(value);
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s: wifi rbus set[%s]:value:%d\n", __FUNCTION__, paramName, bValue));

    /* release rbus variable */
    rbusValue_Release(value);
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS CosaAdvSecFetchSbConfig(char* paramName, char* pValue, ULONG* pUlSize, ULONG* puLong)
{
    errno_t rc1 = -1, rc2 = -1;
    int ind1 = -1, ind2 = -1, i = 0, j = 0, paramLen = 0;
    cJSON *parameterObj = NULL;
    cJSON *json = NULL;
    char* data = NULL;
    char json_key[30] = {0};
    errno_t rc = -1;
    int file_length;

    rc = v_secure_system("/usr/ccsp/advsec/start_adv_security.sh -getSafebroConfig");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        CcspTraceError(("%s: fetch safebro config failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
        return ANSC_STATUS_FAILURE;
    }

    FILE *file = fopen(SAFEBRO_CONFIG_FILE_PATH, "r");
    if(file == NULL){
        CcspTraceError(("%s: Error in opening the file.\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    fseek(file, 0, SEEK_END);
    file_length = ftell(file);
    if (file_length < 0) {
        CcspTraceError(("%s: ftell failed\n", __FUNCTION__));
        fclose(file);
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceDebug(("%s: File length: %d\n", __FUNCTION__, file_length));

    fclose(file);

    data = (char *) malloc((file_length+1)*sizeof(char));
    if(data == NULL){
        CcspTraceError(("%s: malloc failed\n", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }
    memset(data, 0, file_length+1);

    if( !advsec_read_from_file(SAFEBRO_CONFIG_FILE_PATH,data, file_length) )
    {
        CcspTraceWarning(("Error in opening safebro config JSON file %s\n", SAFEBRO_CONFIG_FILE_PATH));
        /* CID 190454: Resource leak */
        free(data);
        data = NULL;
        return ANSC_STATUS_FAILURE;
    }
    else if ( strlen(data) != 0)
    {
        json = cJSON_Parse(data);
        if (data != NULL)
        {
            free(data);
            data = NULL;
        }
        if( !json )
        {
            CcspTraceWarning(("json file parser error %s:%d\n", __FUNCTION__,__LINE__));
            return ANSC_STATUS_FAILURE;
        }
        else
        {
            rc1 = strcmp_s("WhitelistMaxEntries", strlen("WhitelistMaxEntries"), paramName, &ind1);
            ERR_CHK(rc1);
            rc2 = strcmp_s("OtmDedupFqdn", strlen("OtmDedupFqdn"), paramName, &ind2);
            ERR_CHK(rc2);
            if( ((rc1 == EOK) && (!ind1)) || ((rc2 == EOK) && (!ind2)) )
            {
                paramLen = (int)strlen(paramName);
                for (i = 0, j = 0; i < paramLen; i++, j++)
                {
                    if(isupper(paramName[i]) && i != 0)
                    {
                        json_key[j] = '_';
                        j++;
                        json_key[j] = tolower(paramName[i]);
                    }
                    else
                    {
                        json_key[j] = paramName[i];
                    }
                }
            }
            else
            {
                rc1 = strcpy_s(json_key, sizeof(json_key), paramName);
                if(rc1 != EOK)
                {
                    ERR_CHK(rc1);
                    return ANSC_STATUS_FAILURE;
                }
            }

            json_key[0]=tolower(json_key[0]);
            parameterObj = cJSON_GetObjectItem( json, json_key );
            if ( NULL != parameterObj)
            {
                if (parameterObj->valuestring)
                {
                    rc1 = strcpy_s(pValue, strlen(parameterObj->valuestring) + 1, parameterObj->valuestring);
                    if(rc1 != EOK)
                    {
                        ERR_CHK(rc1);
                        return ANSC_STATUS_FAILURE;
                    }
                    *pUlSize = AnscSizeOfString(pValue);
                }
                else
                {
                    *puLong = (unsigned long) parameterObj->valueint;
                }
            }
            else
            {
                CcspTraceWarning(("%s - parameterObj is NULL\n", __FUNCTION__ ));
            }
            cJSON_Delete(json);
        }
    }
    else
    {
        CcspTraceWarning(("SAFEBRO_CONFIG_FILE_PATH %s is empty\n", SAFEBRO_CONFIG_FILE_PATH));
        free(data);
        data = NULL;
        return ANSC_STATUS_FAILURE;
    }
    return ANSC_STATUS_SUCCESS;
}

VOID FreeCosaDmAgent(PCOSA_DATAMODEL_AGENT pMyObject)
{
    if (pMyObject)
    {
        if (pMyObject->pAdvSec)
        {
            if (pMyObject->pAdvSec->pSafeBrows) {
                AnscFreeMemory((ANSC_HANDLE)pMyObject->pAdvSec->pSafeBrows);
                pMyObject->pAdvSec->pSafeBrows = NULL;
            }
            if (pMyObject->pAdvSec->pSoftFlowd) {
                AnscFreeMemory((ANSC_HANDLE)pMyObject->pAdvSec->pSoftFlowd);
                pMyObject->pAdvSec->pSoftFlowd = NULL;
            }
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pAdvSec);
            pMyObject->pAdvSec = NULL;
        }
        if (pMyObject->pAdvPC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pAdvPC);
            pMyObject->pAdvPC = NULL;
        }
        if (pMyObject->pPrivProt) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pPrivProt);
            pMyObject->pPrivProt = NULL;
        }
        if (pMyObject->pRabid) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pRabid);
            pMyObject->pRabid = NULL;
        }
        if (pMyObject->pAdvPC_RFC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pAdvPC_RFC);
            pMyObject->pAdvPC_RFC = NULL;
        }
        if (pMyObject->pPrivProt_RFC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pPrivProt_RFC);
            pMyObject->pPrivProt_RFC = NULL;
        }
        if (pMyObject->pDFIcmpv6_RFC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pDFIcmpv6_RFC);
            pMyObject->pDFIcmpv6_RFC = NULL;
        }
        if (pMyObject->pWSDiscoveryAnalysis_RFC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pWSDiscoveryAnalysis_RFC);
            pMyObject->pWSDiscoveryAnalysis_RFC = NULL;
        }
        if (pMyObject->pAdvSecOTM_RFC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pAdvSecOTM_RFC);
            pMyObject->pAdvSecOTM_RFC = NULL;
        }
        if (pMyObject->pAdvSecUserSpace_RFC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pAdvSecUserSpace_RFC);
            pMyObject->pAdvSecUserSpace_RFC = NULL;
        }
        if (pMyObject->pLevl_RFC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pLevl_RFC);
            pMyObject->pLevl_RFC = NULL;
        }
        if (pMyObject->pAdvSecAgent_RFC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pAdvSecAgent_RFC);
            pMyObject->pAdvSecAgent_RFC = NULL;
        }
        if (pMyObject->pAdvSecSafeBrowsing_RFC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pAdvSecSafeBrowsing_RFC);
            pMyObject->pAdvSecSafeBrowsing_RFC = NULL;
        }
        if (pMyObject->pAdvSecCujoTelemetryWiFiFP_RFC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pAdvSecCujoTelemetryWiFiFP_RFC);
            pMyObject->pAdvSecCujoTelemetryWiFiFP_RFC = NULL;
        }
        if (pMyObject->pAdvSecCujoTracer_RFC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pAdvSecCujoTracer_RFC);
            pMyObject->pAdvSecCujoTracer_RFC = NULL;
        }
        if (pMyObject->pAdvSecCujoTelemetry_RFC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pAdvSecCujoTelemetry_RFC);
            pMyObject->pAdvSecCujoTelemetry_RFC = NULL;
        }
        if (pMyObject->pAdvSecSATE_RFC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pAdvSecSATE_RFC);
            pMyObject->pAdvSecSATE_RFC = NULL;
        }
        if (pMyObject->pAdvSecTCPTrackerFilterDevices_RFC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pAdvSecTCPTrackerFilterDevices_RFC);
            pMyObject->pAdvSecTCPTrackerFilterDevices_RFC = NULL;
        }
        if (pMyObject->pAdvWifiDataCollection_RFC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pAdvWifiDataCollection_RFC);
            pMyObject->pAdvWifiDataCollection_RFC = NULL;
        }
        if (pMyObject->pRaptr_RFC) {
            AnscFreeMemory((ANSC_HANDLE)pMyObject->pRaptr_RFC);
            pMyObject->pRaptr_RFC = NULL;
        }
        AnscFreeMemory((ANSC_HANDLE)pMyObject);
        pMyObject = NULL;
    }
}

ANSC_HANDLE
CosaSecurityCreate
    (
        VOID
    )
{
	
	PCOSA_DATAMODEL_AGENT       pMyObject    = (PCOSA_DATAMODEL_AGENT)NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
     */
    pMyObject = (PCOSA_DATAMODEL_AGENT)AnscAllocateMemory(sizeof(COSA_DATAMODEL_AGENT));
    if ( !pMyObject )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pAdvSec = (PCOSA_DATAMODEL_ADVSEC)AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVSEC));
    if ( !pMyObject->pAdvSec )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pAdvSec->pSafeBrows = (PCOSA_DATAMODEL_SB)AnscAllocateMemory(sizeof(COSA_DATAMODEL_SB));
    if ( !pMyObject->pAdvSec->pSafeBrows )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pAdvSec->pSoftFlowd = (PCOSA_DATAMODEL_SOFTFLOWD)AnscAllocateMemory(sizeof(COSA_DATAMODEL_SOFTFLOWD));
    if ( !pMyObject->pAdvSec->pSoftFlowd )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pAdvPC = (PCOSA_DATAMODEL_ADVPARENTALCONTROL)AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVPARENTALCONTROL));
    if ( !pMyObject->pAdvPC )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pPrivProt = (PCOSA_DATAMODEL_PRIVACYPROTECTION)AnscAllocateMemory(sizeof(COSA_DATAMODEL_PRIVACYPROTECTION));
    if ( !pMyObject->pPrivProt )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pRabid = (PCOSA_DATAMODEL_RABID)AnscAllocateMemory(sizeof(COSA_DATAMODEL_RABID));
    if ( !pMyObject->pRabid )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pAdvPC_RFC = (PCOSA_DATAMODEL_ADVPC_RFC)AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVPC_RFC));
    if ( !pMyObject->pAdvPC_RFC )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pPrivProt_RFC = (PCOSA_DATAMODEL_PRIVACYPROTECTION_RFC)AnscAllocateMemory(sizeof(COSA_DATAMODEL_PRIVACYPROTECTION_RFC));
    if ( !pMyObject->pPrivProt_RFC )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pDFIcmpv6_RFC = (PCOSA_DATAMODEL_DEVICEFINGERPRINTICMPv6_RFC)
                                   AnscAllocateMemory(sizeof(COSA_DATAMODEL_DEVICEFINGERPRINTICMPv6_RFC));
    if ( !pMyObject->pDFIcmpv6_RFC )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pWSDiscoveryAnalysis_RFC = (PCOSA_DATAMODEL_WSDISCOVERYANALYSIS_RFC)
                                              AnscAllocateMemory(sizeof(COSA_DATAMODEL_WSDISCOVERYANALYSIS_RFC));
    if ( !pMyObject->pWSDiscoveryAnalysis_RFC )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pAdvSecOTM_RFC = (PCOSA_DATAMODEL_ADVSECOTM_RFC)AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVSECOTM_RFC));
    if ( !pMyObject->pAdvSecOTM_RFC )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pAdvSecUserSpace_RFC = (PCOSA_DATAMODEL_ADVSECUSERSPACE_RFC)AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVSECUSERSPACE_RFC));
    if ( !pMyObject->pAdvSecUserSpace_RFC )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pLevl_RFC = (PCOSA_DATAMODEL_LEVL_RFC)AnscAllocateMemory(sizeof(COSA_DATAMODEL_LEVL_RFC));
    if ( !pMyObject->pLevl_RFC )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pAdvSecAgent_RFC = (PCOSA_DATAMODEL_ADVSECAGENT_RFC)AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVSECAGENT_RFC));
    if ( !pMyObject->pAdvSecAgent_RFC )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pAdvSecSafeBrowsing_RFC = (PCOSA_DATAMODEL_ADVSECSAFEBROWSING_RFC)
                                             AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVSECSAFEBROWSING_RFC));
    if ( !pMyObject->pAdvSecSafeBrowsing_RFC )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pAdvSecCujoTelemetryWiFiFP_RFC = (PCOSA_DATAMODEL_ADVSECCUJOTELEMETRYWIFIFP_RFC)
                                                    AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVSECCUJOTELEMETRYWIFIFP_RFC));
    if ( !pMyObject->pAdvSecCujoTelemetryWiFiFP_RFC )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pAdvSecCujoTracer_RFC = (PCOSA_DATAMODEL_ADVSECCUJOTRACER_RFC)AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVSECCUJOTRACER_RFC));
    if ( !pMyObject->pAdvSecCujoTracer_RFC )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pAdvSecCujoTelemetry_RFC = (PCOSA_DATAMODEL_ADVSECCUJOTELEMETRY_RFC)
                                              AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVSECCUJOTELEMETRY_RFC));
    if ( !pMyObject->pAdvSecCujoTelemetry_RFC )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pAdvSecSATE_RFC = (PCOSA_DATAMODEL_ADVSECSATE_RFC)
                                              AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVSECSATE_RFC));
    if ( !pMyObject->pAdvSecSATE_RFC )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pAdvSecTCPTrackerFilterDevices_RFC = (PCOSA_DATAMODEL_ADVSECTCPTRACKERFILTERDEVICES_RFC)
                                              AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVSECTCPTRACKERFILTERDEVICES_RFC));
    if ( !pMyObject->pAdvSecTCPTrackerFilterDevices_RFC )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pAdvWifiDataCollection_RFC = (PCOSA_DATAMODEL_ADVSECWIFIDATACOLLECTION_RFC)
                                                AnscAllocateMemory(sizeof(COSA_DATAMODEL_ADVSECWIFIDATACOLLECTION_RFC));
    if ( !pMyObject->pAdvWifiDataCollection_RFC )
    {
        goto mem_alloc_failure;
    }

    pMyObject->pRaptr_RFC = (PCOSA_DATAMODEL_RAPTR_RFC)AnscAllocateMemory(sizeof(COSA_DATAMODEL_RAPTR_RFC));
    if ( !pMyObject->pRaptr_RFC )
    {
        goto mem_alloc_failure;
    }

    if (syscfg_init() != 0) {
        CcspTraceError(("%s: syscfg_init error", __FUNCTION__));
    }

    return  (ANSC_HANDLE)pMyObject;

mem_alloc_failure:
    CcspTraceError(("%s exit ERROR \n", __FUNCTION__));
    FreeCosaDmAgent(pMyObject);
    return (ANSC_HANDLE)NULL;
}


ANSC_STATUS
CosaSecurityInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS             returnStatus        = ANSC_STATUS_SUCCESS;
    ULONG                   Value = 0;
    ULONG                   ValueSB = 0;
    ULONG                   ValueSF = 0;
    ULONG                   ValueAPC = 0;
    ULONG                   ValuePP = 0;
    ULONG                   ValueAPC_RFC = 0;
    ULONG                   ValuePP_RFC = 0;
    ULONG                   ValueDFIcmpv6_RFC = 0;
    ULONG                   ValueWSA_RFC = 0;
    ULONG                   ValueASOTM_RFC = 0;
    ULONG                   ValueASUSERSPACE_RFC = 0;
#ifdef WIFI_DATA_COLLECTION
    ULONG                   ValueASWIFIDCL_RFC = 0;
    ULONG                   ValueLEVL_RFC = 0;
#endif
    ULONG                   ValueASAGENT_RFC = 0;
    ULONG                   ValueASSAFEBROWSING_RFC = 0;
    ULONG                   ValueASCUJOTELEMETRYWIFIFP_RFC = 0;
    ULONG                   ValueASCUJOTRACER_RFC = 0;
    ULONG                   ValueASCUJOTELEMETRY_RFC = 0;
    ULONG                   ValueASSATE_RFC = 0;
    ULONG                   ValueASTCPTrackerFilterDevices_RFC = 0;
    ULONG                   ValueRAPTR_RFC = 0;
    ULONG                   ValueRML = 0;
    ULONG                   ValueRMCS = 0;
    ULONG                   ValueRDCS = 0;

     /* Coverity Fix CID:78774,78899  OVERRUN*/
    char modelName[BUFFERSIZE_MAX]={'\0'};
    char firmwareVersion[64]={'\0'};
    char hardwareVersion[BUFFERSIZE_MAX]={'\0'};
    char deviceMac[64]={'\0'};
    char manufacturer[64]={'\0'};
    errno_t rc = -1;

    int ret = RBUS_ERROR_SUCCESS;
    extern rbusHandle_t g_rbus_handle;

    /* Reuse global RBUS handle for event subscriptions */
    rbus_handle = g_rbus_handle;
    if(!rbus_handle)
    {
        CcspTraceError(("CosaSecurityInitialize: RBUS handle not initialized\n"));
        return ANSC_STATUS_FAILURE;
    }
#if !defined(_XER5_PRODUCT_REQ_) && !defined(_SCER11BEL_PRODUCT_REQ_) && !defined(_PLATFORM_BANANAPI_R4_)
#if defined(_COSA_BCM_MIPS_)
    dpoe_mac_address_t tDpoe_Mac;
#else
    CMMGMT_CM_DHCP_INFO dhcpinfo;
#endif
#endif

    if ( platform_hal_PandMDBInit() == 0)
    {
        CcspTraceInfo(("CcspAdvSecurity: PandMDB initiated successfully\n"));
    }
    else
    {
        CcspTraceError(("CcspAdvSecurity: Failed to initiate DB\n"));
    }

#if !defined(_COSA_BCM_MIPS_) && !defined(_XER5_PRODUCT_REQ_) && !defined(_SCER11BEL_PRODUCT_REQ_) && !defined(_PLATFORM_BANANAPI_R4_)
    if ( cm_hal_InitDB() == 0)
    {
        CcspTraceInfo(("CcspAdvSecurity: cm_hal DB initiated successfully\n"));
    }
    else
    {
        CcspTraceError(("CcspAdvSecurity: Failed to initiate cm_hal DB\n"));
    }
#endif

    if ( platform_hal_GetModelName(modelName) == 0)
    {
        CcspTraceInfo(("CcspAdvSecurity: modelName returned from hal:%s\n", modelName));
    }
    else
    {
        CcspTraceError(("CcspAdvSecurity: Unable to get ModelName\n"));
    }

    if ( platform_hal_GetFirmwareName(firmwareVersion, 64) == 0)
    {
        CcspTraceInfo(("CcspAdvSecurity: firmwareVersion returned from hal:%s\n", firmwareVersion));
    }
    else
    {
        CcspTraceError(("CcspAdvSecurity: Unable to get FirmwareName\n"));
    }

    if ( platform_hal_GetHardwareVersion(hardwareVersion) == 0)
    {
        CcspTraceInfo(("CcspAdvSecurity: HardwareVersion returned from hal:%s\n", hardwareVersion));
    }
    else
    {
        CcspTraceError(("CcspAdvSecurity: Unable to get HardwareVersion\n"));
    }
#if (_COSA_BCM_MIPS_ || _COSA_DRG_TPG_ || CONFIG_CISCO)
    if(strlen(CONFIG_VENDOR_NAME) > 0)
    {
        rc = strcpy_s(manufacturer, sizeof(manufacturer), CONFIG_VENDOR_NAME);
        if(rc != EOK)
        {
            ERR_CHK(rc);
        }
        CcspTraceInfo(("CcspAdvSecurity: Manufacturer Name is %s\n", manufacturer));
    }
    else
    {
        CcspTraceError(("CcspAdvSecurity: Unable to get Manufacturer Name\n"));
    }
#endif
#if defined(_COSA_BCM_MIPS_)
    if( dpoe_getOnuId(&tDpoe_Mac) == 0)
    {
        rc = sprintf_s(deviceMac, sizeof(deviceMac), "%02x:%02x:%02x:%02x:%02x:%02x",tDpoe_Mac.macAddress[0], tDpoe_Mac.macAddress[1],
        tDpoe_Mac.macAddress[2], tDpoe_Mac.macAddress[3], tDpoe_Mac.macAddress[4],tDpoe_Mac.macAddress[5]);
        if(rc < EOK)
        {
            ERR_CHK(rc);
            sleep(30);
            exit(0);
        }
        CcspTraceInfo(("CcspAdvSecurity: deviceMac [%s]\n", deviceMac));
    }
    else
    {
        CcspTraceError(("CcspAdvSecurity: Unable to get MACAdress\n"));
        sleep(30);
        exit(0);
    }
#else
    char isEthEnabled[64]={'\0'};
    token_t  token;
    int  ind = -1;
    int fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "advsec", &token);
    if (fd < 0)
    {
        /* Coverity Fix CID : 125132,125510 PRINTF_ARGS */
        CcspTraceError(("CcspAdvSecurity: Failed to get sysevent fd %d\n", fd));
        /* CID 59050: Improper use of negative value */
	/* exit with error code 1 */
        exit(1);
    }

    char deviceMACValue[32] = { '\0' };
    int found = 0;
    if( 0 == syscfg_get( NULL, "eth_wan_enabled", isEthEnabled, sizeof(isEthEnabled)))
    {
        if(isEthEnabled[0] != '\0')
        {
           rc = strcmp_s(isEthEnabled, sizeof(isEthEnabled), "true", &ind);
           ERR_CHK(rc);
           if(((rc == EOK) && (ind == 0)) && sysevent_get(fd, token, "eth_wan_mac", deviceMACValue, sizeof(deviceMACValue)) == 0 && deviceMACValue[0] != '\0')
           {
               found = 1;
           }
        }
    }
    if(found == 1)
    {
        rc = strcpy_s(deviceMac, sizeof(deviceMac), deviceMACValue);
        if(rc != EOK)
        {
            ERR_CHK(rc);
            sysevent_close(fd, token);
            sleep(30);
            exit(0);
        }
        CcspTraceInfo(("CcspAdvSecurity: deviceMac [%s]\n", deviceMac));
    }
    #if !defined(_XER5_PRODUCT_REQ_) && !defined(_SCER11BEL_PRODUCT_REQ_) && !defined(_PLATFORM_BANANAPI_R4_)
    else if (cm_hal_GetDHCPInfo(&dhcpinfo) == 0 )
    {
          rc = strcmp_s(dhcpinfo.MACAddress, sizeof(dhcpinfo.MACAddress), ADVSEC_DEFAULT_CM_MAC, &ind);
          ERR_CHK(rc);
          if((rc == EOK) && (ind != 0))
          {
              rc = strcpy_s(deviceMac, sizeof(deviceMac), dhcpinfo.MACAddress);
              if(rc != EOK)
              {
                  ERR_CHK(rc);
                  sysevent_close(fd, token);
                  sleep(30);
                  exit(0);
              }
              CcspTraceInfo(("CcspAdvSecurity: deviceMac [%s]\n", deviceMac));
          }
          else
          {
              CcspTraceWarning(("CcspAdvSecurity: Unable to get MACAdress or HAL not ready\n"));
              sysevent_close(fd, token);
              sleep(30);
              exit(0);
          }
    }
    #endif
    else
    {
        CcspTraceWarning(("CcspAdvSecurity: Unable to get MACAdress or HAL not ready\n"));
        sysevent_close(fd, token);
        sleep(30);
        exit(0);
    }
    /* close this session with syseventd */
    sysevent_close(fd, token);
#endif

    advsec_create_dir(ADVSEC_CONFIG_PARAMS_DIR_PATH);
    if ( ! (advsec_write_to_file(ADVSEC_CONFIG_PARAMS_MODEL_PATH,modelName) &&
        advsec_write_to_file(ADVSEC_CONFIG_PARAMS_MNCF_PATH,manufacturer) &&
        advsec_write_to_file(ADVSEC_CONFIG_PARAMS_FW_PATH,firmwareVersion) &&
        advsec_write_to_file(ADVSEC_CONFIG_PARAMS_HW_PATH,hardwareVersion) &&
        advsec_write_to_file(ADVSEC_CONFIG_PARAMS_CM_MAC_PATH,deviceMac)) )
    {
       CcspTraceError(("CcspAdvSecurity: advsec_write_to_file failed\n"));
    }

    CcspTraceInfo(("CcspAdvSecurity: advsec_webconfig_init \n"));
    advsec_webconfig_init();

    CosaGetSysCfgUlong(g_DeviceFingerPrintEnabled, &Value);
    CosaGetSysCfgUlong(g_AdvSecuritySBEnabled, &ValueSB);
    CosaGetSysCfgUlong(g_AdvSecuritySFEnabled, &ValueSF);
    CosaGetSysCfgUlong(g_AdvParentalControl, &ValueAPC);
    CosaGetSysCfgUlong(g_PrivacyProtection, &ValuePP);
    CosaGetSysCfgUlong(g_AdvParentalControlEnabled, &ValueAPC_RFC);
    CosaGetSysCfgUlong(g_PrivacyProtectionEnabled, &ValuePP_RFC);
    CosaGetSysCfgUlong(g_DeviceFingerPrintICMPv6Enabled, &ValueDFIcmpv6_RFC);
    CosaGetSysCfgUlong(g_WSDiscoveryAnalysisEnabled, &ValueWSA_RFC);
    CosaGetSysCfgUlong(g_AdvSecOTMEnabled, &ValueASOTM_RFC);
    CosaGetSysCfgUlong(g_AdvSecUserSpaceEnabled, &ValueASUSERSPACE_RFC);
#ifdef WIFI_DATA_COLLECTION
    CosaGetSysCfgUlong(g_AdvWifiDataCollection, &ValueASWIFIDCL_RFC);
    CosaGetSysCfgUlong(g_LevlEnabled, &ValueLEVL_RFC);
#endif
    CosaGetSysCfgUlong(g_AdvSecAgentEnabled, &ValueASAGENT_RFC);
    CosaGetSysCfgUlong(g_AdvSecSafeBrowsingEnabled, &ValueASSAFEBROWSING_RFC);
    CosaGetSysCfgUlong(g_AdvSecCujoTelemetryWiFiFPEnabled, &ValueASCUJOTELEMETRYWIFIFP_RFC);
    CosaGetSysCfgUlong(g_AdvSecCujoTracerEnabled, &ValueASCUJOTRACER_RFC);
    CosaGetSysCfgUlong(g_AdvSecCujoTelemetryEnabled, &ValueASCUJOTELEMETRY_RFC);
    CosaGetSysCfgUlong(g_AdvSecSATEEnabled, &ValueASSATE_RFC);
    CosaGetSysCfgUlong(g_AdvSecTCPTrackerFilterDevicesEnabled, &ValueASTCPTrackerFilterDevices_RFC);
    CosaGetSysCfgUlong(g_RaptrEnabled, &ValueRAPTR_RFC);
    CosaGetSysCfgUlong(g_RabidMemoryLimit, &ValueRML);
    CosaGetSysCfgUlong(g_RabidMacCacheSize, &ValueRMCS);
    CosaGetSysCfgUlong(g_RabidDNSCacheSize, &ValueRDCS);

    g_pAdvSecAgent->bEnable = Value;
    g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable = ValueSB;
    g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable = ValueSF;
    g_pAdvSecAgent->pAdvPC->bEnable = ValueAPC;
    g_pAdvSecAgent->pPrivProt->bEnable = ValuePP;
    g_pAdvSecAgent->pAdvPC_RFC->bEnable = ValueAPC_RFC;
    g_pAdvSecAgent->pPrivProt_RFC->bEnable = ValuePP_RFC;
    g_pAdvSecAgent->pDFIcmpv6_RFC->bEnable = ValueDFIcmpv6_RFC;
    g_pAdvSecAgent->pWSDiscoveryAnalysis_RFC->bEnable = ValueWSA_RFC;
    g_pAdvSecAgent->pAdvSecOTM_RFC->bEnable = ValueASOTM_RFC;
    if (ValueASUSERSPACE_RFC == 0)
    {
        // Enable user-space feature
        returnStatus = CosaSetSysCfgUlong(g_AdvSecUserSpaceEnabled, 1);
        if (returnStatus != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: syscfg_set failure\n", __FUNCTION__));
        }
        g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable = TRUE;
        CcspTraceInfo(("AdvSecUserSpace_RFCEnable:TRUE\n"));
    }
    else
    {
        g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable = ValueASUSERSPACE_RFC;
    }
#ifdef WIFI_DATA_COLLECTION
    g_pAdvSecAgent->pLevl_RFC->bEnable = ValueLEVL_RFC;

    // If Levl RFC is enabled
    if (g_pAdvSecAgent->pLevl_RFC->bEnable == TRUE)
    {
        // Enable Device.WiFi.Levl if disabled
        if (Wifi_Get_Status(LEVL_DML) == FALSE)
        {
            returnStatus = Wifi_SetParameterValue(LEVL_DML, TRUE);
            if (returnStatus != ANSC_STATUS_SUCCESS)
            {
                CcspTraceError(("%s:%d %s set failed\n", __FUNCTION__, __LINE__, LEVL_DML));
            }
            else
            {
                sleep(1);
            }
        }

        if (Wifi_Get_Status(LEVL_DML) == TRUE)
        {
            // Enable wifidatacollection feature
            returnStatus = CosaSetSysCfgUlong(g_AdvWifiDataCollection, 1);
            if (returnStatus != ANSC_STATUS_SUCCESS)
            {
                CcspTraceError(("%s: syscfg_set failure\n", __FUNCTION__));
            }
            ValueASWIFIDCL_RFC = TRUE;
            CcspTraceInfo(("AdvSecWifiDataCollection_RFCEnable:TRUE\n"));
        }
        else
        {
            CcspTraceError(("%s:%d %s is false even after setting to true\n", __FUNCTION__, __LINE__, LEVL_DML));
        }
    }

    if ((g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable == TRUE) &&
        (Wifi_Get_Status(LEVL_DML) == TRUE))
    {
        g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable = ValueASWIFIDCL_RFC;
    }
    else
    {
        g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable = FALSE;
    }
#else
    g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable = FALSE;
    g_pAdvSecAgent->pLevl_RFC->bEnable = FALSE;
#endif
    g_pAdvSecAgent->pAdvSecAgent_RFC->bEnable = ValueASAGENT_RFC;
    g_pAdvSecAgent->pAdvSecSafeBrowsing_RFC->bEnable = ValueASSAFEBROWSING_RFC;
    g_pAdvSecAgent->pAdvSecCujoTelemetryWiFiFP_RFC->bEnable = ValueASCUJOTELEMETRYWIFIFP_RFC;
    g_pAdvSecAgent->pAdvSecCujoTracer_RFC->bEnable = ValueASCUJOTRACER_RFC;
    g_pAdvSecAgent->pAdvSecCujoTelemetry_RFC->bEnable = ValueASCUJOTELEMETRY_RFC;
    g_pAdvSecAgent->pAdvSecSATE_RFC->bEnable = ValueASSATE_RFC;
    g_pAdvSecAgent->pAdvSecTCPTrackerFilterDevices_RFC->bEnable = ValueASTCPTrackerFilterDevices_RFC;
    g_pAdvSecAgent->pRaptr_RFC->bEnable = ValueRAPTR_RFC;
    g_pAdvSecAgent->pRabid->uMemoryLimit = ValueRML;
    g_pAdvSecAgent->pRabid->uMacCacheSize = ValueRMCS;
    g_pAdvSecAgent->pRabid->uDNSCacheSize = ValueRDCS;

    Advsec_SetDefaultsUrl();

    if(Value == 1)
    {
        returnStatus = CosaAdvSecInit();
        if ( returnStatus != ANSC_STATUS_SUCCESS )
        {
            CcspTraceError(("%s EXIT Error\n", __FUNCTION__));
        }
    }
    else
    {
        CcspTraceWarning(("\nDevice_Finger_Printing_enabled:false\n"));
    }

    CosaAdvSecGetLoggingPeriod();
    CosaAdvSecGetLogLevel();
    CosaAdvSecGetLookupTimeout();
    rc = strcpy_s(prevWanIfname, sizeof(prevWanIfname), ADVSEC_PRIMARY_WAN_IF_NAME);
    ERR_CHK(rc);
    advsec_start_logger_thread();
    advsec_handle_sysevent_async();

#ifdef WAN_FAILOVER_SUPPORTED
    ret = rbusEvent_Subscribe(rbus_handle, "Device.X_RDK_WanManager.CurrentActiveInterface", eventReceiveHandler, NULL, 0);
    if(ret != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("AdvSecurityEventConsumer: rbusEvent_Subscribe failed: %d\n", ret));
        return ANSC_STATUS_FAILURE;
    }
#endif
#ifdef WIFI_DATA_COLLECTION
    ret = rbusEvent_Subscribe(rbus_handle, LEVL_DML, wifiEventReceiveHandler, NULL, 0);
    if(ret != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("AdvSecurityEventConsumer: rbusEvent_Subscribe %s failed: %d\n", LEVL_DML, ret));
        return ANSC_STATUS_FAILURE;
    }
#endif
    return returnStatus;
}


ANSC_STATUS
CosaSecurityRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PCOSA_DATAMODEL_AGENT            pMyObject    = (PCOSA_DATAMODEL_AGENT)hThisObject;

    /* Remove self */
    FreeCosaDmAgent(pMyObject);
    /* Don't close rbus_handle here - it's owned by g_rbus_handle in advsec_rbus_handlers.c */
    CcspTraceInfo(("%s EXIT \n", __FUNCTION__));

    return returnStatus;
}

ANSC_STATUS CosaGetSysCfgUlong(char* setting, ULONG* value)
{
    char buf[32] = {0};
    ANSC_STATUS         ret = ANSC_STATUS_SUCCESS;

    if(ANSC_STATUS_SUCCESS == (ret = syscfg_get( NULL, setting, buf, sizeof(buf))))
    {
        *value = atol(buf);
    }
    else
    {
        CcspTraceError(("syscfg_get failed\n"));
    }

    return ret;
}

ANSC_STATUS CosaSetSysCfgUlong(char* setting, ULONG value)
{
    ANSC_STATUS         ret = ANSC_STATUS_SUCCESS;
    char buf[32] = {0};
    errno_t rc = -1;

    rc = sprintf_s(buf, sizeof(buf), "%lu", value);
    if(rc < EOK)
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }
    if(ANSC_STATUS_SUCCESS != (ret = syscfg_set( NULL, setting, buf)))
    {
        CcspTraceError(("syscfg_set failed\n"));
    }
    else
    {
        if (ANSC_STATUS_SUCCESS != (ret = syscfg_commit()))
        {
            CcspTraceError(("syscfg_commit failed\n"));
        }
    }

    return ret;
}

#ifdef WIFI_DATA_COLLECTION
ANSC_STATUS CosaAdvWifiDataConsumerInit(void)
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;

    returnStatus = cujoagent_wifidatacollection_init(g_cujoagent_dcl);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
         CcspTraceError(("%s: failed to initialize wifi data collection\n", __FUNCTION__));
    }

    return returnStatus;
}

ANSC_STATUS CosaAdvWifiDataConsumerDeInit(void)
{
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;

    returnStatus = cujoagent_wifidatacollection_deinit(g_cujoagent_dcl, TRUE);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
         CcspTraceError(("%s: failed to deinitialize wifi data collection\n", __FUNCTION__));
    }

    return returnStatus;
}

ANSC_STATUS CosaAdvWifiDataCollectionInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    if ((Wifi_Get_Status(LEVL_DML) == TRUE) &&
        (g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable == TRUE) &&
        (wifidcl_init_precheck() == RBUS_ERROR_SUCCESS))
    {
        returnStatus = CosaAdvWifiDataConsumerInit();
        if (ANSC_STATUS_SUCCESS != returnStatus)
        {
            return returnStatus;
        }
        rc = v_secure_system("touch " ADVSEC_WIFIDCL_INIT_FILE_PATH);
        if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
            CcspTraceWarning(("Failed to touch %s", ADVSEC_WIFIDCL_INIT_FILE_PATH));
        }

        returnStatus = CosaSetSysCfgUlong(g_AdvWifiDataCollection, 1);
        if (ANSC_STATUS_SUCCESS != returnStatus)
        {
            CcspTraceWarning(("%s: syscfg_set failure.", __FUNCTION__));
            return returnStatus;
        }

        g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable = TRUE;

        rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enableWifiDCL &");
        if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
           CcspTraceError(("%s: -enableWifiDCL failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
        }

        CcspTraceWarning(("AdvSecWifiDataCollection_RFCEnable:TRUE\n"));
    }
    else
    {
        CcspTraceWarning(("Levl RFC not enabled\n"));
        returnStatus = ANSC_STATUS_FAILURE;
    }
    return returnStatus;
}

ANSC_STATUS CosaAdvWifiDataCollectionDeInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaAdvWifiDataConsumerDeInit();
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        return returnStatus;
    }
    rc = v_secure_system("rm " ADVSEC_WIFIDCL_INIT_FILE_PATH);
    if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
        CcspTraceWarning(("Failed to remove %s", ADVSEC_WIFIDCL_INIT_FILE_PATH));
    }

    returnStatus = CosaSetSysCfgUlong(g_AdvWifiDataCollection, 0);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning(("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable = FALSE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disableWifiDCL &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: -disableWifiDCL failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecWifiDataCollection_RFCEnable:FALSE\n"));
    return returnStatus;
}
#endif

ANSC_STATUS CosaAdvSecInit()
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    int ret = 0;
#ifdef WIFI_DATA_COLLECTION
    errno_t rc = -1;

    if ((g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable == 1) &&
        (Wifi_Get_Status(LEVL_DML) == TRUE) &&
        (wifidcl_init_precheck() == RBUS_ERROR_SUCCESS))
    {
        returnStatus = CosaAdvWifiDataConsumerInit();
        if (returnStatus != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: failed to initialize wifi data collection\n", __FUNCTION__));
            g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable = 0;
        }
        else
        {
            rc = v_secure_system("touch " ADVSEC_WIFIDCL_INIT_FILE_PATH);
            if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
            {
                CcspTraceWarning(("Failed to touch %s", ADVSEC_WIFIDCL_INIT_FILE_PATH));
            }
        }
    }
    else
    {
        // To avoid de-initialize wifi data collection
        g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable = 0;
    }
#endif
    ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enable &");
    if(ret !=0)
    {
         CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
    }

    g_pAdvSecAgent->bEnable = TRUE;
    returnStatus = CosaSetSysCfgUlong(g_DeviceFingerPrintEnabled, 1);
    return returnStatus;
}

ANSC_STATUS CosaAdvSecDeInit()
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    int ret = 0;
#ifdef WIFI_DATA_COLLECTION
    errno_t rc = -1;

    if (g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable == 1)
    {
        returnStatus = CosaAdvWifiDataConsumerDeInit();
        if (returnStatus != ANSC_STATUS_SUCCESS)
        {
            CcspTraceWarning(("%s: failed to deinitialize wifi data collection\n", __FUNCTION__));
        }
        else
        {
            rc = v_secure_system("rm " ADVSEC_WIFIDCL_INIT_FILE_PATH);
            if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
            {
                CcspTraceWarning(("Failed to remove %s", ADVSEC_WIFIDCL_INIT_FILE_PATH));
            }
        }
    }
#endif
    ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disable &");
    if(ret !=0)
    {
          CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
    }

    g_pAdvSecAgent->bEnable = FALSE;

    returnStatus = CosaSetSysCfgUlong(g_DeviceFingerPrintEnabled, 0);
    return returnStatus;
}

static void *advsec_logger_th(void *arg)
{
    UNREFERENCED_PARAMETER(arg);
    ULONG remaining_time;
    int ret = 0;
    pthread_mutex_lock(&logMutex);
    remaining_time = g_pAdvSecAgent->ulLoggingPeriod;
    pthread_mutex_unlock(&logMutex);
    while(1)
    {
        if ( WaitForLoggerTimeout(60 * ADVSEC_MIN_LOG_TIMEOUT) )
        {
            remaining_time = remaining_time - ADVSEC_MIN_LOG_TIMEOUT;

            if ( remaining_time < ADVSEC_MIN_LOG_TIMEOUT && remaining_time != 0 )
            {
                if ( WaitForLoggerTimeout(60 * remaining_time) )
                {
                    remaining_time = 0;
                }
                else
                {
                    pthread_mutex_lock(&logMutex);
                    remaining_time = g_pAdvSecAgent->ulLoggingPeriod;
                    pthread_mutex_unlock(&logMutex);
                }
            }

            if ( remaining_time == 0 )
            {
                pthread_mutex_lock(&logMutex);
                remaining_time = g_pAdvSecAgent->ulLoggingPeriod;
                pthread_mutex_unlock(&logMutex);
            }

            ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/advsec_log_fp_status.sh check_status &");
            if(ret !=0)
            {
                 CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }
            ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/advsec_cpu_mem_recovery.sh &");
            if(ret !=0)
            {
                 CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }

        }
        else
        {
            pthread_mutex_lock(&logMutex);
            remaining_time = g_pAdvSecAgent->ulLoggingPeriod;
            pthread_mutex_unlock(&logMutex);
        }
    }
    return NULL;
}

static void advsec_start_logger_thread(void)
{
    int err;
    pthread_t logger_thread;

    if (!Is_Device_Finger_Print_Enabled())
    {
       CcspTraceWarning(("%s: DeviceFingerPrintEnabled:%d is not enabled!\n",__FUNCTION__, Is_Device_Finger_Print_Enabled()));
    }
    else
    {
      CcspTraceWarning(("%s: DeviceFingerPrintEnabled:%d is enabled, start the logger thread\n",__FUNCTION__, Is_Device_Finger_Print_Enabled()));
      err = pthread_create(&logger_thread, NULL, advsec_logger_th, NULL);
      if(0 != err)
      {
          CcspTraceError(("%s: create logger thread error!\n", __FUNCTION__));
      }
    }
}

ANSC_STATUS CosaAdvSecStartFeatures(advsec_feature_type type)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    int ret =0;

    if (Is_Device_Finger_Print_Enabled() && !Is_Device_Finger_Print_Enabled_Completed())
    {
       CcspTraceWarning(("%s Device finger print is enabled but not completed yet!\n",__FUNCTION__));
       return ANSC_STATUS_FAILURE;
    }

    if(type == ADVSEC_SAFEBROWSING)
    {
        returnStatus = CosaSetSysCfgUlong(g_AdvSecuritySBEnabled, 1);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;
        g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable = TRUE;
    }

    if(type == ADVSEC_SOFTFLOWD)
    {
	returnStatus = CosaSetSysCfgUlong(g_AdvSecuritySFEnabled, 1);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;
 	g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable = TRUE;
    }

    if(type == ADVSEC_ALL)
    {
        returnStatus = CosaSetSysCfgUlong(g_AdvSecuritySBEnabled, 1);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;
        g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable = TRUE;

        returnStatus = CosaSetSysCfgUlong(g_AdvSecuritySFEnabled, 1);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;
        g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable = TRUE;
        g_pAdvSecAgent->pAdvSec->bEnable = TRUE;
    }

    g_pAdvSecAgent->bEnable = TRUE;

    switch (type)
    {
        case ADVSEC_SAFEBROWSING:
        if(Is_Device_Finger_Print_Enabled())
        {
            ret = v_secure_system( TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -start sb null &");
            if(ret !=0)
            {
                 CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }

        }
        else
        {
            ret = v_secure_system( TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enable sb null &");
            if(ret !=0)
            {
                 CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }

        }
        break;

        case ADVSEC_SOFTFLOWD:
        if(Is_Device_Finger_Print_Enabled())
        {
            ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -start null sf &");
            if(ret !=0)
            {
                 CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }

        }
        else
        {
            ret = v_secure_system( TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enable null sf &");
            if(ret !=0)
            {
                 CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }

        }
        break;

        case ADVSEC_ALL:
        if(Is_Device_Finger_Print_Enabled())
        {
            ret = v_secure_system( TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -start sb sf &");
            if(ret !=0)
            {
                 CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }

        }
        else
        {
            ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enable sb sf &");
            if(ret !=0)
            {
                 CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }

        }
        break;

        default:
            return ANSC_STATUS_FAILURE;
        break;
    }

    return returnStatus;
}

ANSC_STATUS CosaAdvSecStopFeatures(advsec_feature_type type)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    int ret =0;
 
    if(type == ADVSEC_SAFEBROWSING)
    {
        returnStatus = CosaSetSysCfgUlong(g_AdvSecuritySBEnabled, 0);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;
        g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable = FALSE;
    }

    if(type == ADVSEC_SOFTFLOWD)
    {
	returnStatus = CosaSetSysCfgUlong(g_AdvSecuritySFEnabled, 0);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;
	g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable = FALSE;
    }

    if(type == ADVSEC_ALL)
    {
        returnStatus = CosaSetSysCfgUlong(g_AdvSecuritySBEnabled, 0);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;
        g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable = FALSE;

        returnStatus = CosaSetSysCfgUlong(g_AdvSecuritySFEnabled, 0);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;
        g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable = FALSE;
        g_pAdvSecAgent->pAdvSec->bEnable = FALSE;
    }

    switch (type)
    {
        case ADVSEC_SAFEBROWSING:
        if(Is_Device_Finger_Print_Enabled())
        {
            ret = v_secure_system( TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -stop sb null &");
            if(ret !=0)
            {
                 CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }

        }
        else
        {
            ret = v_secure_system( TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disable &");
            if(ret !=0)
            {
                 CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }

         }
        break;

        case ADVSEC_SOFTFLOWD:
        if(Is_Device_Finger_Print_Enabled())
        {
            ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -stop null sf &");
            if(ret !=0)
            {
                 CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }

        }
        else
        {
            ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disable &");
            if(ret !=0)
            {
                 CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }

        }
        break;
        case ADVSEC_ALL:
        if(Is_Device_Finger_Print_Enabled())
        {
            ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -stop sb sf &");
            if(ret !=0)
            {
                 CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }

        }
        else
        {
            ret = v_secure_system( TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disable &");
            if(ret !=0)
            {
                 CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }

        }

        break;

        default:
            return returnStatus;
        break;
    }
    return returnStatus;
}

ANSC_STATUS CosaStartAdvParentalControl(BOOL update_status)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    int ret = 0;

    if (!Is_Agent_Initialization_Completed())
    {
       CcspTraceWarning(("%s Agent is not initialized yet!\n",__FUNCTION__));
       return ANSC_STATUS_FAILURE;
    }

    if (update_status)
    {
        returnStatus = CosaSetSysCfgUlong(g_AdvParentalControl, 1);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;

        g_pAdvSecAgent->pAdvPC->bEnable = TRUE;
    }
    
    ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -startAdvPC &");
    if(ret !=0)
    {
         CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
    }


    return returnStatus;
}

ANSC_STATUS CosaStopAdvParentalControl(BOOL update_status)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    int ret = 0;

    if (!Is_Agent_Initialization_Completed())
    {
       CcspTraceWarning(("%s Agent is not initialized yet!\n",__FUNCTION__));
       return ANSC_STATUS_FAILURE;
    }

    if (update_status)
    {
        returnStatus = CosaSetSysCfgUlong(g_AdvParentalControl, 0);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;

        g_pAdvSecAgent->pAdvPC->bEnable = FALSE;
    }
    ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -stopAdvPC &");
    if(ret !=0)
    {
         CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
    }


    return returnStatus;
}

ANSC_STATUS CosaStartPrivacyProtection(BOOL update_status)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    int ret = 0;

    if (!Is_Agent_Initialization_Completed())
    {
       CcspTraceWarning(("%s Agent is not initialized yet!\n",__FUNCTION__));
       return ANSC_STATUS_FAILURE;
    }

    if (update_status)
    {
        returnStatus = CosaSetSysCfgUlong(g_PrivacyProtection, 1);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;

        g_pAdvSecAgent->pPrivProt->bEnable = TRUE;
    }
    ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -startPrivProt &");
    if(ret !=0)
    {
          CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
    }


    return returnStatus;
}

ANSC_STATUS CosaStopPrivacyProtection(BOOL update_status)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    int ret = 0;

    if (!Is_Agent_Initialization_Completed())
    {
       CcspTraceWarning(("%s Agent is not initialized yet!\n",__FUNCTION__));
       return ANSC_STATUS_FAILURE;
    }

    if (update_status)
    {
        returnStatus = CosaSetSysCfgUlong(g_PrivacyProtection, 0);
        if (ANSC_STATUS_SUCCESS != returnStatus)
            return returnStatus;

        g_pAdvSecAgent->pPrivProt->bEnable = FALSE;
    }
    ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -stopPrivProt &");
    if(ret !=0)
    {
         CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
    }

    return returnStatus;
}

static ANSC_STATUS advsec_update_feature_status(char *syscfg , BOOL new_val, BOOL *curr_val)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;

    if ( new_val != *curr_val )
    {
         returnStatus = CosaSetSysCfgUlong(syscfg, new_val);
         if ( returnStatus == ANSC_STATUS_SUCCESS )
             *curr_val = new_val;
    }

    return returnStatus;
}

int advsec_webconfig_handle_blob(advsecurityparam_t *feature)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    int ret =0;
    CcspTraceInfo(("Entering advsec_handle_webconfig_blob\n"));

    if ( feature->fingerprint_enable == g_pAdvSecAgent->bEnable && ! g_pAdvSecAgent->bEnable )
        return ADVSEC_FAILURE;

    returnStatus = advsec_update_feature_status(g_AdvSecuritySBEnabled, feature->safebrowsing_enable, &g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable);
    if ( returnStatus != ANSC_STATUS_SUCCESS )
         return SYSCFG_FAILURE;

    returnStatus = advsec_update_feature_status(g_AdvSecuritySFEnabled, feature->softflowd_enable, &g_pAdvSecAgent->pAdvSec->pSoftFlowd->bEnable);
    if ( returnStatus != ANSC_STATUS_SUCCESS )
         return SYSCFG_FAILURE;

    returnStatus = advsec_update_feature_status(g_AdvParentalControl, feature->parental_control_activate, &g_pAdvSecAgent->pAdvPC->bEnable);
    if ( returnStatus != ANSC_STATUS_SUCCESS )
         return SYSCFG_FAILURE;

    returnStatus = advsec_update_feature_status(g_PrivacyProtection, feature->privacy_protection_activate, &g_pAdvSecAgent->pPrivProt->bEnable);
    if ( returnStatus != ANSC_STATUS_SUCCESS )
         return SYSCFG_FAILURE;

    if ( feature->fingerprint_enable != g_pAdvSecAgent->bEnable )
    {
        if ( feature->fingerprint_enable )
            returnStatus = CosaAdvSecInit();
        else
            returnStatus = CosaAdvSecDeInit();

        if ( returnStatus != ANSC_STATUS_SUCCESS )
            return SYSCFG_FAILURE;
    }
    else
    {
        ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -configure_features &");
        if(ret !=0)
        {
              CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
        }

    }

    CcspTraceInfo(("Done advsec_handle_webconfig_blob\n"));
    return BLOB_EXEC_SUCCESS;
}

ANSC_STATUS CosaAdvSecGetLoggingPeriod()
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    ULONG value = ADVSEC_DEFAULT_LOG_TIMEOUT;
    returnStatus = CosaGetSysCfgUlong(g_DeviceFingerPrintLogginPeriod, &value);

    /* CID 135645: Data race condition */
    if ( returnStatus == ANSC_STATUS_SUCCESS )
    {
        pthread_mutex_lock(&logMutex);
        g_pAdvSecAgent->ulLoggingPeriod = value;
        pthread_mutex_unlock(&logMutex);
    }
    return returnStatus;
}

ANSC_STATUS CosaAdvSecSetLoggingPeriod(ULONG value)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    returnStatus = CosaSetSysCfgUlong(g_DeviceFingerPrintLogginPeriod, value);
    if ( returnStatus == ANSC_STATUS_SUCCESS )
    {
        pthread_mutex_lock(&logMutex);
        g_pAdvSecAgent->ulLoggingPeriod = value;
        logReady = TRUE;
        pthread_cond_signal(&logCond);
        pthread_mutex_unlock(&logMutex);
    }
    return returnStatus;
}

ANSC_STATUS CosaAdvSecGetLogLevel()
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    ULONG value = ADVSEC_LogLevel_WARN;
    returnStatus = CosaGetSysCfgUlong(g_DeviceFingerPrintLogLevel, &value);
    g_pAdvSecAgent->ulLogLevel = value;
    return returnStatus;
}

ANSC_STATUS CosaAdvSecSetLogLevel(ULONG value)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    int ret = 0;

    returnStatus = CosaSetSysCfgUlong(g_DeviceFingerPrintLogLevel, value);
    if ( returnStatus == ANSC_STATUS_SUCCESS )
    {
        g_pAdvSecAgent->ulLogLevel = value;
        ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -agentloglevel %lu &", value);
        if(ret !=0)
        {
            CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
        }
        CcspTraceInfo(("CosaAdvSecSetLogLevel: success\n"));
    }
    else
    {
        CcspTraceError(("CosaAdvSecSetLogLevel: failed\n"));
    }
    return returnStatus;
}

ANSC_STATUS CosaAdvSecGetLookupTimeout()
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    ULONG value = ADVSEC_DEFAULT_LOOKUP_TIMEOUT;
    returnStatus = CosaGetSysCfgUlong(g_AdvSecurityLookupTimeout, &value);
    g_pAdvSecAgent->pAdvSec->pSafeBrows->ulLookupTimeout = value;
    return returnStatus;
}

ANSC_STATUS CosaAdvSecSetCustomURL(char* pString)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    returnStatus = CosaSetSysCfgString(g_AdvSecCustomEndpointURL, pString);
    return returnStatus;
}

ANSC_STATUS CosaAdvSecGetCustomURL(char* pValue, PULONG pUlSize)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    returnStatus = CosaGetSysCfgString(g_AdvSecCustomEndpointURL, pValue, pUlSize);
    return returnStatus;
}

ANSC_STATUS CosaAdvSecSetLookupTimeout(ULONG value)
{
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    int ret = 0;
    returnStatus = CosaSetSysCfgUlong(g_AdvSecurityLookupTimeout, value);
    if ( returnStatus == ANSC_STATUS_SUCCESS )
    {
        g_pAdvSecAgent->pAdvSec->pSafeBrows->ulLookupTimeout = value;
        if (g_pAdvSecAgent->pAdvSec->pSafeBrows->bEnable == TRUE)
        {
            ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -start sb null &");
            if(ret !=0)
            {
                 CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }

        }
    }
    else
    {
        CcspTraceError(("CosaAdvSecSetLookupTimeout: failed\n"));
    }
    return returnStatus;
}

ULONG CosaAdvSecGetLookupTimeoutExceededCount()
{
    ULONG lcount = 0;
    FILE *fp;
    char buf[COMMAND_MAX] = {0};

    fp = fopen(ADVSEC_LOOKUP_EXCEED_COUNT_FILE, "r");
    if ( fp != NULL)
    {
        fgets(buf, COMMAND_MAX, (FILE*)fp);
        fclose(fp);
        lcount = atol(buf);
    }

    return lcount;
}

static BOOL AdvsecSysEventHandlerStarted=FALSE;
static int sysevent_fd = 0;
static token_t sysEtoken;
static async_id_t async_id[4];

enum {SYS_EVENT_ERROR=-1, SYS_EVENT_OK, SYS_EVENT_TIMEOUT, SYS_EVENT_HANDLE_EXIT, SYS_EVENT_RECEIVED=0x10};

/*
 * Initialize sysevnt
 *   return 0 if success and -1 if failure.
 */
int advsec_sysevent_init(void)
{
    int rc;

    sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "advsec", &sysEtoken);
    if (!sysevent_fd) {
        return(SYS_EVENT_ERROR);
    }

    /*you can register the event as you want*/

    //register bridge mode event
    sysevent_set_options(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_BRIDGE_MODE_EVENT, TUPLE_FLAG_EVENT);
    rc = sysevent_setnotification(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_BRIDGE_MODE_EVENT, &async_id[0]);
    if (rc) {
       return(SYS_EVENT_ERROR);
    }

    //register host to IP address
    sysevent_set_options(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_CLOUD_HOST_IP, TUPLE_FLAG_EVENT);
    rc = sysevent_setnotification(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_CLOUD_HOST_IP, &async_id[1]);
    if (rc) {
       return(SYS_EVENT_ERROR);
    }

    //register MAP-T config change event
    sysevent_set_options(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_MAP_T_CONFIG_CHANGED_EVENT, TUPLE_FLAG_EVENT);
    rc = sysevent_setnotification(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_MAP_T_CONFIG_CHANGED_EVENT, &async_id[2]);
    if (rc) {
       return(SYS_EVENT_ERROR);
    }

    //register Current Wan ifname change event
    sysevent_set_options(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_CURRENT_WAN_IFNAME_EVENT, TUPLE_FLAG_EVENT);
    rc = sysevent_setnotification(sysevent_fd, sysEtoken, ADVSEC_SYSEVENT_CURRENT_WAN_IFNAME_EVENT, &async_id[3]);
    if (rc) {
       return(SYS_EVENT_ERROR);
    }

    return(SYS_EVENT_OK);
}

/*
* Sysevent handler.
*/
void advsec_handle_sysevent_notification(char *event, char *val)
{
    enum advSysEvent_e type;
    int ret = 0;
    errno_t rc = -1;
    int ind    = -1;

    if(!event || !val)
        return;

    CcspTraceWarning(("CcspAdvSecurity: Received notification event:val %s:%s\n", event,val));

    if(get_advSysEvent_type_from_name(event, &type))
    {
        if(type == SYSEVENT_BRIDGE_MODE_EVENT)
        {
            if((val[0] == '0') && (val[1] == '\0'))
            {
                CcspTraceWarning(("CcspAdvSecurity: Received Bridge Mode Off\n"));
                ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enable &");
                if(ret !=0)
                {
                      CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
                }

            }

#ifndef _XF3_PRODUCT_REQ_
            if((val[0] == '2') && (val[1] == '\0'))
#else
            if((val[0] == '3') && (val[1] == '\0'))
#endif
            {
                CcspTraceWarning(("CcspAdvSecurity: Received Bridge Mode On\n"));
                ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disable &");
                if(ret !=0)
                {
                      CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
                }

            }
        }
        else if(type == SYSEVENT_CLOUD_HOST_IP)
        {
            char url[COMMAND_MAX];
            memset(url, 0, sizeof(url));

            if (advsec_read_from_file(ADVSEC_CLOUD_HOST,url, COMMAND_MAX))
            {
                char *host1 = NULL;
                char *host2 = NULL;
                char *port = NULL;
                char *ip = NULL;
                if ((host1 = strtok(url, ":")) != NULL)
                {
                    port = strtok(NULL, ":");

                    if ((host2 = strtok(val, ":")) != NULL)
                    {
                       ip = strtok(NULL, ":");
                    }

                    if ( port && ip && strcmp(host1,host2) == 0)
                    {
                        char ip_port[COMMAND_MAX];
                        memset(ip_port, 0, sizeof(ip_port));
                        /* CID 160362: Calling risky function */
                        rc = strcpy_s(ip_port,sizeof(ip_port),ip);
                        ERR_CHK(rc);
                        /*CID 162510: Copy into fixed size buffer */
                        rc = strcat_s(ip_port,sizeof(ip_port),":");
                        ERR_CHK(rc);
                        rc = strcat_s(ip_port,sizeof(ip_port),port);
                        ERR_CHK(rc);
                        CcspTraceWarning(("CcspAdvSecurity: cloud ip:port %s\n",ip_port));
                        if ( ! advsec_write_to_file(ADVSEC_CLOUD_IP,ip_port) )
                        {
                            CcspTraceError(("CcspAdvSecurity: advsec_write_to_file failed\n"));
                        }
                    }
                }
            }
        }
        else if(type == SYSEVENT_MAP_T_CONFIG_CHANGED_EVENT)
        {
            ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -restartAgent MAPTConfigChanged &");
            if(ret != 0)
            {
                  CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
            }

        }
        else if(type == SYSEVENT_CURRENT_WAN_IFNAME_EVENT)
        {
            if(*val)
            {
                rc = strcmp_s(val, sizeof(MAX_INTERFACE_SIZE), prevWanIfname, &ind);
                ERR_CHK(rc);
                if((rc == EOK) && (ind))
                {
                    ret = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -restartAgent WANIfnameChanged &");
                    if(ret != 0)
                    {
                          CcspTraceWarning(("Failure in executing command via v_secure_system. ret val: %d \n", ret));
                    }
                }
                rc = strcpy_s(prevWanIfname, sizeof(prevWanIfname), val);
                ERR_CHK(rc);
            }
        }
    }

    return;
}
/*
 * Listen sysevent notification message
 */
int advsec_sysvent_listener(void)
{
    int     ret = SYS_EVENT_TIMEOUT;
    struct  timeval;

    char name[COMMAND_MAX], val[256];
    int namelen = sizeof(name);
    int vallen	= sizeof(val);
    int err;
    async_id_t getnotification_asyncid;

    err = sysevent_getnotification(sysevent_fd, sysEtoken, name, &namelen,  val, &vallen, &getnotification_asyncid);
    if (err)
    {
        CcspTraceError(("sysevent_getnotification failed with error: %d\n", err));
    }
    else
    {
        advsec_handle_sysevent_notification(name,val);
	ret = SYS_EVENT_RECEIVED;
    }

    return ret;
}

/*
 * Close sysevent
 */
int advsec_sysvent_close(void)
{
    /* we are done with this notification, so unregister it using async_id provided earlier */
    sysevent_rmnotification(sysevent_fd, sysEtoken, async_id[0]);
    sysevent_rmnotification(sysevent_fd, sysEtoken, async_id[1]);
    sysevent_rmnotification(sysevent_fd, sysEtoken, async_id[2]);
    sysevent_rmnotification(sysevent_fd, sysEtoken, async_id[3]);

    /* close this session with syseventd */
    sysevent_close(sysevent_fd, sysEtoken);

    return (SYS_EVENT_OK);
}

/*
 * check the initialized sysevent status (happened or not happened),
 * if the event happened, call the functions registered for the events previously
 */
int advsec_check_sysevent_status(int fd, token_t token)
{
    UNREFERENCED_PARAMETER(fd);
    UNREFERENCED_PARAMETER(token);
    int  returnStatus = ANSC_STATUS_SUCCESS;

    return returnStatus;
}


/*
 * The sysevent handler thread.
 */
static void *advsec_sysevent_handler_th(void *arg)
{
    UNREFERENCED_PARAMETER(arg);
    int ret = SYS_EVENT_ERROR;

    while(SYS_EVENT_ERROR == advsec_sysevent_init())
    {
        CcspTraceError(("%s: sysevent init failed!\n", __FUNCTION__));
        sleep(1);
    }

    /*first check the events status*/
    /* CID 161160: Useless call */
    ANSC_STATUS ret_value  = advsec_check_sysevent_status(sysevent_fd, sysEtoken);
    if(ret_value == ANSC_STATUS_FAILURE)
    {
        CcspTraceWarning(("advsec_check_sysevent_status() failed \n"));
    }

    while(1)
    {
        ret = advsec_sysvent_listener();
        switch (ret)
        {
            case SYS_EVENT_RECEIVED:
                break;
            default :
                CcspTraceError(("The received event status is not expected!\n"));
                break;
        }

        if (SYS_EVENT_HANDLE_EXIT == ret) //end this event handling loop
            break;

        sleep(2);
    }

    advsec_sysvent_close();

    return NULL;
}


/*
 * Create a thread to handle the sysevent asynchronously
 */
void advsec_handle_sysevent_async(void)
{
    int err;
    pthread_t event_handle_thread;

    if(AdvsecSysEventHandlerStarted)
        return;
    else
        AdvsecSysEventHandlerStarted = TRUE;

    err = pthread_create(&event_handle_thread, NULL, advsec_sysevent_handler_th, NULL);
    if(0 != err)
    {
        CcspTraceError(("%s: create the event handle thread error!\n", __FUNCTION__));
    }
}

static BOOL WaitForLoggerTimeout(ULONG period)
{
    struct timespec _ts = {0};
    struct timespec _now = {0};
    int n;
    BOOL ret = TRUE;

    pthread_mutex_lock(&logMutex);

    clock_gettime(CLOCK_REALTIME, &_now);
    _ts.tv_sec = _now.tv_sec + period;
    while (!logReady)
    {
        n = pthread_cond_timedwait(&logCond, &logMutex, &_ts);
        if(n == ETIMEDOUT) {
            ret = TRUE;
            break;
        }
    }
    if (logReady)
    {
        logReady = FALSE;
        ret = FALSE;
    }

    pthread_mutex_unlock(&logMutex);
    return ret;
}


ANSC_STATUS CosaRabidSetMemoryLimit(ANSC_HANDLE hThisObject, ULONG uValue)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS                 returnStatus = ANSC_STATUS_SUCCESS;

    returnStatus = CosaSetSysCfgUlong(g_RabidMemoryLimit, uValue);
    if ( returnStatus == ANSC_STATUS_SUCCESS )
    {
        g_pAdvSecAgent->pRabid->uMemoryLimit = uValue;
    }
    return returnStatus;
}

ANSC_STATUS CosaRabidSetMacCacheSize(ANSC_HANDLE hThisObject, ULONG uValue)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS                 returnStatus = ANSC_STATUS_SUCCESS;

    returnStatus = CosaSetSysCfgUlong(g_RabidMacCacheSize, uValue);
    if ( returnStatus == ANSC_STATUS_SUCCESS )
    {
        g_pAdvSecAgent->pRabid->uMacCacheSize = uValue;
    }
    return returnStatus;
}

ANSC_STATUS CosaRabidSetDNSCacheSize(ANSC_HANDLE hThisObject, ULONG uValue)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS                 returnStatus = ANSC_STATUS_SUCCESS;

    returnStatus = CosaSetSysCfgUlong(g_RabidDNSCacheSize, uValue);
    if ( returnStatus == ANSC_STATUS_SUCCESS )
    {
        g_pAdvSecAgent->pRabid->uDNSCacheSize = uValue;
    }
    return returnStatus;
}

ANSC_STATUS
CosaAdvPCInit
    (
             ANSC_HANDLE                 hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);

    if (CosaSetSysCfgUlong (g_AdvParentalControlEnabled, 1))
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    g_pAdvSecAgent->pAdvPC_RFC->bEnable = TRUE;

    if(g_pAdvSecAgent->pAdvPC->bEnable)
    {
        CosaStartAdvParentalControl(FALSE);
    }

    CcspTraceWarning (("AdvPC_RFCEnable:TRUE\n"));
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaAdvPCDeInit
    (
             ANSC_HANDLE                 hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);

    if (CosaSetSysCfgUlong (g_AdvParentalControlEnabled, 0))
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    g_pAdvSecAgent->pAdvPC_RFC->bEnable = FALSE;

    if (g_pAdvSecAgent->pAdvPC->bEnable)
    {
        CosaStopAdvParentalControl(FALSE);
    }

    CcspTraceWarning (("AdvPC_RFCEnable:FALSE\n"));
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaPrivacyProtectionInit
    (
             ANSC_HANDLE                 hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);

    if (CosaSetSysCfgUlong (g_PrivacyProtectionEnabled, 1))
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    g_pAdvSecAgent->pPrivProt_RFC->bEnable = TRUE;

    if (g_pAdvSecAgent->pPrivProt->bEnable)
    {
        CosaStartPrivacyProtection(FALSE);
    }

    CcspTraceWarning (("AdTrackerBlockingRFCEnable:TRUE\n"));
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS
CosaPrivacyProtectionDeInit
    (
             ANSC_HANDLE                 hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);

    if (CosaSetSysCfgUlong (g_PrivacyProtectionEnabled, 0))
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return ANSC_STATUS_FAILURE;
    }

    g_pAdvSecAgent->pPrivProt_RFC->bEnable = FALSE;

    if (g_pAdvSecAgent->pPrivProt->bEnable)
    {
        CosaStopPrivacyProtection(FALSE);
    }

    CcspTraceWarning (("AdTrackerBlockingRFCEnable:FALSE\n"));
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS CosaAdvDFIcmpv6Init(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_DeviceFingerPrintICMPv6Enabled, 1);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pDFIcmpv6_RFC->bEnable = TRUE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enableICMP6 &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: enable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvDFIcmpv6_RFCEnable:TRUE\n"));
    return returnStatus;
}


ANSC_STATUS CosaAdvDFIcmpv6DeInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_DeviceFingerPrintICMPv6Enabled, 0);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pDFIcmpv6_RFC->bEnable = FALSE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disableICMP6 &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: disable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvDFIcmpv6_RFCEnable:FALSE\n"));
    return returnStatus;
}

ANSC_STATUS CosaWSDisInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    
    returnStatus = CosaSetSysCfgUlong(g_WSDiscoveryAnalysisEnabled, 1);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pWSDiscoveryAnalysis_RFC->bEnable = TRUE;
    
    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enableWSDiscovery &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: enable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("WSDiscoveryAnalysis_RFCEnable:TRUE\n"));
    return returnStatus;
}


ANSC_STATUS CosaWSDisDeInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_WSDiscoveryAnalysisEnabled, 0);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pWSDiscoveryAnalysis_RFC->bEnable = FALSE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disableWSDiscovery &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: disable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("WSDiscoveryAnalysis_RFCEnable:FALSE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecOTMInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecOTMEnabled, 1);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecOTM_RFC->bEnable = TRUE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enableOTM &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: enable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecOTM_RFCEnable:TRUE\n"));
    return returnStatus;
}


ANSC_STATUS CosaAdvSecOTMDeInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecOTMEnabled, 0);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecOTM_RFC->bEnable = FALSE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disableOTM &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: disable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecOTM_RFCEnable:FALSE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecUserSpaceInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecUserSpaceEnabled, 1);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable = TRUE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enableUS &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: enable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecUserSpace_RFCEnable:TRUE\n"));
    return returnStatus;
}

/*
ANSC_STATUS CosaAdvSecUserSpaceDeInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecUserSpaceEnabled, 0);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable = FALSE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disableUS &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: disable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecUserSpace_RFCEnable:FALSE\n"));
    return returnStatus;
}
*/

#ifdef WIFI_DATA_COLLECTION
ANSC_STATUS CosaLevlInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    bool withUS = FALSE;
    bool wifidcl_inited = FALSE;
    int levl_init_count = 0;

    int ret = 0;

    ret = wifidcl_init_precheck();
    if (ret != RBUS_ERROR_SUCCESS)
    {
        CcspTraceError(("%s:%d WiFi webconfig init data RBUS get failed\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    // Enable Device.WiFi.Levl if disabled
    if (Wifi_Get_Status(LEVL_DML) == FALSE)
    {
        returnStatus = Wifi_SetParameterValue(LEVL_DML, TRUE);
        if (returnStatus != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s:%d %s set failed\n", __FUNCTION__, __LINE__, LEVL_DML));
            return returnStatus;
        }
        else
        {
            sleep(1);
        }
    }

    while (Wifi_Get_Status(LEVL_DML) == FALSE)
    {
        CcspTraceInfo(("%s:%d Waiting for levl_init to complete\n", __FUNCTION__, __LINE__));
        CcspTraceDebug(("%s:%d Levl_init wait time is %d seconds\n", __FUNCTION__, __LINE__,levl_init_count));
        sleep(1);
        levl_init_count++;

        if(levl_init_count == 10) {
            CcspTraceError(("%s:%d %s is false even after setting to true\n", __FUNCTION__, __LINE__, LEVL_DML));
            return ANSC_STATUS_FAILURE;
        }
    }

    // Enable Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvanceSecurityUserSpace.Enable if disabled
    if (g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable == FALSE)
    {
        returnStatus = CosaSetSysCfgUlong(g_AdvSecUserSpaceEnabled, 1);
        if (ANSC_STATUS_SUCCESS != returnStatus)
        {
            CcspTraceError(("%s: syscfg_set failure\n", __FUNCTION__));
            return returnStatus;
        }

        g_pAdvSecAgent->pAdvSecUserSpace_RFC->bEnable = TRUE;
        withUS = TRUE;
        CcspTraceInfo(("AdvSecUserSpace_RFCEnable:TRUE\n"));
    }

    // Enable Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.WifiDataCollection.Enable if disabled
    if (g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable == FALSE)
    {
        returnStatus = CosaAdvWifiDataConsumerInit();
        if (ANSC_STATUS_SUCCESS != returnStatus)
        {
            CcspTraceError(("%s:%d CosaAdvWifiDataConsumerInit failed\n", __FUNCTION__, __LINE__));
            return returnStatus;
        }
        rc = v_secure_system("touch " ADVSEC_WIFIDCL_INIT_FILE_PATH);
        if(!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
            CcspTraceError(("Failed to touch %s", ADVSEC_WIFIDCL_INIT_FILE_PATH));
        }
        returnStatus = CosaSetSysCfgUlong(g_AdvWifiDataCollection, 1);
        if (ANSC_STATUS_SUCCESS != returnStatus)
        {
            CcspTraceError(("%s: syscfg_set failure\n", __FUNCTION__));
            return returnStatus;
        }

        g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable = TRUE;
        wifidcl_inited = TRUE;
        CcspTraceInfo(("AdvSecWifiDataCollection_RFCEnable:TRUE\n"));
    }

    returnStatus = CosaSetSysCfgUlong(g_LevlEnabled, 1);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceError(("%s: syscfg_set failure\n", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pLevl_RFC->bEnable = TRUE;
    if (withUS)
    {
        rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enableLEVLwithUS &");
        if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
           CcspTraceError(("%s: disable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
        }
    }
    else if (wifidcl_inited)
    {
        rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enableLEVL &");
        if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
           CcspTraceError(("%s: disable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
        }
    }

    CcspTraceInfo(("Levl_RFCEnable:TRUE\n"));
    return returnStatus;
}


ANSC_STATUS CosaLevlDeInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;
    bool wifidcl_deinited = FALSE;

    // De-initialize wifidatacollection
    if (g_pAdvSecAgent->pAdvWifiDataCollection_RFC->bEnable == 1)
    {
        returnStatus = CosaAdvWifiDataCollectionDeInit(g_pAdvSecAgent->pAdvWifiDataCollection_RFC);
        if (returnStatus != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s: wifidatacollection de-init error\n", __FUNCTION__));
            return returnStatus;
        }
        wifidcl_deinited = TRUE;
    }

    // Disable Device.WiFi.Levl if enabled
    if (Wifi_Get_Status(LEVL_DML) == TRUE)
    {
        returnStatus = Wifi_SetParameterValue(LEVL_DML, FALSE);
        if (returnStatus != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("%s:%d %s set failed\n", __FUNCTION__, __LINE__, LEVL_DML));
            return returnStatus;
        }
        else
        {
            sleep(1);
        }
    }

    returnStatus = CosaSetSysCfgUlong(g_LevlEnabled, 0);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceError(("%s: syscfg_set failure\n", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pLevl_RFC->bEnable = FALSE;

    if (wifidcl_deinited)
    {
        rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disableLEVL &");
        if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
        {
           CcspTraceError(("%s: disable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
        }
    }

    CcspTraceInfo(("Levl_RFCEnable:FALSE\n"));
    return returnStatus;
}
#endif

ANSC_STATUS CosaAdvSecAgentInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecAgentEnabled, 1);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.\n", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecAgent_RFC->bEnable = TRUE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enableAGT &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: enable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecAgent_RFCEnable:TRUE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecAgentDeInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecAgentEnabled, 0);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.\n", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecAgent_RFC->bEnable = FALSE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disableAGT &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: disable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecAgent_RFCEnable:FALSE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecSafeBrowsingInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecSafeBrowsingEnabled, 1);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.\n", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecSafeBrowsing_RFC->bEnable = TRUE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enableSBRule &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: enable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecSafeBrowsing_RFCEnable:TRUE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecSafeBrowsingDeInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecSafeBrowsingEnabled, 0);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.\n", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecSafeBrowsing_RFC->bEnable = FALSE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disableSBRule &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: disable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecSafeBrowsing_RFCEnable:FALSE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecCujoTelemetryWiFiFPInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecCujoTelemetryWiFiFPEnabled, 1);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.\n", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecCujoTelemetryWiFiFP_RFC->bEnable = TRUE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enableCTW &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: enable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecCujoTelemetryWiFiFP_RFCEnable:TRUE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecCujoTelemetryWiFiFPDeInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecCujoTelemetryWiFiFPEnabled, 0);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.\n", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecCujoTelemetryWiFiFP_RFC->bEnable = FALSE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disableCTW &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: disable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecCujoTelemetryWiFiFP_RFCEnable:FALSE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecCujoTracerInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecCujoTracerEnabled, 1);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecCujoTracer_RFC->bEnable = TRUE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enableCT &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: enable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecCujoTracer_RFCEnable:TRUE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecCujoTracerDeInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecCujoTracerEnabled, 0);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecCujoTracer_RFC->bEnable = FALSE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disableCT &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: disable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecCujoTracer_RFCEnable:FALSE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecCujoTelemetryInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecCujoTelemetryEnabled, 1);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecCujoTelemetry_RFC->bEnable = TRUE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enableCTD &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: enable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecCujoTelemetry_RFCEnable:TRUE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecCujoTelemetryDeInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecCujoTelemetryEnabled, 0);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecCujoTelemetry_RFC->bEnable = FALSE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disableCTD &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: disable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecCujoTelemetry_RFCEnable:FALSE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecSATEInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecSATEEnabled, 1);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecSATE_RFC->bEnable = TRUE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enableSATE &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: enable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecSentryAtTheEdge_RFCEnable:TRUE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecSATEDeInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecSATEEnabled, 0);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecSATE_RFC->bEnable = FALSE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disableSATE &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: disable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecSentryAtTheEdge_RFCEnable:FALSE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecTCPTrackerFilterDevicesInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecTCPTrackerFilterDevicesEnabled, 1);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecTCPTrackerFilterDevices_RFC->bEnable = TRUE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enableTCPTrackerFilterDevices &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: enable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecTCPTrackerFilterDevices_RFCEnable:TRUE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecTCPTrackerFilterDevicesDeInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_AdvSecTCPTrackerFilterDevicesEnabled, 0);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pAdvSecTCPTrackerFilterDevices_RFC->bEnable = FALSE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disableTCPTrackerFilterDevices &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: disable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecTCPTrackerFilterDevices_RFCEnable:FALSE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecAgentRaptrInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_RaptrEnabled, 1);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pRaptr_RFC->bEnable = TRUE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -enableRaptr &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: enable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecAgentRaptr_RFCEnable:TRUE\n"));
    return returnStatus;
}

ANSC_STATUS CosaAdvSecAgentRaptrDeInit(ANSC_HANDLE hThisObject)
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS  returnStatus = ANSC_STATUS_SUCCESS;
    errno_t rc = -1;

    returnStatus = CosaSetSysCfgUlong(g_RaptrEnabled, 0);
    if (ANSC_STATUS_SUCCESS != returnStatus)
    {
        CcspTraceWarning (("%s: syscfg_set failure.", __FUNCTION__));
        return returnStatus;
    }

    g_pAdvSecAgent->pRaptr_RFC->bEnable = FALSE;

    rc = v_secure_system(TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/start_adv_security.sh -disableRaptr &");
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
    {
       CcspTraceError(("%s: disable failed rc = %d\n", __FUNCTION__, WEXITSTATUS(rc)));
    }

    CcspTraceWarning (("AdvSecAgentRaptr_RFCEnable:FALSE\n"));
    return returnStatus;
}
