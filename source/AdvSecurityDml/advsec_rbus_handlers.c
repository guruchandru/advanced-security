/*
 * Advanced Security - RBUS Handlers (Metadata-Driven)
 * Uses namespace classification and short_name routing 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <syslog.h>
#include <rbus/rbus.h>
#include "advsec_rbus_handlers.h"
#include "advsec_bus_json_decode.h"
#include "advsec_compat_types.h"
#include "cosa_adv_security_internal.h"
#include "cosa_adv_security_dml.h"

#ifdef WIFI_DATA_COLLECTION
#include "cujoagent_dcl_api.h"
#endif

extern ANSC_HANDLE bus_handle;
extern COSA_DATAMODEL_AGENT* g_pAdvSecAgent;

#ifdef WIFI_DATA_COLLECTION
cujoagent_wifi_consumer_t *g_cujoagent_dcl = NULL;
#endif

#define STR_EQ(a,b) (strcmp((a), (b)) == 0)

/* RBUS handle - global for use across files */
rbusHandle_t g_rbus_handle = NULL;

/* ==================== Namespace GET Dispatchers ==================== */

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.* parameters
 */
static rbusError_t get_device_fingerprint(const char *short_name, rbusValue_t *data)
{
    if (!data || !*data) {
        CcspTraceError(("get_device_fingerprint: NULL data pointer\n"));
        return RBUS_ERROR_BUS_ERROR;
    }
    
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        CcspTraceInfo(("get_device_fingerprint: Calling DeviceFingerPrint_GetParamBoolValue for Enable\n"));
        if (DeviceFingerPrint_GetParamBoolValue(NULL, "Enable", &val)) {
            CcspTraceInfo(("get_device_fingerprint: Got value %d, setting RBUS value\n", val));
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        } else {
            CcspTraceError(("get_device_fingerprint: DeviceFingerPrint_GetParamBoolValue failed\n"));
            return RBUS_ERROR_BUS_ERROR;
        }
    }
    else if (STR_EQ(short_name, "LoggingPeriod")) {
        ULONG val = 0;
        if (DeviceFingerPrint_GetParamUlongValue(NULL, "LoggingPeriod", &val)) {
            rbusValue_SetUInt32(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "LogLevel")) {
        ULONG val = 0;
        if (DeviceFingerPrint_GetParamUlongValue(NULL, "LogLevel", &val)) {
            rbusValue_SetUInt32(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "EndpointURL")) {
        char val[512] = {0};
        ULONG val_len = sizeof(val);
        if (DeviceFingerPrint_GetParamStringValue(NULL, "EndpointURL", val, &val_len)) {
            rbusValue_SetString(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    
    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedSecurity.* parameters
 */
static rbusError_t get_advanced_security(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Data")) {
        rbusValue_SetString(*data, "");
        return RBUS_ERROR_SUCCESS;
    }
    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedSecurity.SafeBrowsing.* parameters
 */
static rbusError_t get_safebrowsing(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (SafeBrowsing_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "LookupTimeout")) {
        ULONG val = 0;
        if (SafeBrowsing_GetParamUlongValue(NULL, "LookupTimeout", &val)) {
            rbusValue_SetUInt32(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "LookupTimeoutExceededCount")) {
        ULONG val = 0;
        if (SafeBrowsing_GetParamUlongValue(NULL, "LookupTimeoutExceededCount", &val)) {
            rbusValue_SetUInt32(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "Threshold")) {
        ULONG val = 0;
        if (SafeBrowsing_GetParamUlongValue(NULL, "Threshold", &val)) {
            rbusValue_SetUInt32(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "Timeout")) {
        ULONG val = 0;
        if (SafeBrowsing_GetParamUlongValue(NULL, "Timeout", &val)) {
            rbusValue_SetUInt32(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "Cachettl")) {
        ULONG val = 0;
        if (SafeBrowsing_GetParamUlongValue(NULL, "Cachettl", &val)) {
            rbusValue_SetUInt32(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "Ttl")) {
        ULONG val = 0;
        if (SafeBrowsing_GetParamUlongValue(NULL, "Ttl", &val)) {
            rbusValue_SetUInt32(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "WhitelistMaxEntries")) {
        ULONG val = 0;
        if (SafeBrowsing_GetParamUlongValue(NULL, "WhitelistMaxEntries", &val)) {
            rbusValue_SetUInt32(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "Endpoint")) {
        char val[512] = {0};
        ULONG val_len = sizeof(val);
        if (SafeBrowsing_GetParamStringValue(NULL, "Endpoint", val, &val_len)) {
            rbusValue_SetString(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "Blockpage")) {
        char val[512] = {0};
        ULONG val_len = sizeof(val);
        if (SafeBrowsing_GetParamStringValue(NULL, "Blockpage", val, &val_len)) {
            rbusValue_SetString(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "Warnpage")) {
        char val[512] = {0};
        ULONG val_len = sizeof(val);
        if (SafeBrowsing_GetParamStringValue(NULL, "Warnpage", val, &val_len)) {
            rbusValue_SetString(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "Cacheurl")) {
        char val[512] = {0};
        ULONG val_len = sizeof(val);
        if (SafeBrowsing_GetParamStringValue(NULL, "Cacheurl", val, &val_len)) {
            rbusValue_SetString(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "OtmDedupFqdn")) {
        char val[512] = {0};
        ULONG val_len = sizeof(val);
        if (SafeBrowsing_GetParamStringValue(NULL, "OtmDedupFqdn", val, &val_len)) {
            rbusValue_SetString(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedSecurity.Softflowd.* parameters
 */
static rbusError_t get_softflowd(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (Softflowd_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    
    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedParentalControl.* parameters
 */
static rbusError_t get_parental_control(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Activate")) {
        BOOL val = FALSE;
        if (AdvancedParentalControl_GetParamBoolValue(NULL, "Activate", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    
    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_PrivacyProtection.* parameters
 */
static rbusError_t get_privacy_protection(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Activate")) {
        BOOL val = FALSE;
        if (PrivacyProtection_GetParamBoolValue(NULL, "Activate", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    
    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.RabidFramework.* parameters
 */
static rbusError_t get_rfc_rabidframework(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "MemoryLimit")) {
        ULONG val = 0;
        if (RabidFramework_GetParamUlongValue(NULL, "MemoryLimit", &val)) {
            rbusValue_SetUInt32(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "MacCacheSize")) {
        ULONG val = 0;
        if (RabidFramework_GetParamUlongValue(NULL, "MacCacheSize", &val)) {
            rbusValue_SetUInt32(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "DNSCacheSize")) {
        ULONG val = 0;
        if (RabidFramework_GetParamUlongValue(NULL, "DNSCacheSize", &val)) {
            rbusValue_SetUInt32(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    
    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvancedParentalControl.* parameters
 */
static rbusError_t get_rfc_advanced_parental_control(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (AdvancedParentalControl_RFC_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    
    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.PrivacyProtection.* parameters
 */
static rbusError_t get_rfc_privacy_protection(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (PrivacyProtection_RFC_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    
    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.DeviceFingerPrintICMPv6.* parameters
 */
static rbusError_t get_rfc_device_fingerprint_icmpv6(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (DeviceFingerPrintICMPv6_RFC_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.WS-Discovery_Analysis.* parameters
 */
static rbusError_t get_rfc_ws_discovery_analysis(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (WS_Discovery_Analysis_RFC_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }
    
    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvancedSecurityOTM.* parameters
 */
static rbusError_t get_rfc_advanced_security_otm(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (AdvancedSecurityOTM_RFC_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvSecAgentRaptr.* parameters
 */
static rbusError_t get_rfc_advsec_agent_raptr(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (AdvSecAgentRaptr_RFC_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvanceSecurityUserSpace.* parameters
 */
static rbusError_t get_rfc_advance_security_user_space(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (AdvanceSecurityUserSpace_RFC_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvanceSecurityCujoTracer.* parameters
 */
static rbusError_t get_rfc_advance_security_cujo_tracer(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (AdvanceSecurityCujoTracer_RFC_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.Levl.* parameters
 */
static rbusError_t get_rfc_levl(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (Levl_RFC_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvSecAgent.* parameters
 */
static rbusError_t get_rfc_advsec_agent(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (AdvSecAgent_RFC_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 *  GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvSecSafeBrowsing.* parameters
 */
static rbusError_t get_rfc_advsec_safe_browsing(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (AdvSecSafeBrowsing_RFC_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvSecCujoTelemetryWiFiFP.* parameters
 */
static rbusError_t get_rfc_advsec_cujo_telemetry_wififp(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (AdvSecCujoTelemetryWiFiFP_RFC_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvanceSecurityCujoTelemetry.* parameters
 */
static rbusError_t get_rfc_advance_security_cujo_telemetry(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (AdvanceSecurityCujoTelemetry_RFC_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvSecSentryAtTheEdge.* parameters
 */
static rbusError_t get_rfc_advsec_sentry_at_the_edge(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (AdvSecSentryAtTheEdge_RFC_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvSecTCPTrackerFilterDevices.* parameters
 */
static rbusError_t get_rfc_advsec_tcp_tracker_filter_devices(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (AdvSecTCPTrackerFilterDevices_RFC_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * GET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.WifiDataCollection.* parameters
 */
static rbusError_t get_rfc_wifi_data_collection(const char *short_name, rbusValue_t *data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = FALSE;
        if (WifiDataCollection_RFC_GetParamBoolValue(NULL, "Enable", &val)) {
            rbusValue_SetBoolean(*data, val);
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}
/* ==================== Namespace SET Dispatchers ==================== */

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_DeviceFingerPrint.* parameters
 */
static rbusError_t set_device_fingerprint(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (DeviceFingerPrint_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "LoggingPeriod")) {
        ULONG val = rbusValue_GetUInt32(data);
        if (DeviceFingerPrint_SetParamUlongValue(NULL, "LoggingPeriod", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "LogLevel")) {
        ULONG val = rbusValue_GetUInt32(data);
        if (DeviceFingerPrint_SetParamUlongValue(NULL, "LogLevel", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "EndpointURL")) {
        const char *val = rbusValue_GetString(data, NULL);
        if (DeviceFingerPrint_SetParamStringValue(NULL, "EndpointURL", (char *)val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }
    
    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedSecurity.* parameters
 */
static rbusError_t set_advanced_security(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Data")) {
        const char *val = rbusValue_GetString(data, NULL);
        if (AdvancedSecurity_SetParamStringValue(NULL, "Data", (char *)val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedSecurity.SafeBrowsing.* parameters
 */
static rbusError_t set_safebrowsing(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (SafeBrowsing_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "LookupTimeout")) {
        ULONG val = rbusValue_GetUInt32(data);
        if (SafeBrowsing_SetParamUlongValue(NULL, "LookupTimeout", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedSecurity.Softflowd.* parameters
 */
static rbusError_t set_softflowd(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (Softflowd_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }
    
    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_AdvancedParentalControl.* parameters
 */
static rbusError_t set_parental_control(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Activate")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (AdvancedParentalControl_SetParamBoolValue(NULL, "Activate", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }
    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_PrivacyProtection.* parameters
 */
static rbusError_t set_privacy_protection(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Activate")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (PrivacyProtection_SetParamBoolValue(NULL, "Activate", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.RabidFramework.* parameters
 */
static rbusError_t set_rfc_rabidframework(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "MemoryLimit")) {
        ULONG val = rbusValue_GetUInt32(data);
        if (RabidFramework_SetParamUlongValue(NULL, "MemoryLimit", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "MacCacheSize")) {
        ULONG val = rbusValue_GetUInt32(data);
        if (RabidFramework_SetParamUlongValue(NULL, "MacCacheSize", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }
    else if (STR_EQ(short_name, "DNSCacheSize")) {
        ULONG val = rbusValue_GetUInt32(data);
        if (RabidFramework_SetParamUlongValue(NULL, "DNSCacheSize", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }
    
    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvancedParentalControl.* parameters
 */
static rbusError_t set_rfc_advanced_parental_control(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (AdvancedParentalControl_RFC_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.PrivacyProtection.* parameters
 */
static rbusError_t set_rfc_privacy_protection(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (PrivacyProtection_RFC_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.DeviceFingerPrintICMPv6.* parameters
 */
static rbusError_t set_rfc_device_fingerprint_icmpv6(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (DeviceFingerPrintICMPv6_RFC_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.WS-Discovery_Analysis.* parameters
 */
static rbusError_t set_rfc_ws_discovery_analysis(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (WS_Discovery_Analysis_RFC_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvancedSecurityOTM.* parameters
 */
static rbusError_t set_rfc_advanced_security_otm(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (AdvancedSecurityOTM_RFC_SetParamBoolValue(NULL, "Enable", val   )) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvSecAgentRaptr.* parameters
 */
static rbusError_t set_rfc_advsec_agent_raptr(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (AdvSecAgentRaptr_RFC_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvanceSecurityUserSpace.* parameters
 */
static rbusError_t set_rfc_advance_security_user_space(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (AdvanceSecurityUserSpace_RFC_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvanceSecurityCujoTracer.* parameters
 */
static rbusError_t set_rfc_advance_security_cujo_tracer(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (AdvanceSecurityCujoTracer_RFC_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.Levl.* parameters
 */
static rbusError_t set_rfc_levl(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (Levl_RFC_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvSecAgent.* parameters
 */
static rbusError_t set_rfc_advsec_agent(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (AdvSecAgent_RFC_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvSecSafeBrowsing.* parameters
 */
static rbusError_t set_rfc_advsec_safe_browsing(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (AdvSecSafeBrowsing_RFC_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvSecCujoTelemetryWiFiFP.* parameters
 */
static rbusError_t set_rfc_advsec_cujo_telemetry_wififp(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (AdvSecCujoTelemetryWiFiFP_RFC_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvanceSecurityCujoTelemetry.* parameters
 */
static rbusError_t set_rfc_advance_security_cujo_telemetry(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (AdvanceSecurityCujoTelemetry_RFC_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvSecSentryAtTheEdge.* parameters
 */
static rbusError_t set_rfc_advsec_sentry_at_the_edge(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (AdvSecSentryAtTheEdge_RFC_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.AdvSecTCPTrackerFilterDevices.* parameters
 */
static rbusError_t set_rfc_advsec_tcp_tracker_filter_devices(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (AdvSecTCPTrackerFilterDevices_RFC_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/**
 * SET handler for Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.WifiDataCollection.* parameters
 */
static rbusError_t set_rfc_wifi_data_collection(const char *short_name, rbusValue_t data)
{
    if (STR_EQ(short_name, "Enable")) {
        BOOL val = rbusValue_GetBoolean(data);
        if (WifiDataCollection_RFC_SetParamBoolValue(NULL, "Enable", val)) {
            return RBUS_ERROR_SUCCESS;
        }
    }

    return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
}

/* ==================== Main GET/SET Handlers ==================== */

/**
 * Main RBUS GET handler - routes to namespace-specific dispatchers
 */
rbusError_t advsec_rbus_get_handler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    const char *param_name = rbusProperty_GetName(property);
    rbusValue_t value = NULL;
    rbusError_t rc = RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    
    CcspTraceInfo(("GET request for: %s\n", param_name));
    
    /* Lookup metadata */
    advsec_param_metadata_t *meta = advsec_find_param_metadata(param_name);
    if (!meta) {
        CcspTraceError(("Parameter not found in metadata: %s\n", param_name));
        return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    }
    
    CcspTraceInfo(("Found metadata for %s: namespace_type=%d, short_name=%s\n", 
                   param_name, meta->namespace_type, meta->short_name ? meta->short_name : "NULL"));
    
    /* Allocate return value */
    rbusValue_Init(&value);
    
    if (!value) {
        CcspTraceError(("rbusValue_Init failed for %s\n", param_name));
        return RBUS_ERROR_BUS_ERROR;
    }
    
    CcspTraceInfo(("rbusValue initialized successfully for %s\n", param_name));
    
    /* Route to namespace-specific dispatcher */
    switch (meta->namespace_type) {
        case ADVSEC_NAMESPACE_DEVICE_FINGERPRINT:
            rc = get_device_fingerprint(meta->short_name, &value);
            break;
            
        case ADVSEC_NAMESPACE_ADVANCED_SECURITY:
            rc = get_advanced_security(meta->short_name, &value);
            break;
            
        case ADVSEC_NAMESPACE_SAFEBROWSING:
            rc = get_safebrowsing(meta->short_name, &value);
            break;
            
        case ADVSEC_NAMESPACE_SOFTFLOWD:
            rc = get_softflowd(meta->short_name, &value);
            break;
            
        case ADVSEC_NAMESPACE_PARENTAL_CONTROL:
            rc = get_parental_control(meta->short_name, &value);
            break;
            
        case ADVSEC_NAMESPACE_PRIVACY_PROTECTION:
            rc = get_privacy_protection(meta->short_name, &value);
            break;
            
        case ADVSEC_NAMESPACE_RFC_RABIDFRAMEWORK:
            rc = get_rfc_rabidframework(meta->short_name, &value);
            break;

        case ADVSEC_NAMESPACE_RFC_ADVANCED_PARENTAL_CONTROL:
            rc = get_rfc_advanced_parental_control(meta->short_name, &value);
            break;

        case ADVSEC_NAMESPACE_RFC_PRIVACY_PROTECTION:
            rc = get_rfc_privacy_protection(meta->short_name, &value);
            break;

        case ADVSEC_NAMESPACE_RFC_DEVICE_FINGERPRINT_ICMPV6:
            rc = get_rfc_device_fingerprint_icmpv6(meta->short_name, &value);
            break;

        case ADVSEC_NAMESPACE_RFC_WS_DISCOVERY_ANALYSIS:
            rc = get_rfc_ws_discovery_analysis(meta->short_name, &value);
            break;

        case ADVSEC_NAMESPACE_RFC_ADVANCED_SECURITY_OTM:
            rc = get_rfc_advanced_security_otm(meta->short_name, &value);
            break;

        case ADVSEC_NAMESPACE_RFC_ADVANCED_SECURITY_USERSPACE:
            rc = get_rfc_advance_security_user_space(meta->short_name, &value);
            break;

        case ADVSEC_NAMESPACE_RFC_ADVANCED_SECURITY_CUJOTRACER:
            rc = get_rfc_advance_security_cujo_tracer(meta->short_name, &value);
            break;

        case ADVSEC_NAMESPACE_RFC_ADVANCED_SECURITY_CUJOTELEMETRY:
            rc = get_rfc_advance_security_cujo_telemetry(meta->short_name, &value);
            break;

        case ADVSEC_NAMESPACE_RFC_ADVSEC_SENTRY_AT_THE_EDGE:
            rc = get_rfc_advsec_sentry_at_the_edge(meta->short_name, &value);
            break;

        case ADVSEC_NAMESPACE_RFC_ADVSEC_TCP_TRACKER_FILTER_DEVICES:
            rc = get_rfc_advsec_tcp_tracker_filter_devices(meta->short_name, &value);
            break;

        case ADVSEC_NAMESPACE_RFC_WIFI_DATA_COLLECTION:
            rc = get_rfc_wifi_data_collection(meta->short_name, &value);
            break;

        case ADVSEC_NAMESPACE_RFC_LEVL:
            rc = get_rfc_levl(meta->short_name, &value);
            break;

        case ADVSEC_NAMESPACE_RFC_ADVSEC_AGENT:
            rc = get_rfc_advsec_agent(meta->short_name, &value);
            break;

        case ADVSEC_NAMESPACE_RFC_ADVSEC_SAFEBROWSING:
            rc = get_rfc_advsec_safe_browsing(meta->short_name, &value);
            break;

        case ADVSEC_NAMESPACE_RFC_ADVSEC_CUJOTELEMETRY_WIFIFP:
            rc = get_rfc_advsec_cujo_telemetry_wififp(meta->short_name, &value);
            break;

        case ADVSEC_NAMESPACE_RFC_ADVSEC_AGENT_RAPTR:
            rc = get_rfc_advsec_agent_raptr(meta->short_name, &value);
            break;

        default:
            CcspTraceError(("Unknown namespace type: %d for parameter: %s\n", 
                           meta->namespace_type, param_name));
            rbusValue_Release(value);
            return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    }
    
    /* Set property value if successful */
    if (rc == RBUS_ERROR_SUCCESS) {
        rbusProperty_SetValue(property, value);
    }
    
    rbusValue_Release(value);
    return rc;
}

/**
 * Main RBUS SET handler - routes to namespace-specific dispatchers
 */
rbusError_t advsec_rbus_set_handler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    (void) handle;
    (void) opts;
    const char *param_name = rbusProperty_GetName(property);
    rbusValue_t value = rbusProperty_GetValue(property);
    
    CcspTraceInfo(("SET request for: %s\n", param_name));
    
    /* Lookup metadata */
    advsec_param_metadata_t *meta = advsec_find_param_metadata(param_name);
    if (!meta) {
        CcspTraceError(("Parameter not found in metadata: %s\n", param_name));
        return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    }
    
    /* Check if parameter is writable */
    if (!meta->writable) {
        CcspTraceError(("Parameter is read-only: %s\n", param_name));
        return RBUS_ERROR_ACCESS_NOT_ALLOWED;
    }
    
    /* Route to namespace-specific dispatcher */
    switch (meta->namespace_type) {
        case ADVSEC_NAMESPACE_DEVICE_FINGERPRINT:
            return set_device_fingerprint(meta->short_name, value);
            
        case ADVSEC_NAMESPACE_ADVANCED_SECURITY:
            return set_advanced_security(meta->short_name, value);
            
        case ADVSEC_NAMESPACE_SAFEBROWSING:
            return set_safebrowsing(meta->short_name, value);
            
        case ADVSEC_NAMESPACE_SOFTFLOWD:
            return set_softflowd(meta->short_name, value);
            
        case ADVSEC_NAMESPACE_PARENTAL_CONTROL:
            return set_parental_control(meta->short_name, value);
            
        case ADVSEC_NAMESPACE_PRIVACY_PROTECTION:
            return set_privacy_protection(meta->short_name, value);
            
        case ADVSEC_NAMESPACE_RFC_RABIDFRAMEWORK:
            return set_rfc_rabidframework(meta->short_name, value);

        case ADVSEC_NAMESPACE_RFC_ADVANCED_PARENTAL_CONTROL:
            return set_rfc_advanced_parental_control(meta->short_name, value);

        case ADVSEC_NAMESPACE_RFC_PRIVACY_PROTECTION:
            return set_rfc_privacy_protection(meta->short_name, value);

        case ADVSEC_NAMESPACE_RFC_DEVICE_FINGERPRINT_ICMPV6:
            return set_rfc_device_fingerprint_icmpv6(meta->short_name, value);

        case ADVSEC_NAMESPACE_RFC_WS_DISCOVERY_ANALYSIS:
            return set_rfc_ws_discovery_analysis(meta->short_name, value);

        case ADVSEC_NAMESPACE_RFC_ADVANCED_SECURITY_OTM:
            return set_rfc_advanced_security_otm(meta->short_name, value);

        case ADVSEC_NAMESPACE_RFC_ADVANCED_SECURITY_USERSPACE:
            return set_rfc_advance_security_user_space(meta->short_name, value);

        case ADVSEC_NAMESPACE_RFC_ADVANCED_SECURITY_CUJOTRACER:
            return set_rfc_advance_security_cujo_tracer(meta->short_name, value);

        case ADVSEC_NAMESPACE_RFC_ADVANCED_SECURITY_CUJOTELEMETRY:
            return set_rfc_advance_security_cujo_telemetry(meta->short_name, value);

        case ADVSEC_NAMESPACE_RFC_ADVSEC_SENTRY_AT_THE_EDGE:
            return set_rfc_advsec_sentry_at_the_edge(meta->short_name, value);

        case ADVSEC_NAMESPACE_RFC_ADVSEC_TCP_TRACKER_FILTER_DEVICES:
            return set_rfc_advsec_tcp_tracker_filter_devices(meta->short_name, value);

        case ADVSEC_NAMESPACE_RFC_WIFI_DATA_COLLECTION:
            return set_rfc_wifi_data_collection(meta->short_name, value);

        case ADVSEC_NAMESPACE_RFC_LEVL:
            return set_rfc_levl(meta->short_name, value);

        case ADVSEC_NAMESPACE_RFC_ADVSEC_AGENT:
            return set_rfc_advsec_agent(meta->short_name, value);

        case ADVSEC_NAMESPACE_RFC_ADVSEC_SAFEBROWSING:
            return set_rfc_advsec_safe_browsing(meta->short_name, value);

        case ADVSEC_NAMESPACE_RFC_ADVSEC_CUJOTELEMETRY_WIFIFP:
            return set_rfc_advsec_cujo_telemetry_wififp(meta->short_name, value);

        case ADVSEC_NAMESPACE_RFC_ADVSEC_AGENT_RAPTR:
            return set_rfc_advsec_agent_raptr(meta->short_name, value);
            
        default:
            CcspTraceError(("Unknown namespace type: %d for parameter: %s\n", 
                           meta->namespace_type, param_name));
            return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    }
}

/* ==================== RBUS Initialization ==================== */

/**
 * Initialize RBUS - called from main()
 */
int advsec_rbus_init(const char *component_name)
{
    int rc = 0;
    
    CcspTraceInfo(("Initializing RBUS component: %s\n", component_name));
    
    /* Open RBUS first - needed before CosaSecurityInitialize */
    rc = rbus_open(&g_rbus_handle, component_name);
    if (rc != RBUS_ERROR_SUCCESS) {
        CcspTraceError(("rbus_open failed: %d\n", rc));
        return -1;
    }

#ifdef WIFI_DATA_COLLECTION
    g_cujoagent_dcl = AnscAllocateMemory(sizeof *g_cujoagent_dcl);
    if (!g_cujoagent_dcl)
    {
        CcspTraceError(("%s: failed to allocate the memory for wifi data collection consumer\n", __FUNCTION__));
    }
#endif

    /* Create and initialize DML data structures (replaces COSA_Init) */
    if (!g_pAdvSecAgent) {
        CcspTraceInfo(("Creating Advanced Security data model...\n"));
        g_pAdvSecAgent = (PCOSA_DATAMODEL_AGENT)CosaSecurityCreate();
        if (!g_pAdvSecAgent) {
            CcspTraceError(("CosaSecurityCreate failed\n"));
            rbus_close(g_rbus_handle);
            return -1;
        }
        
        CcspTraceInfo(("Initializing Advanced Security data model...\n"));
        CosaSecurityInitialize(g_pAdvSecAgent);
    }
    
    /* Parse JSON and register elements */
    rc = advsec_decode_json_config(g_rbus_handle, JSON_CONFIG_PATH);
    if (rc != 0) {
        CcspTraceError(("Failed to parse JSON file: %s\n", JSON_CONFIG_PATH));
        rbus_close(g_rbus_handle);
        return -1;
    }
    
    CcspTraceInfo(("RBUS initialization successful\n"));
    return 0;
}

/**
 * Terminate RBUS - called from cleanup
 */
void advsec_rbus_terminate(void)
{
    if (g_rbus_handle) {
        CcspTraceInfo(("Terminating RBUS\n"));
        
        /* Close RBUS */
        rbus_close(g_rbus_handle);
        g_rbus_handle = NULL;
        
        /* Free metadata and registered elements */
        advsec_free_param_metadata();
        advsec_free_registered_elements();
    }
}
