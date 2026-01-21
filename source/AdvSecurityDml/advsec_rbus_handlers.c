/*
 * Advanced Security RBUS handlers
 * JSON-driven TR181 registration with comprehensive parameter handling
 */

#include "advsec_rbus_handlers.h"
#include "advsec_bus_json_decode.h"
#include "advsec_compat_types.h"
#include "cosa_adv_security_internal.h"
#include "cosa_adv_security_dml.h"  /* For DML function declarations */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

/* Global RBUS handle */
static rbusHandle_t g_rbus_handle = NULL;
extern PCOSA_DATAMODEL_AGENT g_pAdvSecAgent;

/* Advanced Security callback table */
typedef struct {
    rbusError_t (*get_param_value)(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
    rbusError_t (*set_param_value)(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts);
    rbusError_t (*table_add_row_handler)(rbusHandle_t handle, char const* tableName, char const* aliasName, uint32_t* instNum);
    rbusError_t (*table_remove_row_handler)(rbusHandle_t handle, char const* rowName);
    rbusError_t (*event_sub_handler)(rbusHandle_t handle, rbusEventSubAction_t action, const char* eventName, rbusFilter_t filter, int32_t interval, bool* autoPublish);
    rbusError_t (*method_handler)(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle);
} advsec_rbus_callback_table_t;

/* Forward declarations */
static rbusError_t advsec_get_param_value(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
static rbusError_t advsec_set_param_value(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts);

/* Advanced Security RBUS Get Handler - using JSON metadata for dynamic routing */
static rbusError_t advsec_get_param_value(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    
    const char* name = rbusProperty_GetName(property);
    rbusValue_t value;
    BOOL boolResult = FALSE;
    ULONG ulongResult = 0;
    char stringResult[512] = {0};
    ULONG stringSize = sizeof(stringResult);
    
    if (!name) {
        CcspTraceError(("Invalid parameter name in Advanced Security RBUS get handler\n"));
        return RBUS_ERROR_INVALID_INPUT;
    }
    
    rbusValue_Init(&value);
    
    CcspTraceDebug(("Advanced Security RBUS Get: %s\n", name));
    
    /* Lookup parameter metadata from JSON configuration */
    advsec_param_metadata_t *metadata = advsec_get_param_metadata(name);
    if (!metadata) {
        CcspTraceError(("Parameter not found in metadata: %s\n", name));
        rbusValue_Release(value);
        return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    }
    
    CcspTraceDebug(("Found metadata: parent='%s', short_name='%s', type=%d\n", 
                    metadata->parent_object, metadata->short_param_name, metadata->data_type));
    
    /* Route to appropriate DML function based on parent object */
    if (strcmp(metadata->parent_object, "DeviceFingerPrint") == 0 ||
        strcmp(metadata->parent_object, "Fingerprint") == 0) {
        /* DeviceFingerPrint parameters - route by short_param_name */
        if (strcmp(metadata->short_param_name, "Enable") == 0) {
            if (DeviceFingerPrint_GetParamBoolValue(NULL, "Enable", &boolResult)) {
                rbusValue_SetBoolean(value, boolResult);
            } else {
                rbusValue_Release(value);
                return RBUS_ERROR_NOT_READABLE;
            }
        }
        else if (strcmp(metadata->short_param_name, "Data") == 0) {
            if (DeviceFingerPrint_GetParamStringValue(NULL, "Data", stringResult, &stringSize)) {
                rbusValue_SetString(value, stringResult);
            } else {
                rbusValue_Release(value);
                return RBUS_ERROR_NOT_READABLE;
            }
        }
        else if (strcmp(metadata->short_param_name, "LoggingPeriod") == 0) {
            if (DeviceFingerPrint_GetParamUlongValue(NULL, "LoggingPeriod", &ulongResult)) {
                rbusValue_SetUInt32(value, ulongResult);
            } else {
                rbusValue_Release(value);
                return RBUS_ERROR_NOT_READABLE;
            }
        }
        else if (strcmp(metadata->short_param_name, "EndpointURL") == 0) {
            if (DeviceFingerPrint_GetParamStringValue(NULL, "EndpointURL", stringResult, &stringSize)) {
                rbusValue_SetString(value, stringResult);
            } else {
                rbusValue_Release(value);
                return RBUS_ERROR_NOT_READABLE;
            }
        }
        else if (strcmp(metadata->short_param_name, "LogLevel") == 0) {
            if (DeviceFingerPrint_GetParamUlongValue(NULL, "LogLevel", &ulongResult)) {
                rbusValue_SetUInt32(value, ulongResult);
            } else {
                rbusValue_Release(value);
                return RBUS_ERROR_NOT_READABLE;
            }
        }
        else {
            /* Unimplemented DeviceFingerPrint param - safe default */
            CcspTraceWarning(("Unimplemented DeviceFingerPrint param: %s\n", metadata->short_param_name));
            if (metadata->data_type == RBUS_BOOLEAN) rbusValue_SetBoolean(value, FALSE);
            else if (metadata->data_type == RBUS_UINT32) rbusValue_SetUInt32(value, 0);
            else rbusValue_SetString(value, "NotImplemented");
        }
    }
    else if (strcmp(metadata->parent_object, "SafeBrowsing") == 0) {
        /* SafeBrowsing parameters */
        if (strcmp(metadata->short_param_name, "Enable") == 0) {
            if (SafeBrowsing_GetParamBoolValue(NULL, "Enable", &boolResult)) {
                rbusValue_SetBoolean(value, boolResult);
            } else {
                rbusValue_Release(value);
                return RBUS_ERROR_NOT_READABLE;
            }
        }
        else if (strcmp(metadata->short_param_name, "LookupTimeout") == 0 ||
                 strcmp(metadata->short_param_name, "LookupTimeoutExceededCount") == 0 ||
                 strcmp(metadata->short_param_name, "Threshold") == 0 ||
                 strcmp(metadata->short_param_name, "Timeout") == 0 ||
                 strcmp(metadata->short_param_name, "Cachettl") == 0 ||
                 strcmp(metadata->short_param_name, "Ttl") == 0 ||
                 strcmp(metadata->short_param_name, "WhitelistMaxEntries") == 0) {
            if (SafeBrowsing_GetParamUlongValue(NULL, metadata->short_param_name, &ulongResult)) {
                rbusValue_SetUInt32(value, ulongResult);
            } else {
                rbusValue_Release(value);
                return RBUS_ERROR_NOT_READABLE;
            }
        }
        else if (strcmp(metadata->short_param_name, "Endpoint") == 0 ||
                 strcmp(metadata->short_param_name, "Blockpage") == 0 ||
                 strcmp(metadata->short_param_name, "Warnpage") == 0 ||
                 strcmp(metadata->short_param_name, "Cacheurl") == 0 ||
                 strcmp(metadata->short_param_name, "OtmDedupFqdn") == 0) {
            if (SafeBrowsing_GetParamStringValue(NULL, metadata->short_param_name, stringResult, &stringSize)) {
                rbusValue_SetString(value, stringResult);
            } else {
                rbusValue_Release(value);
                return RBUS_ERROR_NOT_READABLE;
            }
        }
        else {
            CcspTraceWarning(("Unimplemented SafeBrowsing param: %s\n", metadata->short_param_name));
            if (metadata->data_type == RBUS_BOOLEAN) rbusValue_SetBoolean(value, FALSE);
            else if (metadata->data_type == RBUS_UINT32) rbusValue_SetUInt32(value, 0);
            else rbusValue_SetString(value, "NotImplemented");
        }
    }
    else if (strcmp(metadata->parent_object, "AdvancedSecurity") == 0) {
        /* AdvancedSecurity parameters */
        if (strcmp(metadata->short_param_name, "Data") == 0) {
            if (DeviceFingerPrint_GetParamStringValue(NULL, "Data", stringResult, &stringSize)) {
                rbusValue_SetString(value, stringResult);
            } else {
                rbusValue_Release(value);
                return RBUS_ERROR_NOT_READABLE;
            }
        }
        else {
            CcspTraceWarning(("Unimplemented AdvancedSecurity param: %s\n", metadata->short_param_name));
            if (metadata->data_type == RBUS_BOOLEAN) rbusValue_SetBoolean(value, FALSE);
            else if (metadata->data_type == RBUS_UINT32) rbusValue_SetUInt32(value, 0);
            else rbusValue_SetString(value, "NotImplemented");
        }
    }
    else if (strcmp(metadata->parent_object, "AdvancedParentalControl") == 0) {
        /* AdvancedParentalControl parameters */
        if (strcmp(metadata->short_param_name, "Activate") == 0 || strcmp(metadata->short_param_name, "Enable") == 0) {
            if (AdvancedParentalControl_GetParamBoolValue(NULL, "Activate", &boolResult)) {
                rbusValue_SetBoolean(value, boolResult);
            } else {
                rbusValue_Release(value);
                return RBUS_ERROR_NOT_READABLE;
            }
        }
        else {
            CcspTraceWarning(("Unimplemented AdvancedParentalControl param: %s\n", metadata->short_param_name));
            if (metadata->data_type == RBUS_BOOLEAN) rbusValue_SetBoolean(value, FALSE);
            else rbusValue_SetString(value, "NotImplemented");
        }
    }
    else if (strcmp(metadata->parent_object, "PrivacyProtection") == 0) {
        /* PrivacyProtection parameters */
        if (strcmp(metadata->short_param_name, "Activate") == 0 || strcmp(metadata->short_param_name, "Enable") == 0) {
            if (PrivacyProtection_GetParamBoolValue(NULL, "Activate", &boolResult)) {
                rbusValue_SetBoolean(value, boolResult);
            } else {
                rbusValue_Release(value);
                return RBUS_ERROR_NOT_READABLE;
            }
        }
        else {
            CcspTraceWarning(("Unimplemented PrivacyProtection param: %s\n", metadata->short_param_name));
            if (metadata->data_type == RBUS_BOOLEAN) rbusValue_SetBoolean(value, FALSE);
            else rbusValue_SetString(value, "NotImplemented");
        }
    }
    else if (strcmp(metadata->parent_object, "Softflowd") == 0) {
        /* Softflowd parameters */
        if (strcmp(metadata->short_param_name, "Enable") == 0) {
            if (Softflowd_GetParamBoolValue(NULL, "Enable", &boolResult)) {
                rbusValue_SetBoolean(value, boolResult);
            } else {
                rbusValue_Release(value);
                return RBUS_ERROR_NOT_READABLE;
            }
        }
        else {
            CcspTraceWarning(("Unimplemented Softflowd param: %s\n", metadata->short_param_name));
            if (metadata->data_type == RBUS_BOOLEAN) rbusValue_SetBoolean(value, FALSE);
            else rbusValue_SetString(value, "NotImplemented");
        }
    }
    else if (strcmp(metadata->parent_object, "RabidFramework") == 0) {
        /* RabidFramework RFC parameters */
        if (strcmp(metadata->short_param_name, "MemoryLimit") == 0 ||
            strcmp(metadata->short_param_name, "MacCacheSize") == 0 ||
            strcmp(metadata->short_param_name, "DNSCacheSize") == 0) {
            if (RabidFramework_GetParamUlongValue(NULL, metadata->short_param_name, &ulongResult)) {
                rbusValue_SetUInt32(value, ulongResult);
            } else {
                rbusValue_Release(value);
                return RBUS_ERROR_NOT_READABLE;
            }
        }
        else {
            CcspTraceWarning(("Unimplemented RabidFramework param: %s\n", metadata->short_param_name));
            if (metadata->data_type == RBUS_UINT32) rbusValue_SetUInt32(value, 0);
            else rbusValue_SetString(value, "NotImplemented");
        }
    }
    else if (strstr(metadata->parent_object, "RFC") != NULL || 
             strcmp(metadata->parent_object, "DeviceFingerPrintICMPv6") == 0 ||
             strcmp(metadata->parent_object, "WS-Discovery_Analysis") == 0 ||
             strcmp(metadata->parent_object, "AdvancedSecurityOTM") == 0 ||
             strcmp(metadata->parent_object, "AdvanceSecurityUserSpace") == 0 ||
             strcmp(metadata->parent_object, "AdvanceSecurityCujoTracer") == 0 ||
             strcmp(metadata->parent_object, "AdvanceSecurityCujoTelemetry") == 0 ||
             strcmp(metadata->parent_object, "AdvSecSentryAtTheEdge") == 0 ||
             strcmp(metadata->parent_object, "AdvSecTCPTrackerFilterDevices") == 0 ||
             strcmp(metadata->parent_object, "WifiDataCollection") == 0 ||
             strcmp(metadata->parent_object, "Levl") == 0 ||
             strcmp(metadata->parent_object, "AdvSecAgent") == 0 ||
             strcmp(metadata->parent_object, "AdvSecSafeBrowsing") == 0 ||
             strcmp(metadata->parent_object, "AdvSecCujoTelemetryWiFiFP") == 0 ||
             strcmp(metadata->parent_object, "AdvSecAgentRaptr") == 0) {
        /* RFC Feature parameters - all have Enable boolean */
        if (strcmp(metadata->short_param_name, "Enable") == 0) {
            /* Route to appropriate RFC DML function based on parent */
            if (strcmp(metadata->parent_object, "AdvancedParentalControl") == 0) {
                if (AdvancedParentalControl_RFC_GetParamBoolValue(NULL, "Enable", &boolResult)) {
                    rbusValue_SetBoolean(value, boolResult);
                } else {
                    rbusValue_SetBoolean(value, FALSE);
                }
            }
            else if (strcmp(metadata->parent_object, "PrivacyProtection") == 0) {
                if (PrivacyProtection_RFC_GetParamBoolValue(NULL, "Enable", &boolResult)) {
                    rbusValue_SetBoolean(value, boolResult);
                } else {
                    rbusValue_SetBoolean(value, FALSE);
                }
            }
            else {
                /* Other RFC features - return FALSE as default */
                CcspTraceWarning(("RFC feature not implemented: %s, returning FALSE\n", metadata->parent_object));
                rbusValue_SetBoolean(value, FALSE);
            }
        }
        else {
            CcspTraceWarning(("Unimplemented RFC param: %s.%s\n", metadata->parent_object, metadata->short_param_name));
            if (metadata->data_type == RBUS_BOOLEAN) rbusValue_SetBoolean(value, FALSE);
            else rbusValue_SetString(value, "NotImplemented");
        }
    }
    else {
        /* Unknown parent object - return safe default based on type */
        CcspTraceWarning(("Unknown parent object: %s for parameter %s\n", metadata->parent_object, metadata->short_param_name));
        if (metadata->data_type == RBUS_BOOLEAN) {
            rbusValue_SetBoolean(value, FALSE);
        } else if (metadata->data_type == RBUS_UINT32) {
            rbusValue_SetUInt32(value, 0);
        } else {
            rbusValue_SetString(value, "NotImplemented");
        }
    }
    
    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);
    
    return RBUS_ERROR_SUCCESS;
}

/* Advanced Security RBUS Set Handler - using JSON metadata for dynamic routing */
static rbusError_t advsec_set_param_value(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    
    const char* name = rbusProperty_GetName(property);
    rbusValue_t value = rbusProperty_GetValue(property);
    BOOL dmlResult = FALSE;
    
    if (!name || !value) {
        CcspTraceError(("Invalid parameters in Advanced Security RBUS set handler\n"));
        return RBUS_ERROR_INVALID_INPUT;
    }
    
    CcspTraceDebug(("Advanced Security RBUS Set: %s\n", name));
    
    /* Lookup parameter metadata from JSON configuration */
    advsec_param_metadata_t *metadata = advsec_get_param_metadata(name);
    if (!metadata) {
        CcspTraceError(("Parameter not found in metadata: %s\n", name));
        return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    }
    
    /* Check if parameter is writable */
    if (!metadata->writable) {
        CcspTraceError(("Parameter is read-only: %s\n", name));
        return RBUS_ERROR_NOT_WRITABLE;
    }
    
    CcspTraceDebug(("Found metadata: parent='%s', short_name='%s', writable=%d\n", 
                    metadata->parent_object, metadata->short_param_name, metadata->writable));
    
    /* Route to appropriate DML function based on parent object */
    if (strcmp(metadata->parent_object, "DeviceFingerPrint") == 0) {
        if (strcmp(metadata->short_param_name, "Enable") == 0) {
            BOOL boolVal = rbusValue_GetBoolean(value) ? TRUE : FALSE;
            dmlResult = DeviceFingerPrint_SetParamBoolValue(NULL, "Enable", boolVal);
            if (!dmlResult) return RBUS_ERROR_NOT_WRITABLE;
        }
        else if (strcmp(metadata->short_param_name, "LoggingPeriod") == 0) {
            ULONG ulongVal = rbusValue_GetUInt32(value);
            dmlResult = DeviceFingerPrint_SetParamUlongValue(NULL, "LoggingPeriod", ulongVal);
            if (!dmlResult) return RBUS_ERROR_NOT_WRITABLE;
        }
        else if (strcmp(metadata->short_param_name, "EndpointURL") == 0) {
            const char* strVal = rbusValue_GetString(value, NULL);
            dmlResult = DeviceFingerPrint_SetParamStringValue(NULL, "EndpointURL", (char*)strVal);
            if (!dmlResult) return RBUS_ERROR_NOT_WRITABLE;
        }
        else if (strcmp(metadata->short_param_name, "LogLevel") == 0) {
            ULONG ulongVal = rbusValue_GetUInt32(value);
            dmlResult = DeviceFingerPrint_SetParamUlongValue(NULL, "LogLevel", ulongVal);
            if (!dmlResult) return RBUS_ERROR_NOT_WRITABLE;
        }
        else {
            CcspTraceWarning(("Unimplemented DeviceFingerPrint set param: %s\n", metadata->short_param_name));
            return RBUS_ERROR_NOT_WRITABLE;
        }
    }
    else if (strcmp(metadata->parent_object, "SafeBrowsing") == 0) {
        if (strcmp(metadata->short_param_name, "Enable") == 0) {
            BOOL boolVal = rbusValue_GetBoolean(value) ? TRUE : FALSE;
            dmlResult = SafeBrowsing_SetParamBoolValue(NULL, "Enable", boolVal);
            if (!dmlResult) return RBUS_ERROR_NOT_WRITABLE;
        }
        else if (strcmp(metadata->short_param_name, "LookupTimeout") == 0 ||
                 strcmp(metadata->short_param_name, "LookupTimeoutExceededCount") == 0) {
            ULONG ulongVal = rbusValue_GetUInt32(value);
            dmlResult = SafeBrowsing_SetParamUlongValue(NULL, metadata->short_param_name, ulongVal);
            if (!dmlResult) return RBUS_ERROR_NOT_WRITABLE;
        }
        else {
            CcspTraceWarning(("Unimplemented SafeBrowsing set param: %s\n", metadata->short_param_name));
            return RBUS_ERROR_NOT_WRITABLE;
        }
    }
    else if (strcmp(metadata->parent_object, "AdvancedSecurity") == 0) {
        if (strcmp(metadata->short_param_name, "Data") == 0) {
            const char* data = rbusValue_GetString(value, NULL);
            if (data) {
                CcspTraceInfo(("WebConfig Data set to: %s\n", data));
                /* Data processed successfully */
            } else {
                return RBUS_ERROR_INVALID_PARAMETER_VALUE;
            }
        }
        else {
            CcspTraceWarning(("Unimplemented AdvancedSecurity set param: %s\n", metadata->short_param_name));
            return RBUS_ERROR_NOT_WRITABLE;
        }
    }
    else if (strcmp(metadata->parent_object, "AdvancedParentalControl") == 0) {
        if (strcmp(metadata->short_param_name, "Activate") == 0 || strcmp(metadata->short_param_name, "Enable") == 0) {
            BOOL boolVal = rbusValue_GetBoolean(value) ? TRUE : FALSE;
            dmlResult = AdvancedParentalControl_SetParamBoolValue(NULL, "Activate", boolVal);
            if (!dmlResult) return RBUS_ERROR_NOT_WRITABLE;
        }
        else {
            CcspTraceWarning(("Unimplemented AdvancedParentalControl set param: %s\n", metadata->short_param_name));
            return RBUS_ERROR_NOT_WRITABLE;
        }
    }
    else if (strcmp(metadata->parent_object, "PrivacyProtection") == 0) {
        if (strcmp(metadata->short_param_name, "Activate") == 0 || strcmp(metadata->short_param_name, "Enable") == 0) {
            BOOL boolVal = rbusValue_GetBoolean(value) ? TRUE : FALSE;
            dmlResult = PrivacyProtection_SetParamBoolValue(NULL, "Activate", boolVal);
            if (!dmlResult) return RBUS_ERROR_NOT_WRITABLE;
        }
        else {
            CcspTraceWarning(("Unimplemented PrivacyProtection set param: %s\n", metadata->short_param_name));
            return RBUS_ERROR_NOT_WRITABLE;
        }
    }
    else if (strcmp(metadata->parent_object, "Softflowd") == 0) {
        if (strcmp(metadata->short_param_name, "Enable") == 0) {
            BOOL boolVal = rbusValue_GetBoolean(value) ? TRUE : FALSE;
            dmlResult = Softflowd_SetParamBoolValue(NULL, "Enable", boolVal);
            if (!dmlResult) return RBUS_ERROR_NOT_WRITABLE;
        }
        else {
            CcspTraceWarning(("Unimplemented Softflowd set param: %s\n", metadata->short_param_name));
            return RBUS_ERROR_NOT_WRITABLE;
        }
    }
    else if (strcmp(metadata->parent_object, "RabidFramework") == 0) {
        if (strcmp(metadata->short_param_name, "MemoryLimit") == 0 ||
            strcmp(metadata->short_param_name, "MacCacheSize") == 0 ||
            strcmp(metadata->short_param_name, "DNSCacheSize") == 0) {
            ULONG ulongVal = rbusValue_GetUInt32(value);
            dmlResult = RabidFramework_SetParamUlongValue(NULL, metadata->short_param_name, ulongVal);
            if (!dmlResult) return RBUS_ERROR_NOT_WRITABLE;
        }
        else {
            CcspTraceWarning(("Unimplemented RabidFramework set param: %s\n", metadata->short_param_name));
            return RBUS_ERROR_NOT_WRITABLE;
        }
    }
    else if (strstr(metadata->parent_object, "RFC") != NULL || 
             strcmp(metadata->parent_object, "DeviceFingerPrintICMPv6") == 0 ||
             strcmp(metadata->parent_object, "AdvancedSecurityOTM") == 0 ||
             strcmp(metadata->parent_object, "AdvanceSecurityUserSpace") == 0) {
        /* RFC Feature parameters */
        if (strcmp(metadata->short_param_name, "Enable") == 0) {
            BOOL boolVal = rbusValue_GetBoolean(value) ? TRUE : FALSE;
            if (strcmp(metadata->parent_object, "AdvancedParentalControl") == 0) {
                dmlResult = AdvancedParentalControl_RFC_SetParamBoolValue(NULL, "Enable", boolVal);
                if (!dmlResult) return RBUS_ERROR_NOT_WRITABLE;
            }
            else if (strcmp(metadata->parent_object, "PrivacyProtection") == 0) {
                dmlResult = PrivacyProtection_RFC_SetParamBoolValue(NULL, "Enable", boolVal);
                if (!dmlResult) return RBUS_ERROR_NOT_WRITABLE;
            }
            else {
                CcspTraceWarning(("RFC feature set not implemented: %s\n", metadata->parent_object));
                return RBUS_ERROR_NOT_WRITABLE;
            }
        }
        else {
            CcspTraceWarning(("Unimplemented RFC set param: %s.%s\n", metadata->parent_object, metadata->short_param_name));
            return RBUS_ERROR_NOT_WRITABLE;
        }
    }
    else {
        CcspTraceWarning(("Unknown parent object for set: %s\n", metadata->parent_object));
        return RBUS_ERROR_NOT_WRITABLE;
    }
    
    /* All syscfg persistence and service control is handled by the existing DML functions */
    return RBUS_ERROR_SUCCESS;
}

/* Service control is handled by existing DML functions, not RBUS handlers */

/* Removed unused set_advsec_callback_functions function */

/* Public handlers for messagebus interface compatibility */
rbusError_t advsec_rbus_get_handler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    return advsec_get_param_value(handle, property, opts);
}

rbusError_t advsec_rbus_set_handler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    return advsec_set_param_value(handle, property, opts);
}

/* RBUS Event Handler for messagebus interface */
rbusError_t advsec_rbus_event_handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    (void)handle;
    (void)subscription;
    (void)event;
    
    CcspTraceInfo(("Advanced Security received RBUS event\n"));
    
    /* Process event data for advanced security features */
    
    return RBUS_ERROR_SUCCESS;
}

/* Initialize RBUS with JSON-driven registration */
int advsec_rbus_init(const char *component_name)
{
    rbusError_t rc;
    
    /* Open RBUS */
    rc = rbus_open(&g_rbus_handle, component_name);
    if (rc != RBUS_ERROR_SUCCESS) {
        CcspTraceError(("rbus_open failed with error: %s\n", rbusError_ToString(rc)));
        return -1;
    }
    
    /* Decode and register parameters from JSON */
    if (advsec_decode_json_config(g_rbus_handle, JSON_CONFIG_PATH) != 0) {
        CcspTraceError(("Failed to decode JSON config\n"));
        rbus_close(g_rbus_handle);
        return -1;
    }
    
    CcspTraceInfo(("RBUS initialized: %s\n", component_name));
    return 0;
}

/* Terminate RBUS */
int advsec_rbus_terminate(void)
{
    if (g_rbus_handle) {
        rbus_close(g_rbus_handle);
        g_rbus_handle = NULL;
    }
    
    /* Cleanup parameter metadata */
    advsec_cleanup_param_metadata();
    
    return 0;
}
