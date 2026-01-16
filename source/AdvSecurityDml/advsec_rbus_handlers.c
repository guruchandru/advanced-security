/*
 * Lightweight RBUS handlers for Advanced Security
 * Stateless RBUS handlers: no in-memory storage, direct backend operations only
 */

#include "advsec_rbus_handlers.h"
#include "advsec_bus_json_decode.h"
#include "advsec_compat_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

/* Global RBUS handle */
static rbusHandle_t g_rbus_handle = NULL;

/* Helper to control agents */
static void control_agent(const char *service, bool enable)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "systemctl %s %s 2>/dev/null", 
             enable ? "start" : "stop", service);
    system(cmd);
}

/* RBUS Get Handler - Returns defaults, backend maintains actual state */
rbusError_t advsec_rbus_get_handler(rbusHandle_t handle, rbusProperty_t property, 
                                     rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    
    const char* name = rbusProperty_GetName(property);
    rbusValue_t value;
    
    rbusValue_Init(&value);
    
    /* Return appropriate defaults based on parameter type */
    if (strstr(name, "Enable") || strstr(name, "Activate")) {
        rbusValue_SetBoolean(value, false);
    } else if (strstr(name, "Period") || strstr(name, "Interval") || strstr(name, "Count")) {
        rbusValue_SetUInt32(value, 0);
    } else {
        rbusValue_SetString(value, "");
    }
    
    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);
    
    return RBUS_ERROR_SUCCESS;
}

/* RBUS Set Handler - Triggers backend actions directly */
rbusError_t advsec_rbus_set_handler(rbusHandle_t handle, rbusProperty_t property, 
                                     rbusSetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    
    const char* name = rbusProperty_GetName(property);
    rbusValue_t value = rbusProperty_GetValue(property);
    
    /* Device Fingerprint */
    if (strstr(name, "DeviceFingerPrint.Enable")) {
        control_agent("fingerprint.service", rbusValue_GetBoolean(value));
    }
    /* SafeBrowsing */
    else if (strstr(name, "SafeBrowsing.Enable")) {
        control_agent("safebrowsing.service", rbusValue_GetBoolean(value));
    }
    /* Parental Control */
    else if (strstr(name, "AdvancedParentalControl.Activate")) {
        control_agent("cujo-agent.service", rbusValue_GetBoolean(value));
    }
    /* Privacy Protection - no action needed, service handles internally */
    else if (strstr(name, "PrivacyProtection.Activate")) {
        /* Backend service monitors this via other mechanisms */
    }
    /* Webconfig Blob */
    else if (strstr(name, "AdvancedSecurity.Data")) {
        const char *data = rbusValue_GetString(value, NULL);
        if (data && strlen(data) > 0) {
            FILE *fp = fopen("/tmp/advsec_webconfig.bin", "w");
            if (fp) {
                fwrite(data, 1, strlen(data), fp);
                fclose(fp);
                /* Service monitors /tmp/advsec_webconfig.bin via inotify or polling */
            }
        }
    }
    /* Softflowd */
    else if (strstr(name, "Softflowd.Enable")) {
        control_agent("softflowd.service", rbusValue_GetBoolean(value));
    }
    /* RFC Features - scripts read from syscfg, no notification needed */
    else if (strstr(name, "RFC.Feature.") && strstr(name, ".Enable")) {
        /* Scripts monitor syscfg/config changes directly */
    }
    
    return RBUS_ERROR_SUCCESS;
}

/* Initialize RBUS */
int advsec_rbus_init(const char *component_name)
{
    rbusError_t rc;
    
    /* Open RBUS */
    rc = rbus_open(&g_rbus_handle, component_name);
    if (rc != RBUS_ERROR_SUCCESS) {
        CcspTraceError(("rbus_open failed: %d\n", rc));
        return -1;
    }
    
    /* Decode and register parameters from JSON */
    if (advsec_decode_json_config(g_rbus_handle, "advsec_dml_config.json") != 0) {
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
    
    return 0;
}
