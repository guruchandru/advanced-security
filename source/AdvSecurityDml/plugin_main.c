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

/*
 * Legacy platform includes commented out for JSON-driven RBUS approach
 * These will be replaced with RBUS-based JSON configuration
 * Legacy common-library header commented out for JSON-driven RBUS approach
 * #include "ansc_platform.h"
 * Legacy common-library headers commented out for JSON-driven RBUS approach
 * #include "ansc_load_library.h"
 * #include "cosa_plugin_api.h"
 */
#include "plugin_main.h"

#ifdef WIFI_DATA_COLLECTION
#include "cujoagent_dcl_api.h"
#endif

#include "cosa_adv_security_dml.h"
#include "cosa_adv_security_internal.h"
#define THIS_PLUGIN_VERSION                         1

COSA_DATAMODEL_AGENT* g_pAdvSecAgent = NULL;
/*
#ifdef WIFI_DATA_COLLECTION
cujoagent_wifi_consumer_t *g_cujoagent_dcl = NULL;
#endif
*/

/* DML plugin initialization commented out for JSON-based RBUS registration. This entire COSA_Init function will be replaced with RBUS-based JSON registration. */
#if 0
int ANSC_EXPORT_API
COSA_Init
    (
        ULONG                       uMaxVersionSupported, 
        void*                       hCosaPlugInfo         /* PCOSA_PLUGIN_INFO passed in by the caller */
    )
{
    PCOSA_PLUGIN_INFO               pPlugInfo  = (PCOSA_PLUGIN_INFO)hCosaPlugInfo;

    if ( uMaxVersionSupported < THIS_PLUGIN_VERSION )
    {
    	CcspTraceError(("%s Exit ERROR Version not supported! \n", __FUNCTION__));

      /* this version is not supported */
        return -1;
    }   
    
    pPlugInfo->uPluginVersion       = THIS_PLUGIN_VERSION;
    /* register the back-end apis for the data model */
    CcspTraceInfo(("Registering the back-end apis for the data model\n"));

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DeviceFingerPrint_GetParamBoolValue",  DeviceFingerPrint_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DeviceFingerPrint_SetParamBoolValue",  DeviceFingerPrint_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DeviceFingerPrint_GetParamUlongValue",  DeviceFingerPrint_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DeviceFingerPrint_SetParamUlongValue",  DeviceFingerPrint_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DeviceFingerPrint_GetParamStringValue",  DeviceFingerPrint_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DeviceFingerPrint_SetParamStringValue",  DeviceFingerPrint_SetParamStringValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvancedSecurity_SetParamStringValue",  AdvancedSecurity_SetParamStringValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SafeBrowsing_GetParamBoolValue",  SafeBrowsing_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SafeBrowsing_SetParamBoolValue",  SafeBrowsing_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SafeBrowsing_GetParamUlongValue",  SafeBrowsing_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SafeBrowsing_SetParamUlongValue",  SafeBrowsing_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SafeBrowsing_GetParamStringValue",  SafeBrowsing_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SafeBrowsing_Validate",  SafeBrowsing_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SafeBrowsing_Commit",  SafeBrowsing_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "SafeBrowsing_Rollback",  SafeBrowsing_Rollback);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Softflowd_GetParamBoolValue",  Softflowd_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Softflowd_SetParamBoolValue",  Softflowd_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Softflowd_Validate",  Softflowd_Validate);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Softflowd_Commit",  Softflowd_Commit);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "Softflowd_Rollback",  Softflowd_Rollback);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RabidFramework_GetParamUlongValue", RabidFramework_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "RabidFramework_SetParamUlongValue", RabidFramework_SetParamUlongValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvancedParentalControl_RFC_GetParamBoolValue", AdvancedParentalControl_RFC_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvancedParentalControl_RFC_SetParamBoolValue", AdvancedParentalControl_RFC_SetParamBoolValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PrivacyProtection_RFC_GetParamBoolValue", PrivacyProtection_RFC_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "PrivacyProtection_RFC_SetParamBoolValue", PrivacyProtection_RFC_SetParamBoolValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DeviceFingerPrintICMPv6_RFC_GetParamBoolValue", DeviceFingerPrintICMPv6_RFC_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "DeviceFingerPrintICMPv6_RFC_SetParamBoolValue", DeviceFingerPrintICMPv6_RFC_SetParamBoolValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "WS_Discovery_Analysis_RFC_GetParamBoolValue", WS_Discovery_Analysis_RFC_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "WS_Discovery_Analysis_RFC_SetParamBoolValue", WS_Discovery_Analysis_RFC_SetParamBoolValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvancedSecurityOTM_RFC_GetParamBoolValue", AdvancedSecurityOTM_RFC_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvancedSecurityOTM_RFC_SetParamBoolValue", AdvancedSecurityOTM_RFC_SetParamBoolValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvSecAgentRaptr_RFC_GetParamBoolValue", AdvSecAgentRaptr_RFC_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvSecAgentRaptr_RFC_SetParamBoolValue", AdvSecAgentRaptr_RFC_SetParamBoolValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvanceSecurityUserSpace_RFC_GetParamBoolValue", AdvanceSecurityUserSpace_RFC_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvanceSecurityUserSpace_RFC_SetParamBoolValue", AdvanceSecurityUserSpace_RFC_SetParamBoolValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "WifiDataCollection_RFC_GetParamBoolValue", WifiDataCollection_RFC_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "WifiDataCollection_RFC_SetParamBoolValue", WifiDataCollection_RFC_SetParamBoolValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvSecAgent_RFC_GetParamBoolValue", AdvSecAgent_RFC_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvSecAgent_RFC_SetParamBoolValue", AdvSecAgent_RFC_SetParamBoolValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvSecSafeBrowsing_RFC_GetParamBoolValue", AdvSecSafeBrowsing_RFC_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvSecSafeBrowsing_RFC_SetParamBoolValue", AdvSecSafeBrowsing_RFC_SetParamBoolValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvSecCujoTelemetryWiFiFP_RFC_GetParamBoolValue", AdvSecCujoTelemetryWiFiFP_RFC_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvSecCujoTelemetryWiFiFP_RFC_SetParamBoolValue", AdvSecCujoTelemetryWiFiFP_RFC_SetParamBoolValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvanceSecurityCujoTracer_RFC_GetParamBoolValue", AdvanceSecurityCujoTracer_RFC_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvanceSecurityCujoTracer_RFC_SetParamBoolValue", AdvanceSecurityCujoTracer_RFC_SetParamBoolValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvanceSecurityCujoTelemetry_RFC_GetParamBoolValue", AdvanceSecurityCujoTelemetry_RFC_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvanceSecurityCujoTelemetry_RFC_SetParamBoolValue", AdvanceSecurityCujoTelemetry_RFC_SetParamBoolValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvSecSentryAtTheEdge_RFC_GetParamBoolValue", AdvSecSentryAtTheEdge_RFC_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvSecSentryAtTheEdge_RFC_SetParamBoolValue", AdvSecSentryAtTheEdge_RFC_SetParamBoolValue);

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvSecTCPTrackerFilterDevices_RFC_GetParamBoolValue", AdvSecTCPTrackerFilterDevices_RFC_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "AdvSecTCPTrackerFilterDevices_RFC_SetParamBoolValue", AdvSecTCPTrackerFilterDevices_RFC_SetParamBoolValue);

    /* Create Object for Settings */
    g_pAdvSecAgent = (PCOSA_DATAMODEL_AGENT)CosaSecurityCreate();

#ifdef WIFI_DATA_COLLECTION
    g_cujoagent_dcl = AnscAllocateMemory(sizeof *g_cujoagent_dcl);
    if (!g_cujoagent_dcl)
    {
        CcspTraceError(("%s: failed to allocate the memory for wifi data collection consumer\n", __FUNCTION__));
    }
#endif

    if ( g_pAdvSecAgent )
    {
    	  CcspTraceInfo(("Initializing CosaAdvSecurityAgent\n"));
    	  CosaSecurityInitialize(g_pAdvSecAgent);
    }
    else
    {
    	CcspTraceError(("%s exit ERROR CosaAdvSecurityCreate returned 0!!!\n", __FUNCTION__));
    }

    return  0;
}

BOOL ANSC_EXPORT_API
COSA_IsObjectSupported
    (
        char*                        pObjName
    )
{
    UNREFERENCED_PARAMETER(pObjName);
    return TRUE;
}

void ANSC_EXPORT_API
COSA_Unload
    (
        void
    )
{
    /* unload the memory here */
    if ( g_pAdvSecAgent )
    {
        
        CosaSecurityRemove(g_pAdvSecAgent);
    }

    g_pAdvSecAgent = NULL;

#ifdef WIFI_DATA_COLLECTION
    if (g_cujoagent_dcl)
    {
        AnscFreeMemory(g_cujoagent_dcl);
    }
    g_cujoagent_dcl = NULL;
#endif
}
#endif /* End of commented DML plugin functions */
