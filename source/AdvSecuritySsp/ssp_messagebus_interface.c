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

/**********************************************************************

    module: ssp_messagebus_interface.c

        For Advanced Security module

    description:

        SSP implementation of the CCSP Message Bus Interface
        Service.

        *   ssp_AdvsecMbi_MessageBusEngage
        *   ssp_AdvsecMbi_EventCallback

**********************************************************************/

/* Compatibility includes to replace common-library */
#include "../AdvSecurityDml/advsec_compat_types.h"
#include "../AdvSecurityDml/advsec_rbus_handlers.h"  /* RBUS handlers */
#include <rbus/rbus.h>  /* RBUS API */

#include "ssp_global.h"


ANSC_HANDLE                 bus_handle         = NULL;
extern ANSC_HANDLE          g_MessageBusHandle_Irep;
extern char                 g_SubSysPrefix_Irep[32];
extern char                 g_Subsystem[32];
extern  BOOL                g_bActive;

#ifdef _ANSC_LINUX
ANSC_STATUS
ssp_AdvsecMbi_MessageBusEngage
    (
        char * component_id,
        char * config_file,
        char * path
    )
{
    (void)config_file; /* Unused parameter */
    /* ANSC_STATUS                 returnStatus       = ANSC_STATUS_SUCCESS; */
    /* Legacy CCSP_Base_Func_CB will be replaced with RBUS method handlers */
    #if 0
    CCSP_Base_Func_CB           cb                 = {0};
    #endif
    errno_t                     rc                 = -1;

    /* Mark unused parameters in RBUS implementation */
    UNREFERENCED_PARAMETER(config_file);

    if ( ! component_id || ! path )
    {
        CcspTraceError((" !!! ssp_AdvsecMbi_MessageBusEngage: component_id or path is NULL !!!\n"));
        return ANSC_STATUS_FAILURE;
    }

    /* Legacy CCSP_Message_Bus_Init will be replaced with rbus_open(). Ansc_AllocateMemory_Callback/Ansc_FreeMemory_Callback not needed in RBUS. */
    #if 0
    /* Connect to message bus */
    returnStatus =
        CCSP_Message_Bus_Init
            (
                component_id,
                config_file,
                &bus_handle,
                (CCSP_MESSAGE_BUS_MALLOC)Ansc_AllocateMemory_Callback,           /* mallocfc, use default */
                Ansc_FreeMemory_Callback                                         /* freefc,   use default */
            );

    if ( returnStatus != ANSC_STATUS_SUCCESS )
    {
        CcspTraceError((" !!! ADVSEC Message Bus Init ERROR !!!\n"));

        return returnStatus;
    }
    ssp_AdvsecMbi_WaitConditionReady(bus_handle, CCSP_DBUS_PSM, CCSP_DBUS_PATH_PSM, component_id);
    #endif
    /* RBUS initialization - replaces legacy DBUS */
    rbusError_t ret = rbus_open((rbusHandle_t*)&bus_handle, component_id);
    if (ret != RBUS_ERROR_SUCCESS) {
        CcspTraceError(("Advanced Security: Failed to open RBUS connection: %d\n", ret));
        return ANSC_STATUS_FAILURE;
    }
    
    CcspTraceInfo(("Advanced Security: RBUS connection established: %s\n", component_id));
    g_MessageBusHandle_Irep = bus_handle;
    rc = strcpy_s(g_SubSysPrefix_Irep, sizeof(g_SubSysPrefix_Irep), g_Subsystem);
    if(rc != EOK)
    {
         ERR_CHK(rc);
         rbus_close((rbusHandle_t)bus_handle);
         return ANSC_STATUS_FAILURE;
    }

    /* Initialize Advanced Security RBUS handlers with JSON pattern */
    if (advsec_rbus_init(component_id) != 0) {
        CcspTraceError(("Failed to initialize Advanced Security RBUS handlers\n"));
        rbus_close((rbusHandle_t)bus_handle);
        return ANSC_STATUS_FAILURE;
    }

    /* Legacy callback structure assignments will be replaced with RBUS method handlers */
    #if 0
    /* Base interface implementation that will be used cross components */
    cb.getParameterValues     = CcspCcMbi_GetParameterValues;
    cb.setParameterValues     = CcspCcMbi_SetParameterValues;
    cb.setCommit              = CcspCcMbi_SetCommit;
    cb.setParameterAttributes = CcspCcMbi_SetParameterAttributes;
    cb.getParameterAttributes = CcspCcMbi_GetParameterAttributes;
    cb.AddTblRow              = CcspCcMbi_AddTblRow;
    cb.DeleteTblRow           = CcspCcMbi_DeleteTblRow;
    cb.getParameterNames      = CcspCcMbi_GetParameterNames;
    cb.currentSessionIDSignal = CcspCcMbi_CurrentSessionIdSignal;

    /* Base interface implementation that will only be used by Advsec */
    cb.initialize             = ssp_AdvsecMbi_Initialize;
    cb.finalize               = ssp_AdvsecMbi_Finalize;
    cb.freeResources          = ssp_AdvsecMbi_FreeResources;
    cb.busCheck               = ssp_AdvsecMbi_Buscheck;

    /*Componet Health*/
    cb.getHealth              = ssp_AdvsecMbi_GetHealth;

    /* RBUS event subscription - replaces DBUS event registration */
    ret = rbusEvent_Subscribe((rbusHandle_t)bus_handle, "Device.WiFi.WebConfig.Data.Subdoc.North", 
                               advsec_rbus_event_handler, NULL, NULL);
    if (ret != RBUS_ERROR_SUCCESS) {
        CcspTraceWarning(("Failed to subscribe to WiFi WebConfig event: %s\n", rbusError_ToString(ret)));
        /* Continue without WebConfig events - not critical */
    } else {
        CcspTraceInfo(("Advanced Security subscribed to WiFi WebConfig events\n"));
    }
    
    /* Subscribe to device configuration events */
    ret = rbusEvent_Subscribe((rbusHandle_t)bus_handle, "Device.DeviceInfo.X_COMCAST-COM_xOpsDeviceMgmt.RPC.RebootDevice", 
                               advsec_rbus_event_handler, NULL, NULL);
    if (ret != RBUS_ERROR_SUCCESS) {
        CcspTraceWarning(("Failed to subscribe to device management event: %s\n", rbusError_ToString(ret)));
        /* Continue without device management events - not critical */
    } else {
        CcspTraceInfo(("Advanced Security subscribed to device management events\n"));
    }
#endif
    return ANSC_STATUS_SUCCESS;
}

__attribute__((unused))
int
ssp_AdvsecMbi_Initialize
    (
        void * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    ANSC_STATUS             returnStatus    = ANSC_STATUS_SUCCESS;

    CcspTraceInfo(("In ssp_AdvsecMbi_Initialize()\n"));

    /* CID 63136 Logically dead code */
    return returnStatus;
}

__attribute__((unused))
int
ssp_AdvsecMbi_Finalize
    (
        void * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    ANSC_STATUS             returnStatus    = ANSC_STATUS_SUCCESS;

    CcspTraceInfo(("In ssp_AdvsecMbi_Finalize()\n"));

    /* CID 71564: Logically dead code */
    return returnStatus;
}


__attribute__((unused))
int
ssp_AdvsecMbi_Buscheck
    (
        void * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    CcspTraceInfo(("In ssp_AdvsecMbi_Buscheck()\n"));

    return 0;
}

__attribute__((unused))
int
ssp_AdvsecMbi_FreeResources
    (
        int priority,
        void * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    UNREFERENCED_PARAMETER(priority);
    ANSC_STATUS             returnStatus    = ANSC_STATUS_SUCCESS;

    CcspTraceInfo(("In ssp_AdvsecMbi_FreeResources()\n"));

    /* CID 67240: Logically dead code */
    return returnStatus;
}


#endif /* _ANSC_LINUX */
