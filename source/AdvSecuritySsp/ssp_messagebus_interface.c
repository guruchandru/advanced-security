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
    /* ANSC_STATUS                 returnStatus       = ANSC_STATUS_SUCCESS; */
    void*                       bus_handle         = NULL;  /* RBUS handle placeholder */
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
    CcspTraceInfo(("!!! Connected to message bus... bus_handle: 0x%8p !!!\n", bus_handle));
    g_MessageBusHandle_Irep = bus_handle;
    rc = strcpy_s(g_SubSysPrefix_Irep, sizeof(g_SubSysPrefix_Irep), g_Subsystem);
    if(rc != EOK)
    {
         ERR_CHK(rc);
         return ANSC_STATUS_FAILURE;
    }

    CCSP_Msg_SleepInMilliSeconds(1000);

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

    /* Legacy messagebus callback registrations will be replaced with RBUS method registrations (CcspBaseIf_SetCallback -> rbus_registerMethod(), CcspBaseIf_Register_Event -> rbus_subscribeToEvent()) */
    CcspBaseIf_SetCallback(bus_handle, &cb);



    /* Register event/signal */
    returnStatus =
        CcspBaseIf_Register_Event
            (
                bus_handle,
                0,
                "currentSessionIDSignal"
            );

    if ( returnStatus != CCSP_Message_Bus_OK )
    {
        CcspTraceError((" !!! CCSP_Message_Bus_Register_Event: CurrentSessionIDSignal ERROR returnStatus: %lu!!!\n", returnStatus));

        return returnStatus;
    }
    #endif

    return ANSC_STATUS_SUCCESS;
}


#endif

int
ssp_AdvsecMbi_Initialize
    (
        void * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    ANSC_STATUS             returnStatus    = ANSC_STATUS_SUCCESS;

    CcspTraceInfo(("In %s()\n", __FUNCTION__));

    /* CID 63136 Logically dead code */
    return returnStatus;
}

int
ssp_AdvsecMbi_Finalize
    (
        void * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    ANSC_STATUS             returnStatus    = ANSC_STATUS_SUCCESS;

    CcspTraceInfo(("In %s()\n", __FUNCTION__));

    /* CID 71564: Logically dead code */
    return returnStatus;
}


int
ssp_AdvsecMbi_Buscheck
    (
        void * user_data
    )
{
    UNREFERENCED_PARAMETER(user_data);
    CcspTraceInfo(("In %s()\n", __FUNCTION__));

    return 0;
}

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

    CcspTraceInfo(("In %s()\n", __FUNCTION__));

    /* CID 67240: Logically dead code */
    return returnStatus;
}

