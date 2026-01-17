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

    module: ssp_action.c

        For CCSP ADVSEC Module

    description:

        SSP implementation of the ADVSEC module.

        *   ssp_create_advsec
        *   ssp_engage_advsec
        *   ssp_cancel_advsec
        *   ssp_AdvSecCCDmGetComponentName
        *   ssp_AdvSecCCDmGetComponentVersion
        *   ssp_AdvSecCCDmGetComponentAuthor
        *   ssp_AdvSecCCDmGetComponentHealth
        *   ssp_AdvSecCCDmGetComponentState
        *   ssp_AdvSecCCDmGetLoggingEnabled
        *   ssp_AdvSecCCDmSetLoggingEnabled
        *   ssp_AdvSecCCDmGetLoggingLevel
        *   ssp_AdvSecCCDmSetLoggingLevel
        *   ssp_AdvSecCCDmGetMemMaxUsage
        *   ssp_AdvSecCCDmGetMemMinUsage
        *   ssp_AdvSecCCDmGetMemConsumed

**********************************************************************/

#include "ssp_global.h"
/* Compatibility types to replace common-library */
#include "../AdvSecurityDml/advsec_compat_types.h"
/* Legacy ccsp_trace macros replaced by advsec_compat_types.h */
/* #include "ccsp_trace.h" */
#include <time.h>
/* Legacy common-library includes commented out for JSON-driven RBUS approach */
/* #include "cosa_plugin_api.h" */
/* #include "dm_pack_create_func.h" */
extern ULONG                            g_ulAllocatedSizePeak;

/* RBUS Implementation Global Variables */
PCOMPONENT_COMMON_DM            g_pComponent_Common_Dm  = NULL;
PCCSP_FC_CONTEXT                pAdvSecFcContext        = NULL;
PCCSP_CCD_INTERFACE             pAdvSecCcdIf           = NULL;
int                             g_iTraceLevel          = CCSP_TRACE_LEVEL_INFO;

/* Legacy common-library global variable externs commented out for JSON-driven RBUS approach */
/* extern  PDSLH_CPE_CONTROLLER_OBJECT     pDslhCpeController; */
/* extern  PDSLH_DATAMODEL_AGENT_OBJECT    g_DslhDataModelAgent; */
/* extern  PCOMPONENT_COMMON_DM            g_pComponent_Common_Dm; */
/* extern  PCCSP_FC_CONTEXT                 pAdvSecFcContext; */
/* extern  PCCSP_CCD_INTERFACE              pAdvSecCcdIf; */
/* extern  ANSC_HANDLE                     bus_handle; */
extern  char                            g_Subsystem[32];

#ifdef DOWNLOADMODULE_ENABLE
#define TEMP_DOWNLOAD_LOCATION "/tmp/cujo_dnld"
#else
#define TEMP_DOWNLOAD_LOCATION ""
#endif

#define  COSA_PLUGIN_XML_FILE           TEMP_DOWNLOAD_LOCATION"/usr/ccsp/advsec/TR181-AdvSecurity.xml"

COSAGetParamValueByPathNameProc     g_GetParamValueByPathNameProc   = NULL;

/* Legacy functions commented out for JSON-based RBUS registration */
#if 0
ANSC_HANDLE
COSAAcquireFunction
    (
        char*                       pApiName
    );

ANSC_STATUS
ssp_create_advsec
    (
    )
{
    errno_t rc = -1;
    /* Create component common data model object */

    g_pComponent_Common_Dm = (PCOMPONENT_COMMON_DM)AnscAllocateMemory(sizeof(COMPONENT_COMMON_DM));

    if ( !g_pComponent_Common_Dm )
    {
        return ANSC_STATUS_RESOURCES;
    }

    ComponentCommonDmInit(g_pComponent_Common_Dm);

    g_pComponent_Common_Dm->Name     = AnscCloneString(CCSP_COMPONENT_NAME_ADVSEC);
    g_pComponent_Common_Dm->Version  = 1;
    g_pComponent_Common_Dm->Author   = AnscCloneString("CCSP");


    /* Create ComponentCommonDatamodel interface*/
    if ( !pAdvSecCcdIf )
    {
        pAdvSecCcdIf = (PCCSP_CCD_INTERFACE)AnscAllocateMemory(sizeof(CCSP_CCD_INTERFACE));

        if ( !pAdvSecCcdIf )
        {
            return ANSC_STATUS_RESOURCES;
        }
        else
        {
            rc = strcpy_s(pAdvSecCcdIf->Name, sizeof(pAdvSecCcdIf->Name), CCSP_CCD_INTERFACE_NAME);
            if(rc != EOK)
            {
                ERR_CHK(rc);
                return ANSC_STATUS_FAILURE;
            }

            pAdvSecCcdIf->InterfaceId              = CCSP_CCD_INTERFACE_ID;
            pAdvSecCcdIf->hOwnerContext            = NULL;
            pAdvSecCcdIf->Size                     = sizeof(CCSP_CCD_INTERFACE);

            pAdvSecCcdIf->GetComponentName         = ssp_AdvSecCCDmGetComponentName;
            pAdvSecCcdIf->GetComponentVersion      = ssp_AdvSecCCDmGetComponentVersion;
            pAdvSecCcdIf->GetComponentAuthor       = ssp_AdvSecCCDmGetComponentAuthor;
            pAdvSecCcdIf->GetComponentHealth       = ssp_AdvSecCCDmGetComponentHealth;
            pAdvSecCcdIf->GetComponentState        = ssp_AdvSecCCDmGetComponentState;
            pAdvSecCcdIf->GetLoggingEnabled        = ssp_AdvSecCCDmGetLoggingEnabled;
            pAdvSecCcdIf->SetLoggingEnabled        = ssp_AdvSecCCDmSetLoggingEnabled;
            pAdvSecCcdIf->GetLoggingLevel          = ssp_AdvSecCCDmGetLoggingLevel;
            pAdvSecCcdIf->SetLoggingLevel          = ssp_AdvSecCCDmSetLoggingLevel;
            pAdvSecCcdIf->GetMemMaxUsage           = ssp_AdvSecCCDmGetMemMaxUsage;
            pAdvSecCcdIf->GetMemMinUsage           = ssp_AdvSecCCDmGetMemMinUsage;
            pAdvSecCcdIf->GetMemConsumed           = ssp_AdvSecCCDmGetMemConsumed;
            pAdvSecCcdIf->ApplyChanges             = ssp_AdvSecCCDmApplyChanges;
        }
    }

    /* Create context used by data model */
    pAdvSecFcContext = (PCCSP_FC_CONTEXT)AnscAllocateMemory(sizeof(CCSP_FC_CONTEXT));

    if ( !pAdvSecFcContext )
    {
        return ANSC_STATUS_RESOURCES;
    }
    else
    {
        AnscZeroMemory(pAdvSecFcContext, sizeof(CCSP_FC_CONTEXT));
    }

    pDslhCpeController = DslhCreateCpeController(NULL, NULL, NULL);

    if ( !pDslhCpeController )
    {
        CcspTraceError(("CANNOT Create pDslhCpeController... Exit!\n"));

        return ANSC_STATUS_RESOURCES;
    }

    return ANSC_STATUS_SUCCESS;
}


ANSC_STATUS
ssp_engage_advsec
    (
    )
{
	ANSC_STATUS					    returnStatus                                         = ANSC_STATUS_SUCCESS;
        char                                                CrName[256];
        errno_t                                             rc                                                   = -1;

    g_pComponent_Common_Dm->Health = CCSP_COMMON_COMPONENT_HEALTH_Yellow;

    if ( pAdvSecCcdIf )
    {
        pAdvSecFcContext->hCcspCcdIf = (ANSC_HANDLE)pAdvSecCcdIf;
        pAdvSecFcContext->hMessageBus = bus_handle;
    }

    g_DslhDataModelAgent->SetFcContext((ANSC_HANDLE)g_DslhDataModelAgent, (ANSC_HANDLE)pAdvSecFcContext);

    pDslhCpeController->AddInterface((ANSC_HANDLE)pDslhCpeController, (ANSC_HANDLE)MsgHelper_CreateCcdMbiIf((void*)bus_handle, g_Subsystem));
    pDslhCpeController->AddInterface((ANSC_HANDLE)pDslhCpeController, (ANSC_HANDLE)pAdvSecCcdIf);
    pDslhCpeController->SetDbusHandle((ANSC_HANDLE)pDslhCpeController, bus_handle);
    pDslhCpeController->Engage((ANSC_HANDLE)pDslhCpeController);

    rc = sprintf_s(CrName, sizeof(CrName), "%s%s", g_Subsystem, CCSP_DBUS_INTERFACE_CR);
    if(rc < EOK)
    {
        ERR_CHK(rc);
        return ANSC_STATUS_FAILURE;
    }

    if ( g_GetParamValueByPathNameProc == NULL )
    {
        g_GetParamValueByPathNameProc = 
            (COSAGetParamValueByPathNameProc)COSAAcquireFunction("COSAGetParamValueByPathName");

        if ( !g_GetParamValueByPathNameProc )
        {
            CcspTraceError(("ADVSEC - failed to load the function COSAGetParamValueByPathName!\n"));
        }
    }

    returnStatus =
        pDslhCpeController->RegisterCcspDataModel2
            (
                (ANSC_HANDLE)pDslhCpeController,
                CrName, /*CCSP_DBUS_INTERFACE_CR,*/             /* CCSP CR ID */
                DMPackCreateDataModelXML,           /* Generated code to create XML. */
                CCSP_COMPONENT_NAME_ADVSEC,            /* Component Name    */
                CCSP_COMPONENT_VERSION_ADVSEC,         /* Component Version */
                CCSP_COMPONENT_PATH_ADVSEC,            /* Component Path    */
                g_Subsystem                         /* Component Prefix  */
            );

    if ( returnStatus == ANSC_STATUS_SUCCESS || CCSP_SUCCESS == returnStatus)
    {
        /* System is fully initialized */
        g_pComponent_Common_Dm->Health = CCSP_COMMON_COMPONENT_HEALTH_Green;
    }

    return ANSC_STATUS_SUCCESS;
}


ANSC_STATUS
ssp_cancel_advsec
    (
    )
{
    pDslhCpeController->Cancel((ANSC_HANDLE)pDslhCpeController);
    AnscFreeMemory(pDslhCpeController);

    return ANSC_STATUS_SUCCESS;
}


char*
ssp_AdvSecCCDmGetComponentName
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_pComponent_Common_Dm->Name;
}


ULONG
ssp_AdvSecCCDmGetComponentVersion
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_pComponent_Common_Dm->Version;
}


char*
ssp_AdvSecCCDmGetComponentAuthor
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_pComponent_Common_Dm->Author;
}


ULONG
ssp_AdvSecCCDmGetComponentHealth
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_pComponent_Common_Dm->Health;
}


ULONG
ssp_AdvSecCCDmGetComponentState
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_pComponent_Common_Dm->State;
}



BOOL
ssp_AdvSecCCDmGetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_pComponent_Common_Dm->LogEnable;
}


ANSC_STATUS
ssp_AdvSecCCDmSetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject,
        BOOL                            bEnabled
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    /*CommonDm.LogEnable = bEnabled;*/
    if(g_pComponent_Common_Dm->LogEnable == bEnabled) return ANSC_STATUS_SUCCESS;
    g_pComponent_Common_Dm->LogEnable = bEnabled;

    if (!bEnabled)
        AnscSetTraceLevel(CCSP_TRACE_INVALID_LEVEL);
    else
        AnscSetTraceLevel(g_pComponent_Common_Dm->LogLevel);

    return ANSC_STATUS_SUCCESS;
}


ULONG
ssp_AdvSecCCDmGetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_pComponent_Common_Dm->LogLevel;
}


ANSC_STATUS
ssp_AdvSecCCDmSetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject,
        ULONG                           LogLevel
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    /*CommonDm.LogLevel = LogLevel;*/
    if(g_pComponent_Common_Dm->LogLevel == LogLevel) return ANSC_STATUS_SUCCESS;
    g_pComponent_Common_Dm->LogLevel = LogLevel;

    if (g_pComponent_Common_Dm->LogEnable)
        AnscSetTraceLevel(LogLevel);        

    return ANSC_STATUS_SUCCESS;
}


ULONG
ssp_AdvSecCCDmGetMemMaxUsage
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_ulAllocatedSizePeak;
}


ULONG
ssp_AdvSecCCDmGetMemMinUsage
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    return g_pComponent_Common_Dm->MemMinUsage;
}


ULONG
ssp_AdvSecCCDmGetMemConsumed
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    LONG             size = 0;

    size = AnscGetComponentMemorySize(CCSP_COMPONENT_NAME_ADVSEC);
    if (size == -1 )
        size = 0;

    return size;
}


ANSC_STATUS
ssp_AdvSecCCDmApplyChanges
    (
        ANSC_HANDLE                     hThisObject
    )
{
    UNREFERENCED_PARAMETER(hThisObject);
    ANSC_STATUS                         returnStatus    = ANSC_STATUS_SUCCESS;
    /* Assume the parameter settings are committed immediately. */
    /*g_pComponent_Common_Dm->LogEnable = CommonDm.LogEnable;
    g_pComponent_Common_Dm->LogLevel  = CommonDm.LogLevel;

    AnscSetTraceLevel((INT)g_pComponent_Common_Dm->LogLevel);*/

    return returnStatus;
}
#endif /* End of commented DML SSP functions */

