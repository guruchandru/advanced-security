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

#ifndef  _COSA_ADV_SEC_INTERNAL_H
#define  _COSA_ADV_SEC_INTERNAL_H

/* Legacy common-library includes commented out for JSON-driven RBUS approach */
/* #include "ansc_platform.h" */
/* #include "ansc_string_util.h" */
/* Compatibility types to replace common-library */
#include "advsec_compat_types.h"

#define ADVSEC_MIN_LOG_TIMEOUT (60 * 1)
#define ADVSEC_MAX_LOG_TIMEOUT (60 * 48)
#define ADVSEC_DEFAULT_LOG_TIMEOUT (60 * 24)
#define ADVSEC_DEFAULT_LOOKUP_TIMEOUT 350
#define ADVSEC_MAX_LOOKUP_TIMEOUT 6000
#define ADVSEC_LogLevel_ERROR 1
#define ADVSEC_LogLevel_WARN 2
#define ADVSEC_LogLevel_INFO 3
#define ADVSEC_LogLevel_VERBOSE 4
#define BUFLEN_1024 1024
#define PARTNER_REDIRECTORURL_PARAMNAME  "Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.AdvsecRedirectorURL"

typedef enum {
    ADVSEC_SAFEBROWSING=0,
    ADVSEC_SOFTFLOWD,
    ADVSEC_ALL=255
}advsec_feature_type;

typedef  struct
_COSA_DATAMODEL_ADVPARENTALCONTROL {
    BOOL                                                bEnable;
}
COSA_DATAMODEL_ADVPARENTALCONTROL, *PCOSA_DATAMODEL_ADVPARENTALCONTROL;

typedef  struct
_COSA_DATAMODEL_ADVPC_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_ADVPC_RFC,  *PCOSA_DATAMODEL_ADVPC_RFC;

typedef  struct
_COSA_DATAMODEL_PRIVACYPROTECTION {
    BOOL                                                bEnable;
}
COSA_DATAMODEL_PRIVACYPROTECTION, *PCOSA_DATAMODEL_PRIVACYPROTECTION;

typedef  struct
_COSA_DATAMODEL_PRIVACYPROTECTION_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_PRIVACYPROTECTION_RFC,  *PCOSA_DATAMODEL_PRIVACYPROTECTION_RFC;

typedef  struct
_COSA_DATAMODEL_DEVICEFINGERPRINTICMPv6_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_DEVICEFINGERPRINTICMPv6_RFC,  *PCOSA_DATAMODEL_DEVICEFINGERPRINTICMPv6_RFC;

typedef  struct
_COSA_DATAMODEL_WSDISCOVERYANALYSIS_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_WSDISCOVERYANALYSIS_RFC,  *PCOSA_DATAMODEL_WSDISCOVERYANALYSIS_RFC;

typedef  struct
_COSA_DATAMODEL_ADVSECOTM_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_ADVSECOTM_RFC,  *PCOSA_DATAMODEL_ADVSECOTM_RFC;

typedef  struct
_COSA_DATAMODEL_ADVSECUSERSPACE_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_ADVSECUSERSPACE_RFC,  *PCOSA_DATAMODEL_ADVSECUSERSPACE_RFC;

typedef  struct
_COSA_DATAMODEL_ADVSECWIFIDATACOLLECTION_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_ADVSECWIFIDATACOLLECTION_RFC,  *PCOSA_DATAMODEL_ADVSECWIFIDATACOLLECTION_RFC;

typedef struct
_COSA_DATAMODEL_LEVL_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_LEVL_RFC,  *PCOSA_DATAMODEL_LEVL_RFC;

typedef struct
_COSA_DATAMODEL_ADVSECAGENT_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_ADVSECAGENT_RFC,  *PCOSA_DATAMODEL_ADVSECAGENT_RFC;

typedef struct
_COSA_DATAMODEL_ADVSECSAFEBROWSING_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_ADVSECSAFEBROWSING_RFC,  *PCOSA_DATAMODEL_ADVSECSAFEBROWSING_RFC;

typedef struct
_COSA_DATAMODEL_ADVSECCUJOTELEMETRYWIFIFP_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_ADVSECCUJOTELEMETRYWIFIFP_RFC,  *PCOSA_DATAMODEL_ADVSECCUJOTELEMETRYWIFIFP_RFC;

typedef  struct
_COSA_DATAMODEL_ADVSECCUJOTRACER_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_ADVSECCUJOTRACER_RFC,  *PCOSA_DATAMODEL_ADVSECCUJOTRACER_RFC;

typedef  struct
_COSA_DATAMODEL_ADVSECCUJOTELEMETRYDATA_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_ADVSECCUJOTELEMETRY_RFC,  *PCOSA_DATAMODEL_ADVSECCUJOTELEMETRY_RFC;

typedef  struct
_COSA_DATAMODEL_ADVSECSATE_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_ADVSECSATE_RFC,  *PCOSA_DATAMODEL_ADVSECSATE_RFC;

typedef  struct
_COSA_DATAMODEL_ADVSECTCPTRACKERFILTERDEVICES_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_ADVSECTCPTRACKERFILTERDEVICES_RFC,  *PCOSA_DATAMODEL_ADVSECTCPTRACKERFILTERDEVICES_RFC;

typedef  struct
_COSA_DATAMODEL_RAPTR_RFC {
    BOOL            bEnable;
}
COSA_DATAMODEL_RAPTR_RFC,  *PCOSA_DATAMODEL_RAPTR_RFC;

typedef  struct
_COSA_DATAMODEL_AGENT_SOFTFLOWD {
    BOOL						bEnable;
}
COSA_DATAMODEL_SOFTFLOWD, *PCOSA_DATAMODEL_SOFTFLOWD;

typedef  struct
_COSA_DATAMODEL_AGENT_SB {
    BOOL						bEnable;
    ULONG                                               ulLookupTimeout;
}
COSA_DATAMODEL_SB, *PCOSA_DATAMODEL_SB;

typedef  struct
_COSA_DATAMODEL_RABID
{
    ULONG                       uMemoryLimit;
    ULONG                       uMacCacheSize;
    ULONG                       uDNSCacheSize;
}
COSA_DATAMODEL_RABID,  *PCOSA_DATAMODEL_RABID;

typedef  struct
_COSA_DATAMODEL_AGENT_ADVSEC {
    BOOL						bEnable;
    PCOSA_DATAMODEL_SB          pSafeBrows;
    PCOSA_DATAMODEL_SOFTFLOWD    pSoftFlowd;
}
COSA_DATAMODEL_ADVSEC, *PCOSA_DATAMODEL_ADVSEC;

typedef  struct
_COSA_DATAMODEL_AGENT
{
    BOOL                        bEnable;
    PCOSA_DATAMODEL_ADVSEC      pAdvSec;
    ULONG                       ulLoggingPeriod;
    ULONG                       ulLogLevel;
    PCOSA_DATAMODEL_ADVPARENTALCONTROL pAdvPC;
    PCOSA_DATAMODEL_ADVPC_RFC pAdvPC_RFC;
    PCOSA_DATAMODEL_PRIVACYPROTECTION pPrivProt;
    PCOSA_DATAMODEL_PRIVACYPROTECTION_RFC pPrivProt_RFC;
    PCOSA_DATAMODEL_DEVICEFINGERPRINTICMPv6_RFC pDFIcmpv6_RFC;
    PCOSA_DATAMODEL_WSDISCOVERYANALYSIS_RFC pWSDiscoveryAnalysis_RFC;
    PCOSA_DATAMODEL_ADVSECOTM_RFC pAdvSecOTM_RFC;
    PCOSA_DATAMODEL_ADVSECUSERSPACE_RFC pAdvSecUserSpace_RFC;
    PCOSA_DATAMODEL_ADVSECWIFIDATACOLLECTION_RFC pAdvWifiDataCollection_RFC;
    PCOSA_DATAMODEL_LEVL_RFC pLevl_RFC;
    PCOSA_DATAMODEL_ADVSECAGENT_RFC pAdvSecAgent_RFC;
    PCOSA_DATAMODEL_ADVSECSAFEBROWSING_RFC pAdvSecSafeBrowsing_RFC;
    PCOSA_DATAMODEL_ADVSECCUJOTELEMETRYWIFIFP_RFC pAdvSecCujoTelemetryWiFiFP_RFC;
    PCOSA_DATAMODEL_ADVSECCUJOTRACER_RFC pAdvSecCujoTracer_RFC;
    PCOSA_DATAMODEL_ADVSECCUJOTELEMETRY_RFC pAdvSecCujoTelemetry_RFC;
    PCOSA_DATAMODEL_ADVSECSATE_RFC pAdvSecSATE_RFC;
    PCOSA_DATAMODEL_ADVSECTCPTRACKERFILTERDEVICES_RFC pAdvSecTCPTrackerFilterDevices_RFC;
    PCOSA_DATAMODEL_RAPTR_RFC pRaptr_RFC;
    PCOSA_DATAMODEL_RABID       pRabid;
    int         	iStatus;
    int             iState;
}
COSA_DATAMODEL_AGENT,  *PCOSA_DATAMODEL_AGENT;

/*
    Standard function declaration 
*/
ANSC_STATUS Wifi_GetParameterValue(const char *pParamName, char *pReturnVal);
BOOL WifiMgmtFrame_GetActive_Status(void);
BOOL WifiLevl_GetActive_Status(void);
int wifidcl_init_precheck(void);

ANSC_HANDLE
CosaSecurityCreate
    (
        VOID
    );

ANSC_STATUS
CosaSecurityInitialize
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
CosaSecurityRemove
    (
        ANSC_HANDLE                 hThisObject
    );

ANSC_STATUS
CosaAdvSecGetLoggingPeriod
    (
    );

ANSC_STATUS
CosaAdvSecSetLoggingPeriod
    (
        ULONG bValue
    );
ANSC_STATUS
CosaAdvSecGetLogLevel
    (
    );

ANSC_STATUS
CosaAdvSecSetLogLevel
    (
        ULONG bValue
    );
ANSC_STATUS
CosaAdvSecGetLookupTimeout
    (
    );

ANSC_STATUS
CosaAdvSecSetLookupTimeout
    (
        ULONG bValue
    );
ULONG
CosaAdvSecGetLookupTimeoutExceededCount
    (
    );

ANSC_STATUS
CosaStartAdvParentalControl
    (
        BOOL update_status
    );

ANSC_STATUS
CosaStopAdvParentalControl
    (
        BOOL update_status
    );

ANSC_STATUS
CosaStartPrivacyProtection
    (
        BOOL update_status
    );

ANSC_STATUS
CosaStopPrivacyProtection
    (
        BOOL update_status
    );

ANSC_STATUS
CosaGetSysCfgUlong
    (
        char* setting,
        ULONG *value
    );

ANSC_STATUS
CosaSetSysCfgUlong
    (
        char* setting,
        ULONG value
    );

ANSC_STATUS
CosaAdvSecGetCustomURL
    (
        char* pValue,
        PULONG pulSize
    );

ANSC_STATUS
CosaAdvSecSetCustomURL
    (
        char* pString
    );

ANSC_STATUS
    CosaAdvSecInit
    (
    );

ANSC_STATUS
CosaAdvSecStartFeatures
    (
        advsec_feature_type type
    );

ANSC_STATUS
CosaAdvSecStopFeatures
    (
        advsec_feature_type type
    );

ANSC_STATUS
CosaAdvSecDeInit
    (
    );

ANSC_STATUS
CosaRabidSetMemoryLimit
    (
        ANSC_HANDLE hThisObject,
        ULONG uValue
    );

ANSC_STATUS
CosaRabidSetMacCacheSize
    (
        ANSC_HANDLE hThisObject,
        ULONG uValue
    );

ANSC_STATUS
CosaRabidSetDNSCacheSize
    (
        ANSC_HANDLE hThisObject,
        ULONG uValue
    );

ANSC_STATUS
CosaAdvPCInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvPCDeInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaPrivacyProtectionInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaPrivacyProtectionDeInit
    (
        ANSC_HANDLE hThisObject
    );
ANSC_STATUS
CosaAdvDFIcmpv6Init
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvDFIcmpv6DeInit
    (
        ANSC_HANDLE hThisObject
    );
ANSC_STATUS
CosaWSDisInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaWSDisDeInit
    (
        ANSC_HANDLE hThisObject
    );
ANSC_STATUS
CosaAdvSecOTMInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecOTMDeInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecAgentRaptrInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecAgentRaptrDeInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecUserSpaceInit
    (
        ANSC_HANDLE hThisObject
    );

/*
ANSC_STATUS
CosaAdvSecUserSpaceDeInit
    (
        ANSC_HANDLE hThisObject
    );
*/

ANSC_STATUS
CosaLevlInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaLevlDeInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecAgentInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecAgentDeInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecSafeBrowsingInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecSafeBrowsingDeInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecCujoTelemetryWiFiFPInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecCujoTelemetryWiFiFPDeInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecCujoTracerInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecCujoTracerDeInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecCujoTelemetryInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecCujoTelemetryDeInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecSATEInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecSATEDeInit
    (
        ANSC_HANDLE hThisObject
    );


ANSC_STATUS
CosaAdvSecTCPTrackerFilterDevicesInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecTCPTrackerFilterDevicesDeInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvWifiDataCollectionInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvWifiDataCollectionDeInit
    (
        ANSC_HANDLE hThisObject
    );

ANSC_STATUS
CosaAdvSecFetchSbConfig
    (
        char* paramName,
        char* pValue,
        ULONG* pUlSize,
        ULONG* puLong
    );
#endif
