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

#ifndef _ADVSEC_COMPAT_TYPES_H_
#define _ADVSEC_COMPAT_TYPES_H_

/*
 * Compatibility type definitions to replace common-library (ANSC) types
 * This allows compilation without common-library dependency
 * Eventually these will be replaced with direct RBUS types in JSON-based approach
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#define _GNU_SOURCE /* for strcasestr */
#include <stdarg.h>
#include <string.h>
#include <errno.h>

/* Additional type definitions for compatibility */
#ifndef errno_t
typedef int                         errno_t;
#endif

/* Basic type replacements */
#ifndef ULONG
typedef unsigned long               ULONG;
#endif

#ifndef PULONG
typedef ULONG*                      PULONG;
#endif

#ifndef LONG
typedef long                        LONG;
#endif

#ifndef PLONG
typedef LONG*                       PLONG;
#endif

#ifndef BOOL
typedef bool                        BOOL;
#endif

#ifndef PBOOL
typedef BOOL*                       PBOOL;
#endif

#ifndef VOID
typedef void                        VOID;
#endif

#ifndef PVOID
typedef void*                       PVOID;
#endif

#ifndef CHAR
typedef char                        CHAR;
#endif

#ifndef PCHAR
typedef char*                       PCHAR;
#endif

#ifndef UCHAR
typedef unsigned char               UCHAR;
#endif

#ifndef PUCHAR
typedef unsigned char*              PUCHAR;
#endif

#ifndef INT
typedef int                         INT;
#endif

#ifndef PINT
typedef int*                        PINT;
#endif

#ifndef UINT
typedef unsigned int                UINT;
#endif

#ifndef PUINT
typedef unsigned int*               PUINT;
#endif

#ifndef TRUE
#define TRUE                        true
#endif

#ifndef FALSE
#define FALSE                       false
#endif

#ifndef ANSC_HANDLE
typedef void*                       ANSC_HANDLE;
#endif

#ifndef ANSC_STATUS
typedef int                         ANSC_STATUS;
#endif

/* Status code replacements */
#ifndef ANSC_STATUS_SUCCESS
#define ANSC_STATUS_SUCCESS         0
#endif

#ifndef ANSC_STATUS_FAILURE
#define ANSC_STATUS_FAILURE         -1
#endif

#ifndef ANSC_STATUS_RESOURCES
#define ANSC_STATUS_RESOURCES       -2
#endif

/* Export API definition */
#if (defined _ANSC_WINDOWSNT) || (defined _ANSC_WINDOWS9X)
#ifdef _ALMIB_EXPORTS
#define ANSC_EXPORT_API             __declspec(dllexport)
#else
#define ANSC_EXPORT_API             __declspec(dllimport)
#endif
#else
#define ANSC_EXPORT_API
#endif

/* Memory management implementations provided as static inline functions below */
/* Macro definitions removed to avoid conflicts with functional implementations */

/* Component Common DM Initialization Macro */
#ifndef ComponentCommonDmInit
#define ComponentCommonDmInit(dm) do { \
    memset(dm, 0, sizeof(COMPONENT_COMMON_DM)); \
    (dm)->Health = CCSP_COMMON_COMPONENT_HEALTH_Red; \
    (dm)->State = CCSP_COMMON_COMPONENT_STATE_Initializing; \
    (dm)->LogLevel = CCSP_TRACE_LEVEL_INFO; \
    (dm)->LogEnable = 1; \
} while(0)
#endif

/* Unreferenced parameter macro */
#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P)   (void)(P)
#endif

/* Platform detection macros (if needed) */
#ifndef _ANSC_LINUX
#ifdef __linux__
#define _ANSC_LINUX
#endif
#endif

#ifndef _ANSC_LITTLE_ENDIAN_
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define _ANSC_LITTLE_ENDIAN_
#endif
#endif

/* CCSP SLAP Variable Types */
typedef struct _SLAP_VARIABLE {
    int varType;
    union {
        char* varString;
        int varInt;
        unsigned int varUint;
        bool varBool;
        void* varHandle;
    } Variant;
} SLAP_VARIABLE;

/* CCSP Function Pointer Types */
typedef int (*COSAGetParamValueByPathNameProc)(const char*, char**);

/* Error checking macro */
#ifndef ERR_CHK
#define ERR_CHK(x) do { if ((x) != 0) { } } while(0)
#endif

/* Logging macros to replace ccsp_trace.h functions */
#include <stdio.h>
#include <syslog.h>

/* CcspTrace uses double parentheses: CcspTraceError(("msg %s", value))
 * We use variadic macros to handle this. The inner parentheses become __VA_ARGS__:
 * CcspTraceError(("msg")) -> fprintf(stderr, "[ERROR] "); fprintf(stderr, "msg"); 
 * CcspTraceError(("msg %s", "arg")) -> fprintf(stderr, "[ERROR] "); fprintf(stderr, "msg %s", "arg");
 */

/* Enhanced logging with file output and timestamp support - based on common-library */
static FILE* g_advsec_logfile = NULL;
static int g_advsec_trace_level = 6; /* Default to INFO level */

/* CCSP Trace Levels - matching common-library definitions */
#ifndef CCSP_TRACE_LEVEL_EMERGENCY
#define CCSP_TRACE_LEVEL_EMERGENCY     0
#endif
#ifndef CCSP_TRACE_LEVEL_ALERT
#define CCSP_TRACE_LEVEL_ALERT         1  
#endif
#ifndef CCSP_TRACE_LEVEL_CRITICAL
#define CCSP_TRACE_LEVEL_CRITICAL      2
#endif
#ifndef CCSP_TRACE_LEVEL_ERROR
#define CCSP_TRACE_LEVEL_ERROR         3
#endif
#ifndef CCSP_TRACE_LEVEL_WARNING
#define CCSP_TRACE_LEVEL_WARNING       4
#endif
#ifndef CCSP_TRACE_LEVEL_NOTICE
#define CCSP_TRACE_LEVEL_NOTICE        5
#endif
#ifndef CCSP_TRACE_LEVEL_INFO
#define CCSP_TRACE_LEVEL_INFO          6
#endif
#ifndef CCSP_TRACE_LEVEL_DEBUG
#define CCSP_TRACE_LEVEL_DEBUG         7
#endif

/* Trace level names */
static const char* g_advsec_TraceLevelStr[] = {
    "EMERGENCY", "ALERT", "CRITICAL", "ERROR", 
    "WARNING", "NOTICE", "INFO", "DEBUG"
};

/* Initialize logging system - based on common-library patterns */
static inline void advsec_trace_init(const char* component_name) {
    const char* log_file = getenv("ADVSEC_LOG_FILE");
    const char* trace_level = getenv("ADVSEC_TRACE_LEVEL");
    
    if (log_file) {
        g_advsec_logfile = fopen(log_file, "a");
    }
    
    if (trace_level) {
        g_advsec_trace_level = atoi(trace_level);
        if (g_advsec_trace_level < 0) g_advsec_trace_level = 0;
        if (g_advsec_trace_level > 7) g_advsec_trace_level = 7;
    }
    
    printf("Advanced Security %s initialized with trace level %d (%s)\n", 
           component_name ? component_name : "Component", 
           g_advsec_trace_level,
           g_advsec_TraceLevelStr[g_advsec_trace_level]);
}

/* Enhanced logging function with timestamps - based on common-library CcspTraceExec */
static inline void advsec_log_write_with_level(int level, const char* format, ...) {
    if (level > g_advsec_trace_level || level < 0 || level > 7) return;
    
    va_list args1, args2;
    time_t rawtime;
    struct tm* timeinfo;
    char timestamp[64];
    
    /* Get current timestamp */
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    /* Prepare arguments for both stdout and file */
    va_start(args1, format);
    va_copy(args2, args1);
    
    /* Write to stdout with timestamp and level */
    fprintf(stdout, "[%s] [%s] ", timestamp, g_advsec_TraceLevelStr[level]);
    vfprintf(stdout, format, args1);
    if (format[strlen(format)-1] != '\n') {
        fprintf(stdout, "\n");
    }
    fflush(stdout);
    
    /* Write to log file if open */
    if (g_advsec_logfile) {
        fprintf(g_advsec_logfile, "[%s] [%s] ", timestamp, g_advsec_TraceLevelStr[level]);
        vfprintf(g_advsec_logfile, format, args2);
        if (format[strlen(format)-1] != '\n') {
            fprintf(g_advsec_logfile, "\n");
        }
        fflush(g_advsec_logfile);
    }
    
    va_end(args1);
    va_end(args2);
}

/* Simple log write for backward compatibility */
static inline void advsec_log_write(const char* level, const char* format, ...) {
    va_list args1, args2;
    va_start(args1, format);
    va_copy(args2, args1);
    
    /* Write to console */
    fprintf(stdout, "[%s] ", level);
    vfprintf(stdout, format, args1);
    fflush(stdout);
    
    /* Write to log file if open */
    if (g_advsec_logfile) {
        fprintf(g_advsec_logfile, "[%s] ", level);
        vfprintf(g_advsec_logfile, format, args2);
        fflush(g_advsec_logfile);
    }
    
    va_end(args1);
    va_end(args2);
}

#ifndef CcspTraceError
#define CcspTraceError(...) advsec_log_write_with_level(CCSP_TRACE_LEVEL_ERROR, __VA_ARGS__)
#endif

#ifndef CcspTraceWarning  
#define CcspTraceWarning(...) advsec_log_write_with_level(CCSP_TRACE_LEVEL_WARNING, __VA_ARGS__)
#endif

#ifndef CcspTraceInfo
#define CcspTraceInfo(...) advsec_log_write_with_level(CCSP_TRACE_LEVEL_INFO, __VA_ARGS__)
#endif

#ifndef CcspTraceDebug
#define CcspTraceDebug(...) advsec_log_write_with_level(CCSP_TRACE_LEVEL_DEBUG, __VA_ARGS__)
#endif

#ifndef CcspTraceNotice
#define CcspTraceNotice(...) advsec_log_write_with_level(CCSP_TRACE_LEVEL_NOTICE, __VA_ARGS__)
#endif

#ifndef CcspTraceCritical
#define CcspTraceCritical(...) advsec_log_write_with_level(CCSP_TRACE_LEVEL_CRITICAL, __VA_ARGS__)
#endif

#ifndef CcspTraceAlert
#define CcspTraceAlert(...) advsec_log_write_with_level(CCSP_TRACE_LEVEL_ALERT, __VA_ARGS__)
#endif

#ifndef CcspTraceEmergency
#define CcspTraceEmergency(...) advsec_log_write_with_level(CCSP_TRACE_LEVEL_EMERGENCY, __VA_ARGS__)
#endif

/* Additional ANSC trace/debug functions - no-op implementations */
#ifndef AnscTraceWarning
#define AnscTraceWarning(msg) CcspTraceWarning(msg)
#endif

#ifndef AnscSetTraceLevel
#define AnscSetTraceLevel(level) do { \
    g_advsec_trace_level = (level); \
    if (g_advsec_trace_level < 0) g_advsec_trace_level = 0; \
    if (g_advsec_trace_level > 7) g_advsec_trace_level = 7; \
} while(0)
#endif

#ifndef AnscGetTraceLevel
#define AnscGetTraceLevel() (g_advsec_trace_level)
#endif

/* DSLH MPA Access Control Constants */
#ifndef DSLH_MPA_ACCESS_CONTROL_ACS
#define DSLH_MPA_ACCESS_CONTROL_ACS                 0x00000001
#endif

/* CCSP Trace Level Constants */
#ifndef CCSP_TRACE_LEVEL_EMERGENCY
#define CCSP_TRACE_LEVEL_EMERGENCY                  0
#define CCSP_TRACE_LEVEL_ALERT                      1
#define CCSP_TRACE_LEVEL_CRITICAL                   2
#define CCSP_TRACE_LEVEL_ERROR                      3
#define CCSP_TRACE_LEVEL_WARNING                    4
#define CCSP_TRACE_LEVEL_NOTICE                     5
#define CCSP_TRACE_LEVEL_INFO                       6
#define CCSP_TRACE_LEVEL_DEBUG                      7
#define CCSP_TRACE_INVALID_LEVEL                    8
#endif

/* CCSP Message Bus Return Codes */
#ifndef CCSP_Message_Bus_OK
#define CCSP_Message_Bus_OK                         0
#define CCSP_Message_Bus_ERROR                      1
#define CCSP_Message_Bus_TIMEOUT                    2
#endif

/* CCSP Interface Stub Types - For legacy compatibility */
#ifndef CCSP_CCD_INTERFACE
typedef struct _CCSP_CCD_INTERFACE {
    char Name[256];
    int InterfaceId;
    int Size;
} CCSP_CCD_INTERFACE, *PCCSP_CCD_INTERFACE;
#endif

#ifndef CCSP_FC_CONTEXT
typedef struct _CCSP_FC_CONTEXT {
    int dummy;  // Stub for legacy compatibility
} CCSP_FC_CONTEXT, *PCCSP_FC_CONTEXT;
#endif

#ifndef CCSP_CCD_INTERFACE_NAME
#define CCSP_CCD_INTERFACE_NAME                     "CCSP.CCD"
#endif

#ifndef CCSP_CCD_INTERFACE_ID
#define CCSP_CCD_INTERFACE_ID                       1
#endif

/* Component Common Data Model Structure */
#ifndef COMPONENT_COMMON_DM
typedef struct _COMPONENT_COMMON_DM {
    char* Name;
    int Version;
    char* Author;
    int Health;
    int State;
    int LogLevel;
    int LogEnable;
    int MemMaxUsage;
    int MemMinUsage;
    int MemConsumed;
} COMPONENT_COMMON_DM, *PCOMPONENT_COMMON_DM;
#endif

#ifndef AnscPrintComponentMemoryTable
#define AnscPrintComponentMemoryTable(name) do { /* No-op - debug function */ } while(0)
#endif

#ifndef AnscTraceMemoryTable
#define AnscTraceMemoryTable() do { /* No-op - debug function */ } while(0)
#endif

#ifndef AnscGetComponentMemorySize
#define AnscGetComponentMemorySize(name) (0)
#endif

/* AnscStartupSocketWrapper implementation provided as static inline function */

/* String utility functions provided as static inline functions */

/* CCSP Message Bus utility functions */
static inline void CCSP_Msg_SleepInMilliSeconds(int milliseconds) {
    usleep(milliseconds * 1000);
}

/* ANSC Memory Management - Full Functional Implementation */
static inline void* AnscAllocateMemory(size_t ulMemorySize) {
    void* p = malloc(ulMemorySize);
    if (p) {
        memset(p, 0, ulMemorySize);  /* Zero-initialize like AnscAllocateMemoryOrig */
    }
    return p;
}

static inline void AnscFreeMemory(void* pMemoryBlock) {
    if (pMemoryBlock) {
        free(pMemoryBlock);
    }
}

static inline void* AnscReAllocMemory(void* pMemoryBlock, size_t ulMemorySize) {
    return realloc(pMemoryBlock, ulMemorySize);
}

static inline void AnscCopyMemory(void* pDestination, const void* pSource, size_t ulMemorySize) {
    if (pDestination && pSource && ulMemorySize > 0) {
        memcpy(pDestination, pSource, ulMemorySize);
    }
}

static inline void AnscZeroMemory(void* pMemory, size_t ulMemorySize) {
    if (pMemory && ulMemorySize > 0) {
        memset(pMemory, 0, ulMemorySize);
    }
}

static inline int AnscEqualMemory(const void* pMemory1, const void* pMemory2, size_t ulMemorySize) {
    if (!pMemory1 || !pMemory2) return 0;
    return (memcmp(pMemory1, pMemory2, ulMemorySize) == 0);
}

/* ANSC String Utilities - Based on common-library implementations */
static inline char* AnscCloneString(const char* pString) {
    char* pNewString = NULL;
    size_t ulStringSize;
    
    if (!pString) return NULL;
    
    ulStringSize = strlen(pString) + 1;
    pNewString = (char*)AnscAllocateMemory(ulStringSize);
    
    if (pNewString) {
        strcpy(pNewString, pString);
    }
    
    return pNewString;
}

static inline int AnscEqualString(const char* pString1, const char* pString2, int bCaseSensitive) {
    if (!pString1 || !pString2) return 0;
    
    if (bCaseSensitive) {
        return (strcmp(pString1, pString2) == 0);
    } else {
        return (strcasecmp(pString1, pString2) == 0);
    }
}

static inline char* AnscSearchSubString(const char* pString, const char* pSubString, int bCaseSensitive) {
    if (!pString || !pSubString) return NULL;
    
    if (bCaseSensitive) {
        return strstr(pString, pSubString);
    } else {
        return strcasestr(pString, pSubString);
    }
}

static inline size_t AnscGetStringUCharCount(const char* pString, char uChar) {
    size_t count = 0;
    
    if (!pString) return 0;
    
    while (*pString) {
        if (*pString == uChar) count++;
        pString++;
    }
    
    return count;
}

/* String conversion utilities */
static inline unsigned long AnscGetStringUlong(const char* pString) {
    return pString ? strtoul(pString, NULL, 10) : 0;
}

static inline long AnscGetStringLong(const char* pString) {
    return pString ? strtol(pString, NULL, 10) : 0;
}

static inline unsigned int AnscGetStringUint(const char* pString) {
    return (unsigned int)AnscGetStringUlong(pString);
}

static inline int AnscGetStringInt(const char* pString) {
    return (int)AnscGetStringLong(pString);
}

/* String utility functions */
static inline size_t AnscSizeOfString(const char* str) {
    return str ? strlen(str) : 0;
}

/* IP address utilities */
static inline int AnscIsValidIpString(const char* pIpString) {
    struct in_addr addr;
    if (!pIpString) return 0;
    return inet_aton(pIpString, &addr);
}

static inline unsigned int AnscReadUlong(const char* pString) {
    return pString ? (unsigned int)strtoul(pString, NULL, 0) : 0;  /* Auto-detect base */
}

/* Time utilities */
static inline void AnscSleep(unsigned int ulMilliSeconds) {
    usleep(ulMilliSeconds * 1000);
}

/* Task/Threading utilities - simplified for RBUS */
static inline int AnscSpawnTask(void* (*start_routine)(void*), void* arg, const char* name) {
    pthread_t thread;
    pthread_attr_t attr;
    int result;
    
    (void)name; /* Unused parameter */
    
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    
    result = pthread_create(&thread, &attr, start_routine, arg);
    
    pthread_attr_destroy(&attr);
    return (result == 0) ? 1 : 0;  /* Return 1 for success, 0 for failure */
}

/* Socket utilities */
static inline int AnscStartupSocketWrapper(void* param) {
    (void)param;  /* No-op on Linux */
    return 0;
}

#endif /* _ADVSEC_COMPAT_TYPES_H_ */
