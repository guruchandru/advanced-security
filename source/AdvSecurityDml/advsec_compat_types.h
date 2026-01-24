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

/* Define _GNU_SOURCE for strcasestr and other GNU extensions */
#define _GNU_SOURCE

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
#include <signal.h>  /* For signal constants */

/* Signal constants - ensure they are defined */
#ifndef SIGINT
#define SIGINT   2
#endif
#ifndef SIGUSR1  
#define SIGUSR1  10
#endif
#ifndef SIGUSR2
#define SIGUSR2  12
#endif
#ifndef SIGCHLD
#define SIGCHLD  17
#endif
#ifndef SIGPIPE
#define SIGPIPE  13
#endif

/* Additional type definitions for compatibility */
#ifndef errno_t
typedef int                         errno_t;
#endif

/* Safe C library constants and functions */
#ifndef EOK
#define EOK                         0
#endif

/* Additional SafecLib error constants */
#ifndef ESNULLP
#define ESNULLP                     400    /* null ptr */
#endif

#ifndef ESLEMAX  
#define ESLEMAX                     403    /* length exceeds RSIZE_MAX */
#endif

#ifndef ESNOSPC
#define ESNOSPC                     406    /* not enough space for dest */
#endif

#ifndef RSIZE_MAX
#define RSIZE_MAX                   0x7FFFFFFF    /* Maximum safe string/memory size */
#endif

/* SafecLib Error Logging - based on RDK_SAFECLIB_ERR */
#define ADVSEC_SAFECLIB_ERR(rc) \
    printf("safeclib error at rc - %d %s %s:%d\n", (int)rc, __FILE__, __FUNCTION__, __LINE__)

/* Safe C library function implementations */
static inline errno_t sprintf_s(char *dest, size_t destsz, const char *fmt, ...) {
    va_list args;
    int result;
    
    if (!dest || !fmt || destsz == 0) return ESNULLP;
    if (destsz > RSIZE_MAX) return ESLEMAX;
    
    va_start(args, fmt);
    result = vsnprintf(dest, destsz, fmt, args);
    va_end(args);
    
    if (result < 0 || (size_t)result >= destsz) {
        if (destsz > 0) dest[0] = '\0';
        return ESNOSPC;
    }
    return EOK;
}

static inline errno_t memset_s(void *dest, size_t destsz, int ch, size_t count) {
    if (!dest || destsz == 0) return ESNULLP;
    if (destsz > RSIZE_MAX || count > RSIZE_MAX) return ESLEMAX;
    if (count > destsz) return ESNOSPC;
    
    memset(dest, ch, count);
    return EOK;
}

static inline errno_t strcpy_s(char *dest, size_t destsz, const char *src) {
    size_t src_len;
    
    if (!dest || !src || destsz == 0) return ESNULLP;
    if (destsz > RSIZE_MAX) return ESLEMAX;
    
    src_len = strlen(src);
    if (src_len >= destsz) {
        if (destsz > 0) dest[0] = '\0';
        return ESNOSPC;
    }
    
    strcpy(dest, src);
    return EOK;
}

static inline errno_t strcmp_s(const char *dest, size_t destsz, const char *src, int *indicator) {
    (void)destsz;  /* Unused parameter for this implementation */
    
    if (!dest || !src || !indicator) return ESNULLP;
    
    *indicator = strcmp(dest, src);
    return EOK;
}

static inline errno_t strcat_s(char *dest, size_t destsz, const char *src) {
    size_t dest_len, src_len;
    
    if (!dest || !src || destsz == 0) return ESNULLP;
    if (destsz > RSIZE_MAX) return ESLEMAX;
    
    dest_len = strlen(dest);
    src_len = strlen(src);
    
    if (dest_len + src_len >= destsz) {
        return ESNOSPC;
    }
    
    strcat(dest, src);
    return EOK;
}

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
typedef unsigned char               BOOL;
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
extern FILE* g_advsec_logfile;
extern int g_advsec_trace_level; 

/* CCSP global variables - matching common-library */
extern int g_iTraceLevel; /* Defined in ssp_action.c */
extern char *pComponentName;

/* CCSP MessageBus globals - for legacy compatibility */
extern void* g_MessageBusHandle_Irep;  /* Not defined in existing code */
extern char g_SubSysPrefix_Irep[32];   /* Not defined in existing code */

/* RBUS function declarations */
extern int advsec_rbus_init(const char *component_name);
extern void advsec_rbus_terminate(void);

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
    
    va_list args;
    time_t rawtime;
    struct tm* timeinfo;
    char timestamp[32];
    
    /* Get current timestamp - matching common-library format */
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    snprintf(timestamp, sizeof(timestamp), "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d",
            timeinfo->tm_year + 1900, timeinfo->tm_mon + 1, timeinfo->tm_mday,
            timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
    
    /* Print in CCSP format: timestamp-component-level-message */
    fprintf(stderr, "%s-AdvSec-%s-", timestamp, g_advsec_TraceLevelStr[level]);
    
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    
    /* Also write to log file if available */
    if (g_advsec_logfile) {
        fprintf(g_advsec_logfile, "%s-AdvSec-%s-", timestamp, g_advsec_TraceLevelStr[level]);
        va_start(args, format);
        vfprintf(g_advsec_logfile, format, args);
        va_end(args);
        fflush(g_advsec_logfile);
    }
}

/* Simple log write for backward compatibility */
static inline void advsec_log_write(const char* level, const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    /* Write to console */
    fprintf(stdout, "[%s] ", level);
    vfprintf(stdout, format, args);
    fflush(stdout);
    
    va_end(args);
}

/* CCSP Trace Macros - Exact format matching common-library ccsp_trace.h
 * These macros expect double parentheses: CcspTraceError(("message %s", arg))
 * The outer parentheses are part of the macro, inner parentheses contain format and args
 */

#ifndef CcspTraceError
#define CcspTraceError(msg) advsec_ccsp_trace_exec(CCSP_TRACE_LEVEL_ERROR, msg)
#endif

#ifndef CcspTraceWarning  
#define CcspTraceWarning(msg) advsec_ccsp_trace_exec(CCSP_TRACE_LEVEL_WARNING, msg)
#endif

#ifndef CcspTraceInfo
#define CcspTraceInfo(msg) advsec_ccsp_trace_exec(CCSP_TRACE_LEVEL_INFO, msg)
#endif

#ifndef CcspTraceDebug
#define CcspTraceDebug(msg) advsec_ccsp_trace_exec(CCSP_TRACE_LEVEL_DEBUG, msg)
#endif

#ifndef CcspTraceNotice
#define CcspTraceNotice(msg) advsec_ccsp_trace_exec(CCSP_TRACE_LEVEL_NOTICE, msg)
#endif

#ifndef CcspTraceCritical
#define CcspTraceCritical(msg) advsec_ccsp_trace_exec(CCSP_TRACE_LEVEL_CRITICAL, msg)
#endif

#ifndef CcspTraceAlert
#define CcspTraceAlert(msg) advsec_ccsp_trace_exec(CCSP_TRACE_LEVEL_ALERT, msg)
#endif

#ifndef CcspTraceEmergency
#define CcspTraceEmergency(msg) advsec_ccsp_trace_exec(CCSP_TRACE_LEVEL_EMERGENCY, msg)
#endif

/* Macro to extract arguments from double parentheses and execute trace */
#define advsec_ccsp_trace_exec(level, msg) \
    do { \
        if ((level) <= g_iTraceLevel) { \
            advsec_ccsp_log_write((level), ADVSEC_EXTRACT_ARGS msg); \
        } \
    } while(0)

/* Helper macro to extract arguments from parentheses */
#define ADVSEC_EXTRACT_ARGS(...) __VA_ARGS__

/* CCSP-compatible logging function */
static inline void advsec_ccsp_log_write(int level, const char* format, ...) {
    if (level > g_iTraceLevel || level < 0 || level > 7) return;
    
    va_list args;
    time_t rawtime;
    struct tm* timeinfo;
    char timestamp[80];
    
    /* Get current timestamp - matching common-library format */
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    snprintf(timestamp, sizeof(timestamp), "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d",
            timeinfo->tm_year + 1900, timeinfo->tm_mon + 1, timeinfo->tm_mday,
            timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
    
    /* Print in CCSP format: timestamp-component-level-message */
    fprintf(stderr, "%s-%s-%s-", timestamp, pComponentName ? pComponentName : "AdvSec", g_advsec_TraceLevelStr[level]);
    
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

/* Additional ANSC trace/debug functions - no-op implementations */
#ifndef AnscTraceWarning
#define AnscTraceWarning(msg) CcspTraceWarning(msg)
#endif

#ifndef AnscSetTraceLevel
#define AnscSetTraceLevel(level) do { \
    g_advsec_trace_level = (level); \
    g_iTraceLevel = (level); \
    if (g_advsec_trace_level < 0) g_advsec_trace_level = 0; \
    if (g_advsec_trace_level > 7) g_advsec_trace_level = 7; \
    if (g_iTraceLevel < 0) g_iTraceLevel = 0; \
    if (g_iTraceLevel > 7) g_iTraceLevel = 7; \
} while(0)
#endif

#ifndef AnscGetTraceLevel
#define AnscGetTraceLevel() (g_iTraceLevel)
#endif

/* Additional CCSP compatible functions */
static inline void AnscSetTraceLevel_func(int level) {
    AnscSetTraceLevel(level);
}

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
static inline void CCSP_Msg_SleepInMilliSeconds(unsigned int milliseconds) {
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
