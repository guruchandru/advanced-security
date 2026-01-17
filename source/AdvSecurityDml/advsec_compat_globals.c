/*
 * Global variable definitions for CCSP compatibility
 * This file defines the global variables that are declared as extern in advsec_compat_types.h
 */

#include "advsec_compat_types.h"

/* CCSP logging global variables */
FILE* g_advsec_logfile = NULL;
int g_advsec_trace_level = 6; /* Default to INFO level */
/* Note: g_iTraceLevel is already defined in ssp_action.c */
char *pComponentName = "AdvSec"; /* Component name for logging */

/* CCSP MessageBus globals - these are already defined in ssp_main.c, so we only need to handle missing ones */
void* g_MessageBusHandle_Irep = NULL;  /* This one is not defined in ssp_main.c */
char g_SubSysPrefix_Irep[32] = "eRT."; /* This one is not defined in ssp_main.c */
/* Note: g_Subsystem and g_bActive are already defined in ssp_main.c */

/* RBUS function implementations are now in advsec_rbus_handlers.c */