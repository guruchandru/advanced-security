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
#define _GNU_SOURCE
#include <string.h>

#ifdef __GNUC__
#if (!defined _NO_EXECINFO_H_)
#include <execinfo.h>
#endif
#endif

#include "ssp_global.h"
#ifdef INCLUDE_BREAKPAD
#include "breakpad_wrapper.h"
#endif
#include "stdlib.h"
#include "webconfig_framework.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
/* RBUS implementation */
#include "../AdvSecurityDml/advsec_rbus_handlers.h"

#define MAX_SUBSYSTEM_SIZE 32

#define ADVSEC_CCSP_INIT_FILE_BOOTUP "/tmp/advsec_ccsp_initialized_bootup"
#define ADVSEC_CUJO_AGENT_ROOT_PRIV "/tmp/advsec_cujo_agent_root_priv"
#define BLOCKLIST_FILE "/opt/secure/Blocklist_file.txt"
#define ADVSEC_AGENT_PROC_NAME "cujo-agent"
#define ADVSEC_LOG_FILE "/rdklogs/logs/advsec_test.log"
#define NUM_SUBSYSTEM_TYPES (sizeof(gSubsystem_type_table)/sizeof(gSubsystem_type_table[0]))

/* Global log file handle */
FILE* g_advsec_logfile = NULL;

/* Initialize logging to file */
static void init_advsec_logging(void) {
    /* Create directory if it doesn't exist */
    if (mkdir("/rdklogs", 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Failed to create /rdklogs directory: %s\n", strerror(errno));
    }
    if (mkdir("/rdklogs/logs", 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Failed to create /rdklogs/logs directory: %s\n", strerror(errno));
    }
    
    /* Open log file */
    g_advsec_logfile = fopen(ADVSEC_LOG_FILE, "a");
    if (!g_advsec_logfile) {
        fprintf(stderr, "Failed to open log file %s: %s\n", ADVSEC_LOG_FILE, strerror(errno));
    } else {
        fprintf(g_advsec_logfile, "\n=== Advanced Security Log Started ===\n");
        fflush(g_advsec_logfile);
    }
}

/* Initialize logging to file */
static void init_advsec_logging(void) {
    /* Create directory if it doesn't exist */
    if (mkdir("/rdklogs", 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Failed to create /rdklogs directory: %s\n", strerror(errno));
    }
    if (mkdir("/rdklogs/logs", 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Failed to create /rdklogs/logs directory: %s\n", strerror(errno));
    }
    
    /* Open log file */
    g_advsec_logfile = fopen(ADVSEC_LOG_FILE, "a");
    if (!g_advsec_logfile) {
        fprintf(stderr, "Failed to open log file %s: %s\n", ADVSEC_LOG_FILE, strerror(errno));
    } else {
        fprintf(g_advsec_logfile, "\n=== Advanced Security Log Started ===\n");
        fflush(g_advsec_logfile);
    }
}

/* Legacy common-library global variables commented out for JSON-driven RBUS approach */
/* PDSLH_CPE_CONTROLLER_OBJECT     pDslhCpeController      = NULL; */
/* PCOMPONENT_COMMON_DM            g_pComponent_Common_Dm  = NULL; */
/* PCCSP_FC_CONTEXT                pAdvSecFcContext           = (PCCSP_FC_CONTEXT            )NULL; */
/* PCCSP_CCD_INTERFACE             pAdvSecCcdIf               = (PCCSP_CCD_INTERFACE         )NULL; */
/* PCCC_MBI_INTERFACE              pTadMbiIf               = (PCCC_MBI_INTERFACE          )NULL; */
char                            g_Subsystem[MAX_SUBSYSTEM_SIZE]         = {0};
BOOL                            g_bActive               = FALSE;

int consoleDebugEnable = 0;
FILE* debugLogFile;

enum subsytemType_e {
    SUBSYS,
    C,
    DEBUG,
    LOGFILE,
};


typedef struct gSubsystem_pair{
  char                 *name;
  enum subsytemType_e   type;
} GSUBSYSTEM_PAIR;

GSUBSYSTEM_PAIR gSubsystem_type_table[] = {
  { "-subsys",     SUBSYS  },
  { "-c",          C       },
  { "-DEBUG",      DEBUG   },
  { "-LOGFILE",    LOGFILE }
};

int get_gSubsystem_type_from_name(char *name, enum subsytemType_e *type_ptr)
{
  errno_t rc = -1;
  int ind = -1;
  unsigned int i = 0;
  size_t strsize = 0;

  if((name == NULL) || (type_ptr == NULL))
     return 0;

  strsize = strlen(name);

  for (i = 0 ; i < NUM_SUBSYSTEM_TYPES ; ++i)
  {
      rc = strcmp_s(name, strsize, gSubsystem_type_table[i].name, &ind);
      ERR_CHK(rc);
      if((rc == EOK) && (!ind))
      {
          *type_ptr = gSubsystem_type_table[i].type;
          return 1;
      }
  }
  return 0;
}


int  cmd_dispatch(int  command)
{
    /* Legacy messagebus/DML code commented out for RBUS approach - no longer needed */
    /* char*                           pParamNames[]      = {"Device.IP.Diagnostics.IPPing."}; */
    /* parameterValStruct_t**          ppReturnVal        = NULL; */
    /* int                             ulReturnValCount   = 0; */
    /* int                             i                  = 0; */
    ANSC_STATUS                     returnStatus       = ANSC_STATUS_SUCCESS;

    switch ( command )
    {
            case	'e' :

#ifdef _ANSC_LINUX
                CcspTraceInfo(("Initializing Advanced Security with RBUS...\n"));

                /* New RBUS-based initialization */
                if (advsec_rbus_init(CCSP_COMPONENT_NAME_ADVSEC) != 0) {
                    CcspTraceError(("Failed to initialize RBUS\n"));
                    return -1;
                }

                g_bActive = TRUE;
                CcspTraceInfo(("AdvSec RBUS Module loaded successfully...\n"));

                /* Legacy messagebus/DML approach (commented out) */

#endif

            break;

            case    'r' :

            /* Legacy CcspCcMbi_GetParameterValues will be replaced with rbus_get() */
            #if 0
            CcspCcMbi_GetParameterValues
                (
                    DSLH_MPA_ACCESS_CONTROL_ACS,
                    pParamNames,
                    1,
                    &ulReturnValCount,
                    &ppReturnVal,
                    NULL
                );



            for ( i = 0; i < ulReturnValCount; i++ )
            {
                CcspTraceWarning(("Parameter %d name: %s value: %s \n", i+1, ppReturnVal[i]->parameterName, ppReturnVal[i]->parameterValue));
            }
            #endif

			break;

        case    'm':

                AnscPrintComponentMemoryTable(pComponentName);

                break;

        case    't':

                AnscTraceMemoryTable();

                break;

        case    'c':
                /* Terminate RBUS */
                if (g_bActive) {
                    advsec_rbus_terminate();
                    g_bActive = FALSE;
                }
                
                /* Legacy cancel function (commented out) */
                /* ssp_cancel_advsec(); */

                break;

        default:
            break;
    }

    return 0;
}

static void _print_stack_backtrace(void)
{
#ifdef __GNUC__
#if (!defined _COSA_SIM_) && (!defined _NO_EXECINFO_H_)
        void* tracePtrs[100];
        char** funcNames = NULL;
        int i, count = 0;

        int fd;
        const char* path = "/nvram/advsecssp_backtrace";
        fd = open(path, O_RDWR | O_CREAT);
        if (fd < 0)
        {
            CcspTraceError(("failed to open backtrace file: %s", path));
            return;
        }

        count = backtrace( tracePtrs, 100 );
        backtrace_symbols_fd( tracePtrs, count, fd );
        close(fd);

        funcNames = backtrace_symbols( tracePtrs, count );

        if ( funcNames ) {
            // Print the stack trace
            for( i = 0; i < count; i++ )
                CcspTraceInfo(("%s\n", funcNames[i] ));

            // Free the string pointers
            free( funcNames );
        }
#endif
#endif
}

#if defined(_ANSC_LINUX)
static void daemonize(void) {
	switch (fork()) {
	case 0:
		break;
	case -1:
		// Error
		CcspTraceError(("Error daemonizing (fork)! %d - %s\n", errno, strerror(
				errno)));
		exit(0);
		break;
	default:
		_exit(0);
	}

	if (setsid() < 	0) {
		CcspTraceError(("Error demonizing (setsid)! %d - %s\n", errno, strerror(errno)));
		exit(0);
	}

//	chdir("/");


#ifndef  _DEBUG

	int fd;
	fd = open("/dev/null", O_RDONLY);
	if (fd != 0) {
		dup2(fd, 0);
		close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd != 1) {
		dup2(fd, 1);
		close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd != 2) {
		dup2(fd, 2);
		close(fd);
	}
#endif
}

void sig_handler(int sig)
{
    if ( sig == SIGINT ) {
    	signal(SIGINT, sig_handler); /* reset it to this function */
    	CcspTraceError(("SIGINT received!\n"));
        exit(0);
    }
    else if ( sig == SIGUSR1 ) {
    	signal(SIGUSR1, sig_handler); /* reset it to this function */
    	CcspTraceWarning(("SIGUSR1 received!\n"));
    }
    else if ( sig == SIGUSR2 ) {
    	CcspTraceWarning(("SIGUSR2 received!\n"));
    }
    else if ( sig == SIGCHLD ) {
    	signal(SIGCHLD, sig_handler); /* reset it to this function */
    	CcspTraceWarning(("SIGCHLD received!\n"));
    }
    else if ( sig == SIGPIPE ) {
    	signal(SIGPIPE, sig_handler); /* reset it to this function */
    	CcspTraceWarning(("SIGPIPE received!\n"));
    }
    else {
    	/* get stack trace first */
    	_print_stack_backtrace();
    	CcspTraceError(("Signal %d received, exiting!\n", sig));
    	exit(0);
    }

}

#endif

BOOL isCujoBlocklisted()
{
    BOOL ret = false;
    FILE *fp = NULL;
    int len = 0;
    char *process_name = ADVSEC_AGENT_PROC_NAME;
    char *buf = NULL;
    fp = fopen(BLOCKLIST_FILE, "r");
    if(fp == NULL)
    {
        return ret;
    }
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    /* CID 255483: Argument cannot be negative */
    if(len == -1)
    {
        fclose(fp);
        return ret;
    }
    fseek(fp, 0, SEEK_SET);
    buf = (char*)malloc(sizeof(char) * (len + 1));
    if (buf != NULL)
    {
        memset(buf, 0, (sizeof(char) * (len + 1)));
        /* CID 255486: Ignoring number of bytes read */
        int result = fread(buf, 1, len, fp);
        if (result != len)
        {
            CcspTraceError(("Failed to read file %s:%d\n", __FUNCTION__, __LINE__));
            free(buf);
            buf = NULL;
            fclose(fp);
            return ret;
        }
        else
        {
            buf[result] = '\0';
        }
    }
    else
    {
        CcspTraceError(("Memory allocation failed for buffer %s:%d\n", __FUNCTION__, __LINE__));
    }
    fclose(fp);

    if(buf != NULL)
    {
        /* CID 255468: Resource leak */
        if(strlen(buf) != 0)
        {
            if(strcasestr(buf,process_name) != NULL)
            {
                CcspTraceInfo(("process[%s] is found in blocklist, thus process runs in Root mode\n", process_name));
                ret = true;
            }
        }
        free(buf);
        buf = NULL;
    }
    return ret;
}

void drop_root(void)
{
    FILE *fp = NULL;
    BOOL blocklist_ret = false;
    blocklist_ret = isCujoBlocklisted();
    if(blocklist_ret)
    {
        CcspTraceInfo(("NonRoot feature is disabled\n"));
        if ((fp = fopen(ADVSEC_CUJO_AGENT_ROOT_PRIV, "w")))
        {
            fclose(fp);
        }
        else
        {
            CcspTraceError(("File creation failed %s:%d\n", __FUNCTION__, __LINE__));
        }
    }
    else
    {
        CcspTraceInfo(("NonRoot feature is enabled, dropping root privileges for cujo-agent process\n"));
    }
}

int main(int argc, char* argv[])
{
    ANSC_STATUS                     returnStatus       = ANSC_STATUS_SUCCESS;
    int                             cmdChar            = 0;
    BOOL                            bRunAsDaemon       = TRUE;
    int                             idx                = 0;
    errno_t                         rc                 = 1;
    enum subsytemType_e             type;
    int                             ret                = 0;

    /* Initialize logging to file */
    init_advsec_logging();
    
    CcspTraceInfo(("Advanced Security SSP Starting...\n"));

    debugLogFile = stderr;
#if defined(_DEBUG) && defined(_COSA_SIM_)
    AnscSetTraceLevel(CCSP_TRACE_LEVEL_INFO);
#endif

    for (idx = 1; idx < argc; idx++)
    {
        /* get the susbsytem type based on the command line argurments */

        if(get_gSubsystem_type_from_name(argv[idx], &type))
        {
             if (type  == SUBSYS)
             {
                  /* Coverity Fix  CID:135431 STRING_SIZE */
                  if( ( (idx+1) < argc  ) && ( strlen(argv[idx + 1]) < sizeof(g_Subsystem) ) )
                  {
                       rc = strcpy_s(g_Subsystem, sizeof(g_Subsystem), argv[idx+1]);
                       if(rc != EOK)
                       {
                           ERR_CHK(rc);
                           CcspTraceError(("Error in copying argv[idx+1] to g_Subsystem\n"));
                           exit(0);
                       }
                  }
                  else
                  {
                       CcspTraceWarning(("idx + 1 exceeds argc  \n"));  
                       exit(0);
                  }
             }
             else if (type == C)
             {
                  bRunAsDaemon = FALSE;
             }
             else if (type == DEBUG)
             {
                  consoleDebugEnable = 1;
                  CcspTraceInfo(("DEBUG ENABLE ON \n"));
             }
             else if (type == LOGFILE)
             {
                  if( (idx+1) < argc )
                  {
                      // We assume argv[1] is a filename to open
                      FILE *fp = fopen( argv[idx + 1], "a+" );

                      /* fopen returns 0, the NULL pointer, on failure */
                      if (!fp)
                      {
                           CcspTraceWarning(("Cannot open -LOGFILE %s\n", argv[idx+1]));
                      }
                      else
                      {
                           debugLogFile = fp;
                           fprintf(debugLogFile, "Log File [%s] Opened for Writing in Append Mode \n",  argv[idx+1]);
                      }
                  }
                  else
                  {
                       CcspTraceWarning(("Invalid Entry for -LOGFILE input \n" ));
                  }
             }
        }          
    }

    /* Set the global pComponentName */
    pComponentName = CCSP_COMPONENT_NAME_ADVSEC;

#ifdef   _DEBUG
    /*AnscSetTraceLevel(CCSP_TRACE_LEVEL_INFO);*/
#endif

#if  defined(_ANSC_WINDOWSNT)

    AnscStartupSocketWrapper(NULL);

    display_info();

    ret = cmd_dispatch('e');
    if(ret != 0)
    {
       CcspTraceError(("Exit error - cmd_dispatch failed %s:%d\n", __FUNCTION__, __LINE__));
       exit(0);
    }

    while ( cmdChar != 'q' )
    {
        cmdChar = getchar();

        ret = cmd_dispatch(cmdChar);
        if(ret != 0)
        {
            CcspTraceError(("Exit error - cmd_dispatch failed %s:%d\n", __FUNCTION__, __LINE__));
            exit(0);
        }
    }
#elif defined(_ANSC_LINUX)
    drop_root();
    if ( bRunAsDaemon )
        daemonize();

#ifdef INCLUDE_BREAKPAD
    breakpad_ExceptionHandler();
#else
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    /*signal(SIGCHLD, sig_handler);*/
    signal(SIGUSR1, sig_handler);
    signal(SIGUSR2, sig_handler);

    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGKILL, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGHUP, sig_handler);
    signal(SIGPIPE, SIG_IGN);
#endif

    ret = cmd_dispatch('e');
    if(ret != 0)
    {
        CcspTraceError(("Exit error - cmd_dispatch failed %s:%d\n", __FUNCTION__, __LINE__));
        exit(0);
    }

    check_component_crash(ADVSEC_CCSP_INIT_FILE_BOOTUP);

    CcspTraceInfo(("ADVSEC:----------------------touch /tmp/advsec_ccsp__initialized_bootup-------------------\n"));
    ret = creat(ADVSEC_CCSP_INIT_FILE_BOOTUP,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if(ret < 0)
    {
        CcspTraceError(("Exit error - Error in copying init_file  %s:%d\n", __FUNCTION__, __LINE__));
        exit(0);
    }

    if ( bRunAsDaemon )
    {
        while(1)
        {
            sleep(30);
        }
    }
    else
    {
        while ( cmdChar != 'q' )
        {
            cmdChar = getchar();

            sleep(30);
            ret = cmd_dispatch(cmdChar);
            if(ret != 0)
            {
                CcspTraceError(("Exit error - cmd_dispatch failed %s:%d\n", __FUNCTION__, __LINE__));
                exit(0);
            }
        }
    }
#endif

    if ( g_bActive )
    {
        /* Terminate RBUS */
        advsec_rbus_terminate();
        g_bActive = FALSE;
        
        /* Legacy cancel function (commented out)
        returnStatus = ssp_cancel_advsec();
        if(returnStatus != ANSC_STATUS_SUCCESS)
        {
            CcspTraceError(("Exit error - ssp_cancel_advsec() failed %s:%d\n", __FUNCTION__, __LINE__));
            exit(0);
        }

        g_bActive = FALSE;
        */
    }

    /* Close log file */
    if (g_advsec_logfile) {
        fprintf(g_advsec_logfile, "=== Advanced Security Log Ended ===\n");
        fclose(g_advsec_logfile);
        g_advsec_logfile = NULL;
    }

    return 0;
}


