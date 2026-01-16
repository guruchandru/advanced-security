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

#include "cosa_adv_security_webconfig.h"
#include "webconfig_framework.h"
#include <syscfg/syscfg.h>
/* Legacy common-library includes commented out for JSON-driven RBUS approach */
/* #include "safec_lib_common.h" */
/* API to get the subdoc version */


uint32_t advsec_webconfig_get_blobversion(char* subdoc)
{

	char subdoc_ver[64] = {0}, buf[72] = {0};
        errno_t rc = -1;
        rc = sprintf_s(buf,sizeof(buf),"%s_version",subdoc);
        if(rc < EOK)
        {
            ERR_CHK(rc);
            return 0;
        }
    	if ( syscfg_get( NULL, buf, subdoc_ver, sizeof(subdoc_ver)) == 0 )
    	{
        	int version = atoi(subdoc_ver);
      		//  uint32_t version = strtoul(subdoc_ver, NULL, 10) ; 

        	return (uint32_t)version;
    	}
    	return 0;
}

/* API to update the subdoc version */
int advsec_webconfig_set_blobversion(char* subdoc,uint32_t version)
{

	char subdoc_ver[64] = {0}, buf[72] = {0};
        errno_t rc = -1;

        rc = sprintf_s(subdoc_ver,sizeof(subdoc_ver),"%u",version);
        if(rc < EOK)
        {
            ERR_CHK(rc);
            return -1;
        }
        rc = sprintf_s(buf,sizeof(buf),"%s_version",subdoc);
        if(rc < EOK)
        {
            ERR_CHK(rc);
            return -1;
        }
 	if(syscfg_set(NULL,buf,subdoc_ver) != 0)
 	{
        	CcspTraceError(("syscfg_set failed\n"));
        	return -1;
 	}
	else
     	{
        	if (syscfg_commit() != 0)
        	{
           		CcspTraceError(("syscfg_commit failed\n"));
                return -1;

        	}
    	}
     	
	return 0;
     	 
}

/* API to register all the supported subdocs , versionGet and versionSet are callback functions to get and set the subdoc versions in db */

void advsec_webconfig_init()
{
        errno_t rc = -1;
	char *sub_docs[SUBDOC_COUNT+1]= {ADVSEC_WEBCONFIG_SUBDOC_NAME,(char *) 0 };
    
    	blobRegInfo *blobData;

    	blobData = (blobRegInfo*) AnscAllocateMemory (SUBDOC_COUNT * sizeof(blobRegInfo));
        if(blobData == NULL)
		return;

    	int i;
        rc = memset_s(blobData, SUBDOC_COUNT * sizeof(blobRegInfo), 0, SUBDOC_COUNT * sizeof(blobRegInfo));
        ERR_CHK(rc);

    	blobRegInfo *blobDataPointer = blobData;


    	for (i=0 ; i < SUBDOC_COUNT ; i++ )
    	{
                rc = strcpy_s( blobDataPointer->subdoc_name, sizeof(blobDataPointer->subdoc_name), sub_docs[i]);
                if(rc != EOK)
		{
                    ERR_CHK(rc);
                    return;
                }

        	blobDataPointer++;
    	}

 	 blobDataPointer = blobData ;

    	getVersion versionGet = advsec_webconfig_get_blobversion;

    	setVersion versionSet = advsec_webconfig_set_blobversion;
    
    	register_sub_docs(blobData,SUBDOC_COUNT,versionGet,versionSet);
 
}

/* CallBack API to execute Adv Security Blob request */
pErr advsec_webconfig_process_request(void *Data)
{

    	pErr execRetVal = NULL;
        errno_t rc = -1;
        int ind = -1;

    	execRetVal = (pErr) AnscAllocateMemory (sizeof(Err));
    	if (execRetVal == NULL )
    	{
        	CcspTraceError(("%s : AnscAllocateMemory failed\n",__FUNCTION__));
        	return execRetVal;
    	}

        rc = memset_s(execRetVal, sizeof(Err), 0, sizeof(Err));
        ERR_CHK(rc);

    	execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;

        advsecuritydoc_t *advsec = (advsecuritydoc_t *) Data ;
        if( advsec != NULL && advsec->subdoc_name != NULL && advsec->param != NULL )
        {
            CcspTraceInfo(("%s: advsec->subdoc_name is %s\n", __FUNCTION__, advsec->subdoc_name));
            CcspTraceInfo(("%s: advsec->version is %lu\n", __FUNCTION__, (long)advsec->version));
            CcspTraceInfo(("%s: advsec->transaction_id %lu\n",__FUNCTION__, (long) advsec->transaction_id));
            CcspTraceInfo(("%s: fingerprint_enable[%d], softflowd_enable[%d], safebrowsing_enable[%d], parental_control_activate[%d], privacy_protection_activate[%d]\n",
                __FUNCTION__, advsec->param->fingerprint_enable,advsec->param->softflowd_enable,advsec->param->safebrowsing_enable,
                advsec->param->parental_control_activate, advsec->param->privacy_protection_activate));

            rc = strcmp_s(ADVSEC_WEBCONFIG_SUBDOC_NAME, strlen(ADVSEC_WEBCONFIG_SUBDOC_NAME), advsec->subdoc_name, &ind);
            ERR_CHK(rc);
            if((rc == EOK) && (ind == 0))
            {
                int ret = advsec_webconfig_handle_blob(advsec->param);

                CcspTraceInfo(("%s: Return value = %d\n",__FUNCTION__, ret));

                if ( ret == BLOB_EXEC_SUCCESS )
                {
                    if ( advsec->param->fingerprint_enable == TRUE )
                    {
                        strncpy(execRetVal->ErrorMsg,"enabled",sizeof(execRetVal->ErrorMsg)-1);
                    }
                    else
                    {
                        strncpy(execRetVal->ErrorMsg,"disabled",sizeof(execRetVal->ErrorMsg)-1);
                    }
                }
                else
                {
                    execRetVal->ErrorCode = ret;
                }
            }
            else
            {
                CcspTraceWarning(("%s: Received an invalid subdoc: %s\n",__FUNCTION__, advsec->subdoc_name));
                execRetVal->ErrorCode = SUBDOC_NOT_SUPPORTED;
            }
        }
        else
        {
            CcspTraceWarning(("%s: Received null subdoc blob\n",__FUNCTION__));
            execRetVal->ErrorCode = NULL_BLOB_EXEC_POINTER;
        }

    	return execRetVal;
}

/* Callback function to rollback when Adv Security blob execution fails */
int advsec_webconfig_rollback()
{
    // return 0 to notify framework when rollback is success
    CcspTraceInfo((" Entering %s \n",__FUNCTION__));

    int ret = 0;

    CcspTraceWarning(("%s: Something went wrong while processing webconfig request\n",__FUNCTION__));

    return ret ;
}

/* Callback function to free webconfig resources */
void advsec_webconfig_free_resources(void *arg)
{

    CcspTraceInfo((" Entering %s \n",__FUNCTION__));
    execData *blob_exec_data  = (execData*) arg;

    /* CID 158652: Dereference before null check */
    if ( blob_exec_data != NULL )
    {
        advsecuritydoc_t *ad = (advsecuritydoc_t *) blob_exec_data->user_data ;

        if ( ad != NULL )
        {
            advsecuritydoc_destroy(ad);
        }

        AnscFreeMemory (blob_exec_data);
        blob_exec_data = NULL ;
    }
}

