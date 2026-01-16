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

#include <errno.h>
#include <string.h>
#include <msgpack.h>
#include <stdarg.h>
/* Legacy ccsp_trace macros replaced by advsec_compat_types.h */
/* #include "ccsp_trace.h" */
#include "advsecurity_helpers.h"
#include "advsecurity_param.h"
/* Legacy code commented out for JSON-based RBUS approach */
/* #include "ansc_platform.h" */

/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
/* none */
/*----------------------------------------------------------------------------*/
/*                               Data Structures                              */
/*----------------------------------------------------------------------------*/
enum {
    OK                       = HELPERS_OK,
    OUT_OF_MEMORY            = HELPERS_OUT_OF_MEMORY,
    INVALID_FIRST_ELEMENT    = HELPERS_INVALID_FIRST_ELEMENT,
    MISSING_ENTRY         = HELPERS_MISSING_WRAPPER,
    INVALID_OBJECT,
    INVALID_VERSION,
};
/*----------------------------------------------------------------------------*/
/*                            File Scoped Variables                           */
/*----------------------------------------------------------------------------*/
/* none */
/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
int process_advsecurityparams( advsecurityparam_t *e, msgpack_object_map *map );
int process_advsecuritydoc( advsecuritydoc_t *ad, int num, ...); 
/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
/* See advsecuritydoc.h for details. */
advsecuritydoc_t* advsecuritydoc_convert( const void *buf, size_t len )
{
	return comp_helper_convert( buf, len, sizeof(advsecuritydoc_t), ADVSEC_WEBCONFIG_SUBDOC_NAME,
                            MSGPACK_OBJECT_MAP, true,
                           (process_fn_t) process_advsecuritydoc,
                           (destroy_fn_t) advsecuritydoc_destroy );
}
/* See advsecuritydoc.h for details. */
void advsecuritydoc_destroy( advsecuritydoc_t *ad )
{
	if( NULL != ad )
	{
		
		if( NULL != ad->subdoc_name )
		{
			AnscFreeMemory ( ad->subdoc_name );
		}
                if( NULL != ad->param )
                {
                        AnscFreeMemory ( ad->param );
                }
		AnscFreeMemory ( ad );
	}
}
/* See advsecuritydoc.h for details. */
const char* advsecuritydoc_strerror( int errnum )
{
    struct error_map {
        int v;
        const char *txt;
    } map[] = {
        { .v = OK,                               .txt = "No errors." },
        { .v = OUT_OF_MEMORY,                    .txt = "Out of memory." },
        { .v = INVALID_FIRST_ELEMENT,            .txt = "Invalid first element." },
        { .v = INVALID_VERSION,                 .txt = "Invalid 'version' value." },
        { .v = INVALID_OBJECT,                .txt = "Invalid 'value' array." },
        { .v = 0, .txt = NULL }
    };
    int i = 0;
    while( (map[i].v != errnum) && (NULL != map[i].txt) ) { i++; }
    if( NULL == map[i].txt )
    {
	CcspTraceError(("----%s----\n", __FUNCTION__));
        return "Unknown error.";
    }
    return map[i].txt;
}
/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/
/**
 *  Convert the msgpack map into the doc_t structure.
 *
 *  @param e    the entry pointer
 *  @param map  the msgpack map pointer
 *
 *  @return 0 on success, error otherwise
 */
int process_advsecurityparams( advsecurityparam_t *e, msgpack_object_map *map )
{
    int left = map->size;
    uint8_t objects_left = 0x05;
    msgpack_object_kv *p;
    p = map->ptr;
    while( (0 < objects_left) && (0 < left--) )
    {
        if( MSGPACK_OBJECT_STR == p->key.type )
        {
              if( MSGPACK_OBJECT_BOOLEAN == p->val.type )
              {
                 if( 0 == match(p, "FingerPrintEnable") )
                 {
                     e->fingerprint_enable = p->val.via.boolean;
                     objects_left &= ~(1 << 0);
                 }
                 if( 0 == match(p, "SoftflowdEnable") )
                 {
                     e->softflowd_enable = p->val.via.boolean;
                     objects_left &= ~(1 << 3);
                 }
                 if( 0 == match(p, "SafeBrowsingEnable") )
                 {
                     e->safebrowsing_enable = p->val.via.boolean;
                     objects_left &= ~(1 << 4);
                 }
                 if( 0 == match(p, "ParentalControlActivate") )
                 {
                     e->parental_control_activate = p->val.via.boolean;
                     objects_left &= ~(1 << 1);
                 }
                 if( 0 == match(p, "PrivacyProtectionActivate") )
                 {
                     e->privacy_protection_activate = p->val.via.boolean;
                     objects_left &= ~(1 << 2);
                 }
              }

        }
           p++;
    }
        
    
    if( 1 & objects_left ) {
    } else {
        errno = OK;
    }
   
    return (0 == objects_left) ? 0 : -1;
}
int process_advsecuritydoc( advsecuritydoc_t *ad,int num, ... )
{
//To access the variable arguments use va_list 
	va_list valist;
	va_start(valist, num);//start of variable argument loop

	msgpack_object *obj = va_arg(valist, msgpack_object *);//each usage of va_arg fn argument iterates by one time
	msgpack_object_map *mapobj = &obj->via.map;

	msgpack_object *obj1 = va_arg(valist, msgpack_object *);
	ad->subdoc_name = strndup( obj1->via.str.ptr, obj1->via.str.size );

	msgpack_object *obj2 = va_arg(valist, msgpack_object *);
	ad->version = (uint32_t) obj2->via.u64;

	msgpack_object *obj3 = va_arg(valist, msgpack_object *);
	ad->transaction_id = (uint16_t) obj3->via.u64;
	va_end(valist);//End of variable argument loop


	ad->param = (advsecurityparam_t *) AnscAllocateMemory( sizeof(advsecurityparam_t) );
        if( NULL == ad->param )
        {
	    CcspTraceError(("%s entries count AnscAllocateMemory failed\n", __FUNCTION__));
            return -1;
        }
        memset( ad->param, 0, sizeof(advsecurityparam_t));


	if( 0 != process_advsecurityparams(ad->param, mapobj) )
	{
		CcspTraceError(("%s failed\n", __FUNCTION__));
		return -1;
	}

    return 0;
}

