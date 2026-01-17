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

#ifndef  _SSP_GLOBAL_
#define  _SSP_GLOBAL_

#include <time.h>

/* Compatibility types to replace common-library */
#include "../AdvSecurityDml/advsec_compat_types.h"

/* Legacy common-library includes commented out for JSON-driven RBUS approach */
/* #include "ansc_platform.h" */
/* #include "slap_definitions.h" */
/* #include "ansc_load_library.h" */
/* #include "ccsp_message_bus.h" */
/* #include "ccsp_base_api.h" */
/* #include "ccsp_trace.h" */
/* ccsp_trace.h macros now provided by advsec_compat_types.h */
/* Legacy CCSP custom header removed for JSON-driven RBUS approach */
/* #include "ccsp_custom.h" */

/* Legacy CCSP/DSLH/SLAP headers commented out for JSON-driven RBUS approach */
/* #include "dslh_cpeco_interface.h" */
/* #include "dslh_cpeco_exported_api.h" */
/* #include "slap_vco_exported_api.h" */
/* #include "dslh_ifo_mpa.h" */
/* #include "dslh_dmagnt_interface.h" */
/* #include "dslh_dmagnt_exported_api.h" */
/* #include "ssd_ifo_dml.h" */
/* #include "ccsp_ifo_ccd.h" */
/* #include "ccc_ifo_mbi.h" */
/* #include "messagebus_interface_helper.h" */

#include "ssp_messagebus_interface.h"
#include "ssp_internal.h"

/*
 *  Define custom trace module ID
 */
/* Legacy trace module ID commented out for JSON-driven RBUS approach
#ifdef   ANSC_TRACE_MODULE_ID
    #undef  ANSC_TRACE_MODULE_ID
#endif
#define  ANSC_TRACE_MODULE_ID                       ANSC_TRACE_ID_SSP
*/

#endif
