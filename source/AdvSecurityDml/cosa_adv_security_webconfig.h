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

#ifndef  _COSA_ADV_SECURITY_WEBCONFIG_H
#define  _COSA_ADV_SECURITY_WEBCONFIG_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
/* Legacy common-library includes commented out for JSON-driven RBUS approach */
/* #include "ansc_status.h" */
/* #include "ansc_platform.h" */
/* Compatibility types to replace common-library */
#include "advsec_compat_types.h"

#include "webconfig_framework.h"
#include "advsecurity_param.h"

#define SUBDOC_COUNT 1

#define BLOCK_SIZE 32

uint32_t advsec_webconfig_get_blobversion(char* subdoc);
int advsec_webconfig_set_blobversion(char* subdoc,uint32_t version);
void advsec_webconfig_nit() ;

pErr advsec_webconfig_process_request(void *Data);
int advsec_webconfig_rollback();
void advsec_webconfig_free_resources(void *arg);
int advsec_webconfig_handle_blob(advsecurityparam_t *feature);
void advsec_webconfig_init();

#endif
