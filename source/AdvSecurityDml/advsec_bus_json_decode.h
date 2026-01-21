/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2024 RDK Management
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
*/

#ifndef ADVSEC_BUS_JSON_DECODE_H
#define ADVSEC_BUS_JSON_DECODE_H

#include "advsec_compat_types.h"  /* Include compatibility layer */
#include <rbus.h>
#include <stdbool.h>

#define JSON_CONFIG_PATH "advsec_dml_config.json"

/* Parameter metadata stored from JSON */
typedef struct {
    char *full_param_name;        /* Full TR181 parameter path */
    char *short_param_name;       /* Short parameter name (e.g., "Enable", "Data") */
    char *parent_object;          /* Parent object (e.g., "DeviceFingerPrint", "SafeBrowsing") */
    rbusValueType_t data_type;    /* RBUS data type */
    bool writable;                /* Whether parameter is writable */
} advsec_param_metadata_t;

/* Decode and register advanced security parameters from JSON config */
int advsec_decode_json_config(rbusHandle_t handle, const char *json_file_path);

/* Lookup parameter metadata by full parameter name */
advsec_param_metadata_t* advsec_get_param_metadata(const char *param_name);

/* Cleanup parameter metadata storage */
void advsec_cleanup_param_metadata(void);

#endif /* ADVSEC_BUS_JSON_DECODE_H */
