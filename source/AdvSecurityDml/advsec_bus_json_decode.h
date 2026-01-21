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

typedef enum {
    ADVSEC_NAMESPACE_DEVICE_FINGERPRINT,
    ADVSEC_NAMESPACE_ADVANCED_SECURITY,
    ADVSEC_NAMESPACE_SAFEBROWSING,
    ADVSEC_NAMESPACE_SOFTFLOWD,
    ADVSEC_NAMESPACE_PARENTAL_CONTROL,
    ADVSEC_NAMESPACE_PRIVACY_PROTECTION,
    ADVSEC_NAMESPACE_RFC_RABIDFRAMEWORK,
    ADVSEC_NAMESPACE_RFC_ADVANCED_PARENTAL_CONTROL,
    ADVSEC_NAMESPACE_RFC_PRIVACY_PROTECTION,
    ADVSEC_NAMESPACE_RFC_DEVICE_FINGERPRINT_ICMPV6,
    ADVSEC_NAMESPACE_RFC_WS_DISCOVERY_ANALYSIS,
    ADVSEC_NAMESPACE_RFC_ADVANCED_SECURITY_OTM,
    ADVSEC_NAMESPACE_RFC_ADVANCED_SECURITY_USERSPACE,
    ADVSEC_NAMESPACE_RFC_ADVANCED_SECURITY_CUJOTRACER,
    ADVSEC_NAMESPACE_RFC_ADVANCED_SECURITY_CUJOTELEMETRY,
    ADVSEC_NAMESPACE_RFC_ADVSEC_SENTRY_AT_THE_EDGE,
    ADVSEC_NAMESPACE_RFC_ADVSEC_TCP_TRACKER_FILTER_DEVICES,
    ADVSEC_NAMESPACE_RFC_WIFI_DATA_COLLECTION,
    ADVSEC_NAMESPACE_RFC_LEVL,
    ADVSEC_NAMESPACE_RFC_ADVSEC_AGENT,
    ADVSEC_NAMESPACE_RFC_ADVSEC_SAFEBROWSING,
    ADVSEC_NAMESPACE_RFC_ADVSEC_CUJOTELEMETRY_WIFIFP,
    ADVSEC_NAMESPACE_RFC_ADVSEC_AGENT_RAPTR,
    ADVSEC_NAMESPACE_UNKNOWN
} advsec_namespace_t;

typedef struct {
    char* full_name;
    char* short_name;
    char* parent_namespace;
    advsec_namespace_t namespace_type;
    rbusValueType_t type;
    bool writable;
} advsec_param_metadata_t;

int advsec_decode_json_config(rbusHandle_t handle, const char *json_file_path);

void advsec_free_registered_elements(void);

advsec_param_metadata_t* advsec_find_param_metadata(const char* full_name);
void advsec_free_param_metadata(void);

#endif /* ADVSEC_BUS_JSON_DECODE_H */
