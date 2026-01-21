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

#include "advsec_bus_json_decode.h"
#include "advsec_rbus_handlers.h"
#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#define MAX_PARAM_NAME_LEN 256

typedef struct advsec_param_meta_node {
    advsec_param_metadata_t meta;
    struct advsec_param_meta_node* next;
} advsec_param_meta_node_t;

static advsec_param_meta_node_t* g_meta_head = NULL;

static advsec_namespace_t classify_namespace(const char* full_name)
{
    if (!full_name) return ADVSEC_NAMESPACE_UNKNOWN;
    
    if (strstr(full_name, "DeviceFingerPrint") && !strstr(full_name, "RFC"))
        return ADVSEC_NAMESPACE_DEVICE_FINGERPRINT;
    if (strstr(full_name, "AdvancedSecurity") && strstr(full_name, "Data"))
        return ADVSEC_NAMESPACE_ADVANCED_SECURITY;
    if (strstr(full_name, "SafeBrowsing") && !strstr(full_name, "RFC"))
        return ADVSEC_NAMESPACE_SAFEBROWSING;
    if (strstr(full_name, "Softflowd"))
        return ADVSEC_NAMESPACE_SOFTFLOWD;
    if (strstr(full_name, "AdvancedParentalControl") && !strstr(full_name, "RFC"))
        return ADVSEC_NAMESPACE_PARENTAL_CONTROL;
    if (strstr(full_name, "PrivacyProtection") && !strstr(full_name, "RFC"))
        return ADVSEC_NAMESPACE_PRIVACY_PROTECTION;
    if (strstr(full_name, "RFC.Feature.RabidFramework"))
        return ADVSEC_NAMESPACE_RFC_RABIDFRAMEWORK;
    if (strstr(full_name, "RFC.Feature.AdvancedParentalControl"))
        return ADVSEC_NAMESPACE_RFC_ADVANCED_PARENTAL_CONTROL;
    if (strstr(full_name, "RFC.Feature.PrivacyProtection"))
        return ADVSEC_NAMESPACE_RFC_PRIVACY_PROTECTION;
    if (strstr(full_name, "RFC.Feature.DeviceFingerPrintICMPv6"))
        return ADVSEC_NAMESPACE_RFC_DEVICE_FINGERPRINT_ICMPV6;
    if (strstr(full_name, "RFC.Feature.WS-Discovery_Analysis"))
        return ADVSEC_NAMESPACE_RFC_WS_DISCOVERY_ANALYSIS;
    if (strstr(full_name, "RFC.Feature.AdvancedSecurityOTM"))
        return ADVSEC_NAMESPACE_RFC_ADVANCED_SECURITY_OTM;
    if (strstr(full_name, "RFC.Feature.AdvanceSecurityUserSpace"))
        return ADVSEC_NAMESPACE_RFC_ADVANCED_SECURITY_USERSPACE;
    if (strstr(full_name, "RFC.Feature.AdvanceSecurityCujoTracer"))
        return ADVSEC_NAMESPACE_RFC_ADVANCED_SECURITY_CUJOTRACER;
    if (strstr(full_name, "RFC.Feature.AdvanceSecurityCujoTelemetry"))
        return ADVSEC_NAMESPACE_RFC_ADVANCED_SECURITY_CUJOTELEMETRY;
    if (strstr(full_name, "RFC.Feature.AdvSecSentryAtTheEdge"))
        return ADVSEC_NAMESPACE_RFC_ADVSEC_SENTRY_AT_THE_EDGE;
    if (strstr(full_name, "RFC.Feature.AdvSecTCPTrackerFilterDevices"))
        return ADVSEC_NAMESPACE_RFC_ADVSEC_TCP_TRACKER_FILTER_DEVICES;
    if (strstr(full_name, "RFC.Feature.WifiDataCollection"))
        return ADVSEC_NAMESPACE_RFC_WIFI_DATA_COLLECTION;
    if (strstr(full_name, "RFC.Feature.Levl"))
        return ADVSEC_NAMESPACE_RFC_LEVL;
    if (strstr(full_name, "RFC.Feature.AdvSecAgent"))
        return ADVSEC_NAMESPACE_RFC_ADVSEC_AGENT;
    if (strstr(full_name, "RFC.Feature.AdvSecSafeBrowsing"))
        return ADVSEC_NAMESPACE_RFC_ADVSEC_SAFEBROWSING;
    if (strstr(full_name, "RFC.Feature.AdvSecCujoTelemetryWiFiFP"))
        return ADVSEC_NAMESPACE_RFC_ADVSEC_CUJOTELEMETRY_WIFIFP;
    if (strstr(full_name, "RFC.Feature.AdvSecAgentRaptR"))
        return ADVSEC_NAMESPACE_RFC_ADVSEC_AGENT_RAPTR;
    
    return ADVSEC_NAMESPACE_UNKNOWN;
}

static advsec_param_metadata_t* advsec_meta_add(const char* full_name, rbusValueType_t type, bool writable)
{
    if(!full_name) return NULL;
    
    advsec_param_meta_node_t* n = (advsec_param_meta_node_t*)calloc(1, sizeof(*n));
    if(!n) return NULL;
    
    n->meta.full_name = strdup(full_name);
    if(!n->meta.full_name) {
        free(n);
        return NULL;
    }
    
    const char* last_dot = strrchr(full_name, '.');
    n->meta.short_name = last_dot ? strdup(last_dot + 1) : strdup(full_name);
    
    if (last_dot) {
        size_t parent_len = last_dot - full_name;
        n->meta.parent_namespace = strndup(full_name, parent_len);
    } else {
        n->meta.parent_namespace = strdup("");
    }
    
    n->meta.namespace_type = classify_namespace(full_name);
    n->meta.type = type;
    n->meta.writable = writable;
    n->next = g_meta_head;
    g_meta_head = n;
    return &n->meta;
}

advsec_param_metadata_t* advsec_find_param_metadata(const char* full_name)
{
    if(!full_name) return NULL;
    for(advsec_param_meta_node_t* n = g_meta_head; n; n = n->next) {
        if(strcmp(n->meta.full_name, full_name) == 0) return &n->meta;
    }
    return NULL;
}

void advsec_free_param_metadata(void)
{
    advsec_param_meta_node_t* n = g_meta_head;
    while(n) {
        advsec_param_meta_node_t* next = n->next;
        free(n->meta.full_name);
        free(n->meta.short_name);
        free(n->meta.parent_namespace);
        free(n);
        n = next;
    }
    g_meta_head = NULL;
}

static char **g_registered_names = NULL;
static size_t g_registered_names_count = 0;

static const char* advsec_store_registered_name(const char *param_name)
{
    if (!param_name) return NULL;

    char *heap_copy = strdup(param_name);
    if (!heap_copy) {
        fprintf(stderr, "ERROR: strdup() failed for %s\n", param_name);
        return NULL;
    }

    char **tmp = realloc(g_registered_names,
                         (g_registered_names_count + 1) * sizeof(char*));
    if (!tmp) {
        free(heap_copy);
        fprintf(stderr, "ERROR: realloc() failed for %s\n", param_name);
        return NULL;
    }

    g_registered_names = tmp;
    g_registered_names[g_registered_names_count++] = heap_copy;
    return heap_copy;
}

void advsec_free_registered_elements(void)
{
    for (size_t i = 0; i < g_registered_names_count; i++) {
        free(g_registered_names[i]);
    }
    free(g_registered_names);
    g_registered_names = NULL;
    g_registered_names_count = 0;
    fprintf(stderr, "Freed all registered RBUS element names\n");
}

static rbusValueType_t get_rbus_type_from_string(const char *type_str)
{
    if (!type_str) {
        return RBUS_NONE;
    }

    if (strcmp(type_str, "boolean") == 0) {
        return RBUS_BOOLEAN;
    } else if (strcmp(type_str, "uint32_t") == 0) {
        return RBUS_UINT32;
    } else if (strcmp(type_str, "string") == 0) {
        return RBUS_STRING;
    }

    return RBUS_NONE;
}

static int register_parameter(rbusHandle_t handle, const char *param_name, rbusValueType_t type, bool writable,
                              advsec_param_metadata_t* meta)
{
    (void)type;
    (void)meta;
    
    rbusDataElement_t dataElement;
    memset(&dataElement, 0, sizeof(dataElement));

    dataElement.name = (char *)param_name;
    dataElement.type = RBUS_ELEMENT_TYPE_PROPERTY;
    
    dataElement.cbTable.getHandler = advsec_rbus_get_handler;
    dataElement.cbTable.setHandler = writable ? advsec_rbus_set_handler : NULL;

    fprintf(stderr, "Registering: %s (writable=%d)\n", param_name, writable);

    rbusError_t rc = rbus_regDataElements(handle, 1, &dataElement);
    if (rc != RBUS_ERROR_SUCCESS) {
        fprintf(stderr, "Failed to register %s: %s\n", param_name, rbusError_ToString(rc));
        return -1;
    }

    return 0;
}

static int process_list_of_def(rbusHandle_t handle, cJSON *list_of_def, const char *parent_path, cJSON *definitions)
{
    UNREFERENCED_PARAMETER(definitions);  /* Parameter not used in current implementation */
    
    if (!cJSON_IsArray(list_of_def)) {
        fprintf(stderr, "List_Of_Def is not an array for %s\n", parent_path);
        return -1;
    }

    int array_size = cJSON_GetArraySize(list_of_def);
    for (int i = 0; i < array_size; i++) {
        cJSON *param_obj = cJSON_GetArrayItem(list_of_def, i);
        if (!param_obj) continue;

        cJSON *param = param_obj->child;
        if (!param || !param->string) continue;

        char full_param_name[MAX_PARAM_NAME_LEN];
        snprintf(full_param_name, sizeof(full_param_name), "%s.%s", parent_path, param->string);

        cJSON *type_obj = cJSON_GetObjectItem(param, "type");
        cJSON *writable_obj = cJSON_GetObjectItem(param, "writable");

        if (!type_obj || !cJSON_IsString(type_obj)) {
            fprintf(stderr, "Missing or invalid type for %s\n", full_param_name);
            continue;
        }

        rbusValueType_t rbus_type = get_rbus_type_from_string(type_obj->valuestring);
        bool writable = writable_obj && cJSON_IsTrue(writable_obj);

        const char *stable_name = advsec_store_registered_name(full_param_name);
        if (!stable_name) {
            fprintf(stderr, "ERROR: Failed to allocate stable name for %s\n", full_param_name);
            continue;
        }

        advsec_param_metadata_t* meta = advsec_meta_add(stable_name, rbus_type, writable);
        if(!meta) {
            fprintf(stderr, "ERROR: Failed to allocate metadata for %s\n", stable_name);
            continue;
        }

        if (register_parameter(handle, stable_name, rbus_type, writable, meta) != 0) {
            fprintf(stderr, "WARNING: Failed to register %s\n", full_param_name);
        }
    }

    return 0;
}

static void process_object_recursive(rbusHandle_t handle, cJSON *obj, const char *path, cJSON *definitions)
{
    if (!obj || !cJSON_IsObject(obj)) {
        return;
    }

    cJSON *child = obj->child;
    while (child) {
        if (strcmp(child->string, "List_Of_Def") == 0) {
            process_list_of_def(handle, child, path, definitions);
        } else if (cJSON_IsObject(child)) {
            char new_path[MAX_PARAM_NAME_LEN];
            snprintf(new_path, sizeof(new_path), "%s.%s", path, child->string);
            process_object_recursive(handle, child, new_path, definitions);
        }
        child = child->next;
    }
}

int advsec_decode_json_config(rbusHandle_t handle, const char *json_file_path)
{
    FILE *file = fopen(json_file_path, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open JSON config file: %s\n", json_file_path);
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    if (file_size < 0) {
        fprintf(stderr, "Error: Failed to get file size\n");
        fclose(file);
        return -1;
    }
    fseek(file, 0, SEEK_SET);

    char *json_buffer = (char *)malloc(file_size + 1);
    if (!json_buffer) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(file);
        return -1;
    }

    size_t bytes_read = fread(json_buffer, 1, file_size, file);
    fclose(file);

    if ((long)bytes_read != file_size) {
        fprintf(stderr, "Error: Failed to read complete file\n");
        free(json_buffer);
        return -1;
    }

    json_buffer[file_size] = '\0';

    cJSON *root = cJSON_Parse(json_buffer);
    if (!root) {
        const char *error_ptr = cJSON_GetErrorPtr();
        fprintf(stderr, "Error: JSON parse failed: %s\n", error_ptr ? error_ptr : "unknown");
        free(json_buffer);
        return -1;
    }

    fprintf(stderr, "Successfully parsed JSON config file: %s\n", json_file_path);

    /* Get definitions section */
    cJSON *definitions = cJSON_GetObjectItem(root, "definitions");
    
    /* Get Device.DeviceInfo section */
    cJSON *device = cJSON_GetObjectItem(root, "Device");
    if (device) {
        cJSON *device_info = cJSON_GetObjectItem(device, "DeviceInfo");
        if (device_info) {
            process_object_recursive(handle, device_info, "Device.DeviceInfo", definitions);
        }
    }

    cJSON_Delete(root);
    free(json_buffer);

    fprintf(stderr, "Advanced Security JSON config processing complete (%zu parameters registered)\n", g_registered_names_count);
    return 0;
}
