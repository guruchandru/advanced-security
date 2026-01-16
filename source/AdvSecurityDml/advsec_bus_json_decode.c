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

#define JSON_CONFIG_PATH "advsec_dml_config.json"
#define MAX_PARAM_NAME_LEN 256

typedef struct {
    char param_name[MAX_PARAM_NAME_LEN];
    rbusValueType_t data_type;
    bool writable;
} advsec_param_info_t;

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

static int register_parameter(rbusHandle_t handle, const char *param_name, rbusValueType_t type, bool writable)
{
    rbusDataElement_t dataElement;

    dataElement.name = param_name;
    dataElement.type = RBUS_ELEMENT_TYPE_PROPERTY;
    dataElement.cbTable.getHandler = advsec_rbus_get_handler;
    
    if (writable) {
        dataElement.cbTable.setHandler = advsec_rbus_set_handler;
    } else {
        dataElement.cbTable.setHandler = NULL;
    }

    fprintf(stderr, "Registering parameter: %s (type=%d, writable=%d)\n", param_name, type, writable);

    rbusError_t rc = rbus_regDataElements(handle, 1, &dataElement);
    if (rc != RBUS_ERROR_SUCCESS) {
        fprintf(stderr, "Failed to register parameter %s: %d\n", param_name, rc);
        return -1;
    }

    return 0;
}

static int process_list_of_def(rbusHandle_t handle, cJSON *list_of_def, const char *parent_path, cJSON *definitions)
{
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

        register_parameter(handle, full_param_name, rbus_type, writable);
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

    fprintf(stderr, "Advanced Security JSON config processing complete\n");
    return 0;
}
