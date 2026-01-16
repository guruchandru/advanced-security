##########################################################################
#
# Copyright 2016 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# SPDX-License-Identifier: Apache-2.0
##########################################################################
AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
# Legacy DML and common-library lines commented out for JSON-driven RBUS approach
#AM_LDFLAGS = -lccsp_common -lsysevent -lwebconfig_framework -lmsgpackc -ltrower-base64
AM_LDFLAGS = -lsysevent -lwebconfig_framework -lmsgpackc -ltrower-base64 -lrbus

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

lib_LTLIBRARIES = libdmlasecurity.la
libdmlasecurity_la_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/source/AdvSecurityDml -I$(top_srcdir)/source/AdvSecuritySsp $(CPPFLAGS) -I$(top_srcdir)/../Utopia/source/include/sysevent -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/cjson
libdmlasecurity_la_SOURCES = plugin_main.c cosa_adv_security_internal.c cosa_adv_security_dml.c cosa_adv_security_webconfig.c advsecurity_helpers.c advsecurity_param.c advsec_bus_json_decode.c advsec_rbus_handlers.c
# Legacy ccsp_common lines commented out for JSON-driven RBUS approach
#libdmlasecurity_la_LDFLAGS = -lccsp_common -lsyscfg -lsysevent -lwebconfig_framework -lmsgpackc -ltrower-base64 -lsecure_wrapper -lrbus $(SSP_LDFLAGS)
libdmlasecurity_la_LDFLAGS = -lsyscfg -lsysevent -lwebconfig_framework -lmsgpackc -ltrower-base64 -lsecure_wrapper -lrbus -lcjson $(SSP_LDFLAGS)

if WIFI_DATA_COLLECTION
libdmlasecurity_la_CPPFLAGS += -DDML_SUPPORT -DNON_PRIVILEGED -DWIFI_DATA_COLLECTION
libdmlasecurity_la_SOURCES += cujoagent_dcl_api.c
libdmlasecurity_la_LDFLAGS += -lwifi_webconfig
endif
