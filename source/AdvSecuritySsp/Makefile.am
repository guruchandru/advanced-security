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
#AM_LDFLAGS = -lccsp_common -ldl -lwebconfig_framework
AM_LDFLAGS = -ldl -lwebconfig_framework -lrbus

if CCSP_ARCH_ARM
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_
endif

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

bin_PROGRAMS = CcspAdvSecuritySsp
CcspAdvSecuritySsp_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/source/AdvSecurityDml -I$(top_srcdir)/source/AdvSecuritySsp $(CPPFLAGS) -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/cjson
CcspAdvSecuritySsp_SOURCES = ssp_messagebus_interface.c ssp_main.c ssp_action.c ssp_messagebus_interface_priv.c
# ccsp_common removed: replaced by RBUS/JSON config auto-registration
#CcspAdvSecuritySsp_LDFLAGS = -lccsp_common -ldl -lsyscfg -rdynamic -lwebconfig_framework $(SSP_LDFLAGS)
CcspAdvSecuritySsp_LDFLAGS = -ldl -rdynamic -lwebconfig_framework -lrbus -lcjson $(SSP_LDFLAGS)
