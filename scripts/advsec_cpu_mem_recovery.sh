#!/bin/sh
##########################################################################
#
# Copyright 2018 Comcast Cable Communications Management, LLC
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
#Inputs: sampling time in seconds, max cpu threshold in %, max rss threshold in kb

source $(dirname $(realpath ${0}))/advsec.sh

bridge_mode=`syscfg get bridge_mode`
if [ "${bridge_mode}" = "2" ]; then
        #Advsec Agent doesn't run in Bridge mode.
        exit 0
fi

KB=1024
SAMPLING_TIME=10
MAX_CPU_THRESHOLD=45
AGENT_PS_COUNT_THRESHOLD=3

# soft and hard limits are in MB
MAX_MEM_FIRST_SOFT_LIMIT=40
MAX_MEM_SECOND_SOFT_LIMIT=45
MAX_MEM_HARD_LIMIT=50

#syscfg contains value in MB.
max_rss=`syscfg get Advsecurity_RabidMemoryLimit`
if [ "$max_rss" != "" ]; then
    MAX_MEM_HARD_LIMIT=$max_rss
fi

MIN_RSS_FIRST_THRESHOLD=$(($MAX_MEM_FIRST_SOFT_LIMIT * $KB)) #kb
MIN_RSS_SECOND_THRESHOLD=$(($MAX_MEM_SECOND_SOFT_LIMIT * $KB)) #kb
MAX_RSS_THRESHOLD=$(($MAX_MEM_HARD_LIMIT * $KB)) #kb
LOWFREE_MEM_THRESHOLD=$((10 * $KB))

if [ "$1" != "" ]; then
	SAMPLING_TIME=$1
fi

if [ "$2" != "" ]; then
	MAX_CPU_THRESHOLD=$2
fi

if [ "$3" != "" ]; then
        MAX_RSS_THRESHOLD=$3
fi

get_agent_pid_list()
{
	AGENT_PROC=${CUJO_AGENT}
	for agent in ${AGENT_PROC}; do
		PID=`pidof $agent`
		if [ "$PID" != "" ]; then
			PID_LIST="$PID_LIST $PID"
		fi
	done
}

get_agent_cpu_time_spent()
{
#14 utime - CPU time spent in user code, measured in clock ticks
#15 stime - CPU time spent in kernel code, measured in clock ticks
	total_time=0
	for pid in ${PID_LIST}; do
		sfile=/proc/$pid/stat
		if [ -e $sfile ]; then
			utime=`cat $sfile| awk '{print $14}'`
			ctime=`cat $sfile| awk '{print $15}'`
			total_time=`expr $total_time + $utime + $ctime`
		fi
	done
	echo "$total_time"
}

get_total_cpu_usage()
{
#2 user: normal processes executing in user mode
#3 nice: niced processes executing in user mode
#4 system: processes executing in kernel mode
#5 idle: twiddling thumbs
#6 iowait: In a word, iowait stands for waiting for I/O to complete. 
#7 irq: servicing interrupts
#8 softirq: servicing softirqs
#9 steal: involuntary wait
#10 guest: running a normal guest
	total_cpu_usage=`grep '^cpu ' /proc/stat | awk '{sum=$2+$3+$4+$5+$6+$7+$8+$9+$10; print sum}'`
	echo "$total_cpu_usage"
}

log_agent_cpu_statistics()
{
	#Log all agent processes cpu stats before clearing them.
	agent_cpu_stats=`top -bn1 | grep -e ${CUJO_AGENT} | grep -v grep`
	echo "####Advsec Agent CPU stats####" >> $ADVSEC_AGENT_LOG_PATH
	echo_t "$agent_cpu_stats" >> $ADVSEC_AGENT_LOG_PATH
	echo "##############################" >> $ADVSEC_AGENT_LOG_PATH
}

advsec_agent_multiple_processes_recovery()
{
    AGENT_PS_COUNT=$(echo "$PID_LIST" | wc -w)
    if [ "$AGENT_PS_COUNT" -gt "$AGENT_PS_COUNT_THRESHOLD" ]; then
        echo_t "Advsec Agent multiple processes detected, count=$AGENT_PS_COUNT" >> $ADVSEC_AGENT_LOG_PATH
        advsec_restart_agent "MultipleProcesses"
        exit
    fi
}

log_agent_mem_statistics()
{
	echo "####Advsec Agent RSS MEM stats####" >> $ADVSEC_AGENT_LOG_PATH
	total_rss_mem=0
	for pid in ${PID_LIST}; do
		sfile=/proc/$pid/status
		proc_name=`cat /proc/$pid/cmdline`
		if [ -e $sfile ]; then
                        rss=`cat $sfile | grep VmRSS | awk '{print $2}'`
			echo_t "$pid:$proc_name : $rss kb" >> $ADVSEC_AGENT_LOG_PATH
                        total_rss_mem=`expr $total_rss_mem + $rss`
		fi
        done
        echo_t "ADVSEC_PROCESS_TOTAL_RSS_MEM:$total_rss_mem" >> $ADVSEC_AGENT_LOG_PATH
	echo "######################################################" >> $ADVSEC_AGENT_LOG_PATH

	if [ "$total_rss_mem" -ge "$MAX_RSS_THRESHOLD" ]; then
                echo_t "Warning !!! Reached hard limit of $MAX_MEM_HARD_LIMIT MB, current memory:$total_rss_mem which is HighRSS Memory, restarting $CUJO_AGENT" >> $ADVSEC_AGENT_LOG_PATH
		advsec_restart_agent "HighRSS"
		exit
	elif [ "$total_rss_mem" -ge "$MIN_RSS_SECOND_THRESHOLD" ]; then
                echo_t "Warning !!! Reached Soft limit of $MAX_MEM_SECOND_SOFT_LIMIT MB, current memory:$total_rss_mem" >> $ADVSEC_AGENT_LOG_PATH
	elif [ "$total_rss_mem" -ge "$MIN_RSS_FIRST_THRESHOLD" ]; then
                echo_t "Warning !!! Reached Soft limit of $MAX_MEM_FIRST_SOFT_LIMIT MB, current memory:$total_rss_mem" >> $ADVSEC_AGENT_LOG_PATH
        fi

	if [ "$BOX_TYPE" = "XF3" ]; then
		lowfree_mem=`cat /proc/meminfo | grep -i lowfree | awk '{ print $2 }'`
		if [ $lowfree_mem -le $LOWFREE_MEM_THRESHOLD ]; then
			echo_t "ADVSEC Lowfree Memory threshold recovery" >> $ADVSEC_AGENT_LOG_PATH
			advsec_restart_agent "LowFreeMem"
			exit
		fi
	fi

	if [ ! -e ${ADVSEC_USERSPACE_ENABLED_PATH} ]; then
		tracer_interval=`${RUNTIME_DIR}/bin/${CUJO_AGENT_SH} -e 'return cujo.config.tracer_interval'`
		if [ "x${tracer_interval}" = "x" ]; then
			${RUNTIME_DIR}/bin/${CUJO_AGENT_SH} -e 'cujo.nf.dostring([[print("nfluamem:"..collectgarbage("count"))]])'
			nflua_rss=`dmesg | grep nfluamem: | tail -1 | cut -d':' -f2`
			if [ "${nflua_rss}" = "" ]; then
				nflua_rss=0
			fi
			# nflua_rss is in bytes
			nflua_rss=$((${nflua_rss} / $KB))
			echo_t "NFLua memory usage:${nflua_rss}" >> $ADVSEC_AGENT_LOG_PATH

			if [ "${nflua_rss}" -ge "${MAX_RSS_THRESHOLD}" ]; then
				advsec_restart_agent "NfluaHighRSS"
				exit
			fi
		fi
	fi
}

get_agent_pid_list

if [ "${PID_LIST}" = "" ]; then
	if [ -f $ADVSEC_INITIALIZING ]; then
		advsec_wait_for_agent
		if [ ${EXIT_STATUS} -ne 0 ]; then
			echo_t "$CUJO_AGENT_LOG process is not running" >> $ADVSEC_AGENT_LOG_PATH
			rm $ADVSEC_INITIALIZING
			exit 0
		fi
		# advsec agent is up after waiting
		if [ -f $ADVSEC_INITIALIZING ]; then
			rm $ADVSEC_INITIALIZING
		fi
		get_agent_pid_list
	else
		# advsec agent got crashed
		echo_t "$CUJO_AGENT_LOG process is not running" >> $ADVSEC_AGENT_LOG_PATH
		exit 0
	fi
else
	# remove ADVSEC_INITIALIZING file if advsec agent PID is alive
	if [ -f $ADVSEC_INITIALIZING ]; then
		advsec_wait_for_agent
		if [ -f $ADVSEC_INITIALIZING ]; then
			rm $ADVSEC_INITIALIZING
		fi
	fi
fi

advsec_agent_multiple_processes_recovery

log_agent_mem_statistics

total_cpu_time_before=$( get_agent_cpu_time_spent )
total_cpu_usage_before=$( get_total_cpu_usage )

sleep $SAMPLING_TIME

total_cpu_time_after=$( get_agent_cpu_time_spent )
total_cpu_usage_after=$( get_total_cpu_usage )

cpu_time_diff=`expr $total_cpu_time_after - $total_cpu_time_before`
cpu_usage_diff=`expr $total_cpu_usage_after - $total_cpu_usage_before`

CPU=`expr $cpu_time_diff \* 100 / $cpu_usage_diff`

echo_t "Advsec total_CPU_usage=$CPU %" >> $ADVSEC_AGENT_LOG_PATH

