#!/data/data/com.termux/files/usr/bin/bash

STATUS_CHECK_INTERVAL=1
STATUS_URL="http://192.168.3.85/status"

SCREEN_UNLOCK_WAIT_TIME=0.5
TURN_ON_WAIT_TIME=0.2
HEATER_UI_KEEP=10
power_button_pos="540 1916"
FLUSH_WAIT_TIME=10
FLUSH_INTERVAL=15

DEBUG_ECHO=1

# 调试输出
echo "STATUS_CHECK_INTERVAL: ${STATUS_CHECK_INTERVAL}"
echo "STATUS_URL: ${STATUS_URL}"

debug_echo() {
    if [ $DEBUG_ECHO -eq 1 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a /data/data/com.termux/files/home/http_base/heater_daemon.log
    fi
}

toggle_heater_run_once() {
  python heater_lan.py cycle
  sleep ${TURN_ON_WAIT_TIME}
  python heater_lan.py cycle
}

# 检查必要工具是否安装
if ! command -v curl &> /dev/null; then
    echo "请先安装curl: pkg install curl"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "请先安装jq: pkg install jq"
    exit 1
fi

# 检查STATUS_URL是否可访问,http code 200
http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 0.5 "${STATUS_URL}")
if [ $http_code -ne 200 ]; then
    echo "STATUS_URL不可访问,http code: ${http_code}"
    exit 1
fi

termux-wake-lock

# 初始化上次执行时间戳为0（单位：秒）
LAST_EXECUTED=0
last_regular_active=0
last_flush_time=0

# 主循环，每100ms检查一次状态
while true; do
    # 获取JSON数据并解析heaterActive值    
    resp=$(curl -s -m 0.5 "${STATUS_URL}")
    HEATER_ACTIVE=$(echo $resp | jq -r '.heaterActive')
    REGULAR_ACTIVE=$(echo $resp | jq -r '.USER_2')

    should_execute=$HEATER_ACTIVE
    if (( REGULAR_ACTIVE == 1 )); then
        today=$(date +%d)
        if [ $today -ne $last_regular_active ]; then
            last_regular_active=$today
            should_execute=$((should_execute + 1))
        fi
    fi 

    debug_echo "heaterActive: ${HEATER_ACTIVE}, regularActive: ${REGULAR_ACTIVE}, should_execute: ${should_execute}"

    # 当heaterActive为1时执行操作
    if (( should_execute > 0 )); then
        # 获取当前时间戳（单位：秒）
        CURRENT_TIME=$(date +%s)
        # 计算与上次执行的时间差（秒）
        TIME_DIFF=$((CURRENT_TIME - LAST_EXECUTED))
        debug_echo "TIME_DIFF: ${TIME_DIFF}"

        # 只有当时间差大于30秒时才执行操作
        if [ $TIME_DIFF -gt 30 ]; then
            toggle_heater_run_once

            # 更新上次执行时间戳为当前时间
            LAST_EXECUTED=$CURRENT_TIME
        fi
    fi

    # 等待STATUS_CHECK_INTERVAL秒后再次检查状态
    sleep "${STATUS_CHECK_INTERVAL}"
done

termux-wake-unlock

