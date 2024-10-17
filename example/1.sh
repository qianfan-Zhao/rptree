#!/bin/sh

self_path=$(dirname "$(readlink -f "$0")")

export SELF="$0"
export GLOBAL_ENV="env1"

function get_timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

/usr/bin/echo "script running in $0"
/usr/bin/echo "timestamp: " "$(get_timestamp)"

sleep 5
sh ${self_path}/2.sh
