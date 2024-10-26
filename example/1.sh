#!/bin/bash

enable -n echo

export GLOBAL_ENV="env1"
self_path=$(dirname "$(readlink -f "$0")")

function get_timestamp() {
    date '+%Y-%m-%d %H:%M:%S' | tr ' ' 'T'
}

function get_timestamp_zone() {
    local ts=$(get_timestamp)

    echo "${ts}$(date '+%z')"
}

echo "script running in $0"
echo "timestamp: " "$(get_timestamp)"
echo "timestamp with zone: " "$(get_timestamp_zone)"
sh ${self_path}/2.sh
