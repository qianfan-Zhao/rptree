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

function fork_dep1() {
    (
        echo "$@"
    )
}

function fork_dep2() {
    (
        fork_dep1 "$@"
    )
}

function fork_dep3() {
    (
        fork_dep2 "$@"
    )
}

function fork_dep4() {
    (
        fork_dep3 "$@"
    )
}

echo "script running in $0"
echo "timestamp: " "$(get_timestamp)"
echo "timestamp with zone: " "$(get_timestamp_zone)"
echo "fork_dep4:" "$(fork_dep4 abcd)"

NEXT_SCRIPT=2.sh
bash -c ${self_path}/${NEXT_SCRIPT}
