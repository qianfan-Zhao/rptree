#!/bin/bash
enable -n echo

function get_timestamp() {
    date '+%Y-%m-%d %H:%M:%S' | tr ' ' 'T'
}

echo "script running in $0, global env is: \"${GLOBAL_ENV}\""
echo "timestamp: $(get_timestamp)"
