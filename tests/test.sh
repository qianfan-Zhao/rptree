#!/bin/bash

TEST_NAME=$1

run_test() {
    local cases=$(find ./ -name '*.txt')

    for c in $cases ; do
        local name=$(basename "${c%.txt}")
        local arg=$(cat $c | head -1)
        local tmpdir=${CMAKE_CURRENT_BINARY_DIR}/tests/${TEST_NAME}/${name}

        if [[ "${arg}" != '-'* ]] ; then
            echo "bad case ${TEST_NAME}/${name}.json (no rptree arg found)"
            exit 1
        fi

        mkdir -p ${tmpdir}
        tail -n '+2' $c > ${tmpdir}/${name}.expect

        echo "rptree $c $arg"
        ${CMAKE_CURRENT_BINARY_DIR}/rptree ${name}.json $arg > ${tmpdir}/${name}.txt
        if [ $? -ne 0 ] ; then
            exit 1
        fi

        cmp --quiet ${tmpdir}/${name}.expect ${tmpdir}/${name}.txt
        if [ $? -ne 0 ] ; then
            exit 1
        fi
    done
}

run_test
exit 0
