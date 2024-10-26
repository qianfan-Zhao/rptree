#!/bin/sh

/usr/bin/echo 'hello world' | tr ' ' ':' | awk -F':' '{print $2}'
/usr/bin/echo "not piped"
