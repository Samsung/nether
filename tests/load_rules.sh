#!/bin/bash

if [ "$1" == "" ]; then
	echo "$0 <rules>"
	exit 1
fi

echo "Loading rules"
cat $1 | grep --line-buffered "" > /sys/fs/smackfs/load2
