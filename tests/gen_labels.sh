#!/bin/bash

if [ "$1" == "" ]; then
	echo "$0 <how many>"
	exit 1
fi

for i in `seq 0 $1`; do
	echo "AppLabel$i"
done
