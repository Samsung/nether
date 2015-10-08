#!/bin/bash

if [ "$1" == "" ]; then
	echo "$0 <labels>"
	exit 1
fi

for i in `cat $1`; do
	echo "MANIFESTS;$i;0;http://tizen.org/privilege/internet;65535;"
done
