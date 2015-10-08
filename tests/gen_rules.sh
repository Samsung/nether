#!/bin/bash

if [ "$1" == "" ]; then
	echo "$0 <labels>"
	exit 1
fi

for i in `cat $1`; do
	cat rules_template.txt | sed 's/APP_ID/'$i'/g'
done