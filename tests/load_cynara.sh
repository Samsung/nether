#!/bin/bash

if [ "$1" == "" ] || [ "$2" == "" ]; then
	echo "$0 <labels> <bucket>"
	exit 1
fi

for i in `cat $1`; do
	echo "remove $i"
	cyad -e $2 -r no -c $i -u 0 -p http://tizen.org/privilege/internet
	echo "add $1"
	cyad -s $2 -c $i -u 0 -p http://tizen.org/privilege/internet -t allow
done
