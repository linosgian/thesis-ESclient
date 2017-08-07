#!/bin/bash

# Runs the event processing script every 2 hours for a list of services

services=( "sshd" )
current_dir="$(dirname -- "$(readlink -f -- "$0")")"
parent_dir="$(dirname $current_dir)"
python="$(which python3.5)"
date="$(date --utc +%Y.%m.%d)"

processing_interval=2 # Change this to define the processing interval. Be sure to change the cronjob timer too

for service in "${services[@]}"
do
	command="$python $parent_dir/run.py -s $service -i $DISTRICT-logstash-$date -gt "$processing_interval"h --debug_off"
	echo "$command"
done
