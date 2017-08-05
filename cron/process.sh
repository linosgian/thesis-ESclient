#!/bin/bash

# Runs the event processing script every 2 hours for a list of services

services=( "sshd" )
current_dir="$(dirname -- "$(readlink -f -- "$0")")"
parent_dir="$(dirname $current_dir)"
python="$(which python3.5)"

for service in "${services[@]}"
do
	$python run.py 
done
