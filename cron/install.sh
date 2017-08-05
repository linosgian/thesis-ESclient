#!/bin/bash
# Installs two cronjobs
current_dir="$(dirname -- "$(readlink -f -- "$0")")"
if ! [[ -x "$current_dir/process.sh" ]] 
then
	echo "Please set the executable bit for process.sh"
	exit
fi
decay_rep_job="0 1 * * * /usr/bin/curl \"localhost:5000/decay_rep\" --silent --output /dev/null"
event_processing_job="0 */2 * * * $current_dir/process.sh"
(crontab -l 2>/dev/null; echo "$event_processing_job"; echo "$decay_rep_job") | crontab -
