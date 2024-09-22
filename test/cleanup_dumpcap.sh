#!/bin/bash

cleanup_dumpcap() {
	ps -ef | grep dumpcap | grep -v grep | while read -r line; do
		pid=$(echo $line | awk '{print $2}')
		filepath=$(echo $line | grep -oP '(?<=-w\s)\S+')

		if [ -z "$filepath" ]; then
			continue
		fi

		echo "PID: $pid"
		echo "File Path: $filepath"

		parent_dir=$(dirname "$filepath")
		m=$(basename "$parent_dir")

		echo "Measurement name (m): $m"

		grandparent_dir=$(dirname "$parent_dir")
		echo "Bot directory: $grandparent_dir"

		measurement_file="$grandparent_dir/measurements.csv"
		if [ ! -f "$measurement_file" ]; then
			echo "measurements.csv not found in $grandparent_dir"
			continue
		fi

		date_str=$(echo "${m}" | sed 's/_/-/g')
    formatted_date="${date_str:0:10} ${date_str:11:2}:${date_str:14:2}:${date_str:17:2}"
    if grep -q "$formatted_date" "$measurement_file"; then
			echo "Found $m in $measurement_file"
			kill -9 "$pid"
			echo "Process $pid killed"
		else
			echo "$m not found in $measurement_file"
		fi
	done
}

while true; do
    cleanup_dumpcap
    sleep 30
done