#!/bin/bash

for dir in */ ; do
    if [ -d "$dir" ]; then
        case "$dir" in
            "DUP/"|"ERROR/"|"V1/"|"UNSTAGED/")
                echo "Skipping directory: $dir"
                continue
                ;;
        esac

        echo "Processing directory: $dir"
        new_folder="${dir%/}/2024-07-14-09-27-03_2024-07-14-14-48-51"
	
	if [ -d "$new_folder" ]; then
            echo "Directory $new_folder already exists. Skipping."
            continue
        fi

        mkdir -p "$new_folder"
        
        mv "$dir"/*.csv "$new_folder" 2>/dev/null
        mv "$dir"/*.pcap "$new_folder" 2>/dev/null
        echo "Moved CSV and PCAP files to: $new_folder"
    fi
done
