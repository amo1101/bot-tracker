#!/bin/bash

source_dir="UNSTAGED"
remote_user="cw486"
remote_host="linux-labs.cms.waikato.ac.nz"
remote_dir="~/temp"
key_path="./id_ed25519"
split_size_mb=2048
split_size_bytes=$(echo "$split_size_mb * 1024 * 1024" | bc)
temp_dir="temp"

upload_file() {
    local file=$1
    echo "Uploading $(basename "$file")..."
    scp -i "$key_path" "$file" "$remote_user@$remote_host:$remote_dir/"
    if [ $? -eq 0 ]; then
        echo "Successfully uploaded $(basename "$file")"
        rm "$file"
    else
        echo "Failed to upload $(basename "$file")"
        exit 1
    fi
}

tar -czf - "$source_dir" | split -b "${split_size_mb}m" - "$temp_dir/part_" &

while true; do
    for file in "$temp_dir"/part_*; do
    	if [ -f "$file" ]; then
    	    filesize=$(stat -c %s "$file")
            if [ "$filesize" -ge "$split_size_bytes" ]; then
		upload_file "$file"
	    else
		echo "Wait file: "$file" to complete..."
		sleep 10
		break
	    fi
        else
            echo "No files found. Waiting for 5 seconds..."
            sleep 10
	    break
	fi
    done
done

echo "All files have been uploaded and processed."

