#!/bin/bash

# 0: backup data from botpot to jump server
# 1: relay from jump server to kaka server
direction=0
log_file="backup.log"
source_dir="/home/crow/PycharmProjects/bot-tracker/tracker/log"
remote_user="cw486"
key_path="./id_ed25519"
jump_server="linux-labs.cms.waikato.ac.nz"
jump_server_dir="/home/cw486/temp/relay"
data_server="kaka.cms.waikato.ac.nz"
data_server_dir="/Data/scratch/cw486/dataset/V3"

log_msg(){
  local msg=$1
  echo "$msg"
  #echo "$msg" >> $log_file
}

upload_file() {
  local file=$1
  local dst_file=$2
  local remote_host=$3
  local remote_dir=$4

  log_msg "Uploading $(basename "$file") -> ${dst_file}..."
  scp -i "$key_path" "$file" "$remote_user@$remote_host:$remote_dir/$dst_file"
  if [ $? -eq 0 ]; then
    log_msg "Successfully uploaded $(basename "$file")"
    rm "$file"
    return 0
  else
    log_msg "Failed to upload $(basename "$file")"
    return 1
  fi
}

check_next_file_exist() {
  folder_path=$1
  current_file=$2

  # e.g., capture_00001_20240915162607.pcap on botpot
  # or 2024_04_01_00_00_00_test_bot1-2024_09_15_16_26_06-capture_00001_20240915162607.pcap on jump server
  prefix=$(echo "$current_file" | sed -E 's/(capture_[0-9]{5}).*//')
  current_number=$(echo "$current_file" | grep -oP '(?<=capture_)\d{5}')
  next_number=$(printf "%05d" $((10#$current_number + 1)))
  next_file_pattern="${prefix}capture_${next_number}"

  if ls "$folder_path" | grep -q "$next_file_pattern"; then
      echo 0
  else
      echo 1
  fi
}

upload_to_jump_server() {
  for bot in "$source_dir"/*; do
    if [ ! -d "$bot" ]; then
      continue
    fi
    log_msg "bot: $bot"
    m_f="${bot}/measurements.csv"

    for m in "$bot"/*; do
      if [ ! -d "$m" ]; then
        continue
      fi
      m_done=1
      if [ -f "$m_f" ]; then
        date_str=$(basename "$m")
        date_str=$(echo "${date_str}" | sed 's/_/-/g')
        formatted_date="${date_str:0:10} ${date_str:11:2}:${date_str:14:2}:${date_str:17:2}"
        if grep -q "$formatted_date" "$m_f"; then
          m_done=0
        fi
      fi
      log_msg "measurement: ${m}, m_done: ${m_done}"

      for file in "$m"/*; do
        if [ -f "$file" ]; then
          current_file=$(basename "$file")
          if [[ $current_file != capture* ]]; then
            continue
          fi
          m_next=$(check_next_file_exist "$m" "$current_file")
          if [ "$m_next" -eq 0 ] || [ "$m_done" -eq 0 ]; then
            dst_file=$(basename "$bot")-$(basename "$m")-${current_file}
            upload_file "$file" "$dst_file" "$jump_server" "$jump_server_dir"
	    if [ $? -ne 0 ]; then
	      log_msg "upload file failed."
	      break
	    fi
            if [ "$m_next" -ne 0 ]; then
              # mark finished file upload
              echo "done" > "${file}.done"
              upload_file "${file}.done" "${dst_file}.done" "$jump_server" "$jump_server_dir"
            fi
          fi
        fi
      done
    done
  done
}

upload_to_data_server() {
  for file in "$jump_server_dir"/*; do
    if [ -f "$file" ]; then
      current_file=$(basename "$file")
      if [[ $current_file != *capture* ]]; then
        continue
      fi
      log_msg "file: $file"
      m_next=$(check_next_file_exist "$jump_server_dir" "$current_file")
      if [ "$m_next" -eq 0 ] || [ -f "${file}.done" ]; then
        dst_file=$current_file
        upload_file "$file" "$dst_file" "$data_server" "$data_server_dir"
	if [ $? -ne 0 ]; then
	  log_msg "upload file failed."
	  break
	fi
        # last file has been uploaded, remove the mark file
        if [ "$m_next" -eq 0 ]; then
          rm "${file}.done"
        fi
      fi
    fi
  done
}

if [ "$direction" -eq 0 ]; then
  log_msg "Start migrating pcap files to jump server..."
  while true; do
    upload_to_jump_server
    sleep 30
  done
fi

if [ "$direction" -eq 1 ]; then
  log_msg "Start relaying pcap files to data server..."
  while true; do
    upload_to_data_server
    sleep 30
  done
fi
