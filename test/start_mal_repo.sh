#!/bin/bash

VM_NAME="REMnux"

while true; do
  RUNNING_VM=$(VBoxManage list runningvms | grep "$VM_NAME")
  if [ -z "$RUNNING_VM" ]; then
    echo "$VM_NAME is not running, start it..."
    VBoxManage startvm "$VM_NAME" --type headless
    if [ $? -eq 0 ]; then
      echo "$VM_NAME started"
    else
      echo "$VM_NAME start failed"
    fi
  fi
  sleep 5
done

