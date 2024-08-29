#!/bin/bash
while true; do
   top -b -n 1 >> ./top_output.txt
   sleep 5
done

