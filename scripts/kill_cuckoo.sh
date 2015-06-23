#!/bin/bash
# ------------------------------------------------------------------
# [Author] Hialo Muniz, Vinicius Franco
#  Description:
#
#		   This script checks if there's any cuckoo scripts running in
#		   the machine, and kills if it founds one.
#
# Dependency:
# ------------------------------------------------------------------
CUCKOO=cuckoo.py

if ps ax | grep -i $CUCKOO | grep -v grep > /dev/null; then
	PID=$(pgrep python)
 	echo "An instance of cuckoo was found (PID "$PID"). Killing..."
 	kill -9 $PID
 else
 	echo "Instance not found."
 fi