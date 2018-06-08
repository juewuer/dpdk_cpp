#!/usr/bin/env bash
flags="
  --is_sender 0 \
	--num_threads 5
"

# Check for non-gdb mode
if [ "$#" -eq 0 ]; then
  sudo -E numactl --cpunodebind=0 --membind=0 ./example $flags
fi

# Check for gdb mode
if [ "$#" -eq 1 ]; then
  sudo -E gdb -ex run --args ./example $flags
fi
