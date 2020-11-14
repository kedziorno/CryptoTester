#!/bin/sh

NO_TESTS=5
OUTPUT_FILE=get-hashes.log
for i in 1 2 4 8 16 32 64 128 256 512 1024 2048;
do
	./get-hashes rndfile_${i} ${NO_TESTS} 2>&1 | tee -a ${OUTPUT_FILE}
done
