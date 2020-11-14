#!/bin/sh

OUTPUT_FILE=crypto-tester.log.`date +"%Y%m%d_%H%M%S"`
for i in 1 2 4 8 16 32 64 128 256 512 1024 2048 4096;
do
	./crypto-tester rndfile_${i} 2>&1 | tee -a ${OUTPUT_FILE}
done
