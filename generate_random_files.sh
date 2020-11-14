#!/bin/sh
RANDOM_PREFIX=rndfile
UNIT=M

for i in [ 1 2 4 8 16 32 64 128 256 512 1024 2048 4096 ];
do
	dd if=/dev/urandom of=${RANDOM_PREFIX}_${i}${UNIT} bs=1${UNIT} count=${i}
done
