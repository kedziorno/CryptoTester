#!/bin/sh

FILE=$1
PIECES=$2
TOOL="sha256sum"

SKIP=0
BUFFERS=1
FILE_SIZE=`stat -c "%s" ${FILE}`
PIECE_SIZE=`echo "${FILE_SIZE} / ${PIECES}" | bc`
BLOCK_SIZE_MB=`echo "${BUFFERS} * 1024 * 1024" | bc`
COUNT=`echo "${PIECE_SIZE} / ${BLOCK_SIZE_MB}" | bc`

echo "FILE_SIZE       : ${FILE_SIZE}"
echo "PIECE_SIZE      : ${PIECE_SIZE}"
echo "BLOCK_SIZE_MB   : ${BLOCK_SIZE_MB}"
echo "COUNT_BLOCKSIZE : ${COUNT}"
echo

dd_sha256()
{
	local FILE=$1
	local SKIP=$2
	local COUNT=$3
	local BLOCK_SIZE_MB=$4
	local FROM_BS=$5
	local TO_BS=$6

	gawk 'BEGIN {
		cmd1 = "echo Piece from '${FROM_BS}' to '${TO_BS}'"
		cmd1 |& getline var1
		close(cmd1)
		cmd2 = "dd if='${FILE}' skip='${SKIP}' count='${COUNT}' bs='${BLOCK_SIZE_MB}' 2>&- | sha256sum"
		cmd2 |& getline var2
		close(cmd2)
		printf("%s : %s\n", var1, substr(var2, 0, length(var2)-length("  -")))
	}'
}

# https://bash.cyberciti.biz/guide/While_loop#while_loop_Example

I=0
while [ $I -lt ${PIECES} ]
do
	FROM_BS=`echo "${SKIP} * ${BLOCK_SIZE_MB}" | bc`
	TO_BS=`echo "${FROM_BS} + (${COUNT} * ${BLOCK_SIZE_MB}) - 1" | bc` #calculate from 0 to n-1
	dd_sha256 ${FILE} ${SKIP} ${COUNT} ${BLOCK_SIZE_MB} ${SHA256_TOOL} ${FROM_BS} ${TO_BS}	
	SKIP=`echo "${SKIP} + ${COUNT}" | bc`
	I=$(( I+1 ))
done

