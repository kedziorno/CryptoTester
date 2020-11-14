#!/bin/sh

FILE_NAME=$1
gawk 'BEGIN {
	print "filename,sha256,sha512,blake2b,ed25519";
	lines_sha256=0;
	lines_sha512=0;
	lines_blake2b=0;
	lines_ed25519=0;
};

/.*for sha256.*[0-9]+ ms/ {
	n = split($0,as,":");
	rec1 = as[4];
	n = split(rec1,as,",");
	rec2 = as[1];
	n = split(rec2,as," ");
	file_name = as[1];

	n = split($0,as,":");
	time_ms = as[5];
	n = split(time_ms,as," ");
	ms_time = as[1];

	sha256[lines_sha256] = ms_time;
	sha256_filename[lines_sha256] = file_name;
	++lines_sha256;
}

/.*for sha512.*[0-9]+ ms/ {
	n = split($0,as,":");
	rec1 = as[4];
	n = split(rec1,as,",");
	rec2 = as[1];
	n = split(rec2,as," ");
	file_name = as[1];

	n = split($0,as,":");
	time_ms = as[5];
	n = split(time_ms,as," ");
	ms_time = as[1];

	sha512[lines_sha512] = ms_time;
	sha512_filename[lines_sha512] = file_name;
	++lines_sha512;
}

/.*for blake2b.*[0-9]+ ms/ {
	n = split($0,as,":");
	rec1 = as[4];
	n = split(rec1,as,",");
	rec2 = as[1];
	n = split(rec2,as," ");
	file_name = as[1];

	n = split($0,as,":");
	time_ms = as[5];
	n = split(time_ms,as," ");
	ms_time = as[1];

	blake2b[lines_blake2b] = ms_time;
	blake2b_filename[lines_blake2b] = file_name;
	++lines_blake2b;
}

/.*for ed25519.*[0-9]+ ms/ {
	n = split($0,as,":");
	rec1 = as[4];
	n = split(rec1,as,",");
	rec2 = as[1];
	n = split(rec2,as," ");
	file_name = as[1];

	n = split($0,as,":");
	time_ms = as[5];
	n = split(time_ms,as," ");
	ms_time = as[1];

	ed25519[lines_ed25519] = ms_time;
	ed25519_filename[lines_ed25519] = file_name;
	++lines_ed25519;
}

END {
	for(i=0;i<lines_sha256;i++) {
		printf("%s,%d,%d,%d,%d\n",sha256_filename[i],sha256[i],sha512[i],blake2b[i],ed25519[i]);
	}
};

' ${FILE_NAME}
