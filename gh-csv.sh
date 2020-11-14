#!/bin/sh

FILE_NAME=$1
gawk 'BEGIN {
	print "filename,sha256,sha512,blake2b,ed25519_final,ed25519_verify";
	lines_filename=0;
	lines_sha256=0;
	lines_sha512=0;
	lines_blake2b=0;
	lines_ed25519_final=0;
	lines_ed25519_verify=0;
	regexp_filename = " file : .* , number tests : [:digit:]*";
	regexp_sha256 = "avg time sha256.*:[:digit:]*";
	regexp_sha512 = "avg time sha512.*:[:digit:]*";
	regexp_blake2b = "avg time blake2b.*:[:digit:]*";
	regexp_ed25519_final = "avg time ed25519_final.*:[:digit:]*";
	regexp_ed25519_verify = "avg time ed25519_verify.*:[:digit:]*";
};

$0 ~ regexp_filename {
	n = split($0,as,":");
	rec1 = as[4];
	n = split(rec1,as,",");
	rec2 = as[1];
	n = split(rec2,as," ");
	filename[lines_filename] = as[1];
	++lines_filename;
}

$0 ~ regexp_sha256 {
	n = split($0,as,":");
	rec1 = as[4];
	n = split(rec1,as,",");
	rec2 = as[1];
	n = split(rec2,as," ");
	sha256[lines_sha256] = as[1];
	++lines_sha256;
}

$0 ~ regexp_sha512 {
	n = split($0,as,":");
	rec1 = as[4];
	n = split(rec1,as,",");
	rec2 = as[1];
	n = split(rec2,as," ");
	sha512[lines_sha512] = as[1];
	++lines_sha512;	
}

$0 ~ regexp_blake2b {
	n = split($0,as,":");
	rec1 = as[4];
	n = split(rec1,as,",");
	rec2 = as[1];
	n = split(rec2,as," ");
	blake2b[lines_blake2b] = as[1];
	++lines_blake2b;
}

$0 ~ regexp_ed25519_final {
	n = split($0,as,":");
	rec1 = as[4];
	n = split(rec1,as,",");
	rec2 = as[1];
	n = split(rec2,as," ");
	ed25519_final[lines_ed25519_final] = as[1];
	++lines_ed25519_final;
}

$0 ~ regexp_ed25519_verify {
	n = split($0,as,":");
	rec1 = as[4];
	n = split(rec1,as,",");
	rec2 = as[1];
	n = split(rec2,as," ");
	ed25519_verify[lines_ed25519_verify] = as[1];
	++lines_ed25519_verify;
}

END {
	for(i=0;i<lines_filename;i++) {
		printf("%s,%d,%d,%d,%d,%d\n",filename[i],sha256[i],sha512[i],blake2b[i],ed25519_final[i],ed25519_verify[i]);
	}
};

' ${FILE_NAME}
