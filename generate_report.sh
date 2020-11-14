#!/bin/sh

NO_TESTS=1000
OUTPUT_FOLDER=report
OUTPUT_FILE_SEQ=report_sequence
OUTPUT_FILE_THR=report_thread
BIN_SEQ=./get-hashes
BIN_THR=./crypto-tester
#FILES="1 2 4 8 16 32 64 128 256 512 1024 2048 4096"
FILES="1 2"
#OPTIMIZE_FLAGS="-O0 -O1 -O2 -O3"
OPTIMIZE_FLAGS="-O0 -O1"
RANDOM_PREFIX=rndfile

for i in ${FILES};
do
        echo $i
        dd if=/dev/urandom of=${RANDOM_PREFIX}_${i} bs=1M count=${i}
done

rm -rf ${OUTPUT_FOLDER}

for cxxflags in ${OPTIMIZE_FLAGS};
do
	rm -rf CMakeCache.txt CMakeFiles/
	cmake ..
	CXXFLAGS="${cxxflags}" VERBOSE=1 make

	mkdir -p ${OUTPUT_FOLDER}/`echo "${cxxflags}" | cut -c2-`

	for i in ${FILES};
	do
		${BIN_SEQ} rndfile_${i} ${NO_TESTS} ${OUTPUT_FOLDER}/`echo "${cxxflags}" | cut -c2-`/${OUTPUT_FILE_SEQ}_${NO_TESTS}_${i}.csv
	done

	for i in ${FILES};
	do
		${BIN_THR} rndfile_${i} ${NO_TESTS} ${OUTPUT_FOLDER}/`echo "${cxxflags}" | cut -c2-`/${OUTPUT_FILE_THR}_${NO_TESTS}_${i}.csv
	done
done

# for SEQ
for FILE_NAME in `find ${OUTPUT_FOLDER}/ -name "*${OUTPUT_FILE_SEQ}*" -type f | sort`;
do
	echo "For ${FILE_NAME}";
	gawk 'BEGIN {
		print "arithmetic average / standard uncertainty for SEQ file";

		n = 0;

		sha256 = 0;
		sha512 = 0;
		blake2b = 0;
		ed25519_s = 0;
		ed25519_v = 0;

		regexp_v = "^[[:digit:]]+,[[:digit:]]+,[[:digit:]]+,[[:digit:]]+,[[:digit:]]+$";
	};

	function f(a,b,c,d,e)
	{
		p = 0;
		q = 0;
		r = c / e;
		for(i = 0; i < n; i++) {
			p += ((d[i] - r) * (d[i] - r))
		}
		q = b * sqrt(p / (e * (e - 1)));
		printf("%s : X=%F ms , S=%F ms\n",a,r,q);
	}

	$0 ~ regexp_v {
		split($0,tab,",");

		sha256 += tab[1];
		a_sha256[n] = tab[1];

		sha512 += tab[2];
		a_sha512[n] = tab[2];

		blake2b += tab[3];
		a_blake2b[n] = tab[3];

		ed25519_s += tab[4];
		a_ed25519_s[n] = tab[4];

		ed25519_v += tab[5];
		a_ed25519_v[n] = tab[5];

		++n;
	}

	END {
		N = 3;
		if (n > 0) {
			f("SHA256    ",N,sha256    ,a_sha256    ,n);
			f("SHA512    ",N,sha512    ,a_sha512    ,n);
			f("BLAKE2B   ",N,blake2b   ,a_blake2b   ,n);
			f("ED25519_S ",N,ed25519_s ,a_ed25519_s ,n);
			f("ED25519_V ",N,ed25519_v ,a_ed25519_v ,n);
		}
	};
' ${FILE_NAME}
done

# THR
for FILE_NAME in `find ${OUTPUT_FOLDER}/ -name "*${OUTPUT_FILE_THR}*" -type f | sort`;
do
	echo "For ${FILE_NAME}";
	gawk 'BEGIN {
		print "arithmetic average / standard uncertainty for THR file";

		n = 0;

		sha256 = 0;
		sha512 = 0;
		blake2b = 0;
		ed25519_s = 0;

		regexp_v = "^[[:digit:]]+,[[:digit:]]+,[[:digit:]]+,[[:digit:]]+$";
	};

	function f(a,b,c,d,e)
	{
		p = 0;
		q = 0;
		r = c / e;
		for(i = 0; i < n; i++) {
			p += ((d[i] - r) * (d[i] - r))
		}
		q = b * sqrt(p / (e * (e - 1)));
		printf("%s : X=%F ms , S=%F ms\n",a,r,q);
	}

	$0 ~ regexp_v {
		split($0,tab,",");

		sha256 += tab[1];
		a_sha256[n] = tab[1];

		sha512 += tab[2];
		a_sha512[n] = tab[2];

		blake2b += tab[3];
		a_blake2b[n] = tab[3];

		ed25519_s += tab[4];
		a_ed25519_s[n] = tab[4];

		++n;
	}

	END {
		N = 3;
		if (n > 0) {
			f("SHA256    ",N,sha256    ,a_sha256    ,n);
			f("SHA512    ",N,sha512    ,a_sha512    ,n);
			f("BLAKE2B   ",N,blake2b   ,a_blake2b   ,n);
			f("ED25519_S ",N,ed25519_s ,a_ed25519_s ,n);
		}
	};
' ${FILE_NAME}
done

