#!/bin/bash
# bash performance_tests.bash

outputFolder="../info/"
filesExt="_performance.txt"
#TIMEFORMAT='%7R' # measure real times (but not enough precission)

# Keys and IV
iv="000102030405060708090A0B0C0D0E0F"
key128="2b7e151628aed2a6abf7158809cf4f3c"
key192="000102030405060708090a0b0c0d0e0f1011121314151617"
key256="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

# Generate input files filled with up to 128MB (not MiB!) 
#  of random data. With MB instead of MiB the generated 
#  data will have to be padded ($size % 16 is not 0).
size=$(( 1*1000*1000 )) # $(( 128*1000*1000 ))
nFiles=1 #16
stepSize=$(( $size/$nFiles ))
declare -A files
declare -A fileSizes
for ((fi=0; fi<nFiles; fi++))
do
	files[fi]=$(mktemp /tmp/paracrypt.XXXXXX)
	fileSizes[fi]=$(( $size/(2**$fi) ))
	fiName=${files[fi]}
	fiSize=${fileSizes[fi]}
	trap "rm -f $file" 0 2 3 15
	printf "\ngenerating random data..."
	head -c $fiSize </dev/urandom >$fiName
	printf " $fiSize bytes of random data generated at $fiName\n"
	ls -la $fiName
done

function nanoTime {
	ts=$(date +%s%N) ; $@ ; tt=$((($(date +%s%N) - $ts)/1000000)) ; echo "Time taken: $tt"
}

# Generate performance files where each row follow 
#  the format: bytes_processed real_time
openSSLTag="openssl-"
function openssl_test {
	cipher=$1
	key=$2
	iv_option=
	if ! [ -z "$3" ]; then
		iv_option="-iv $3"
	fi

	output="$outputFolder$openSSLTag$cipher$filesExt"
	printf "\ngenerating $output\n"

	for ((fi=0; fi<nFiles; fi++))
	do
		fiName=${files[fi]}
		fiSize=${fileSizes[fi]}
		printf        "openssl $cipher -e -K $key $iv_option -in size$fiSize ... "
		#A="$( { time ls -la > /dev/null; } 2>&1 )"
		real=$( { time openssl $cipher -e -K $key $iv_option -in $fiName > /dev/null; } 2>&1 )
		row="$fiSize $real\n"
		printf " $row"
		printf "$row" >> $fiName
	done
}

#TODO do 10 times  average...
#https://stackoverflow.com/questions/4617489/get-values-from-time-command-via-bash-script

openssl_test aes-128-cbc $key128 $iv

# OpenSSL encryption
# openssl aes-128-cbc -e -K 2b7e151628aed2a6abf7158809cf4f3c -iv 000102030405060708090A0B0C0D0E0F -in in.bin -out out.txt
# speed is only avaliable with aes-128-cbc aes-192-cbc aes-256-cbc aes-128-ige aes-192-ige aes-256-ige
#openssl speed -elapsed -evp aes-128-cbc
#openssl speed -evp aes-128-cbc -e -K $key128 -iv $iv -in $temp_file -out /dev/null 
#  speed -elapsed
#cmp --silent $old $new || echo "no match with original file after decryption"

#TODO generate graphs with python
for ((fi=0; fi<nFiles; fi++))
do
	fiName=${files[fi]}
	rm $fiName
done




