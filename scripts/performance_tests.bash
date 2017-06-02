#!/bin/bash
# bash performance_tests.bash

outputFolder="../info/"
filesExt="_performance.txt"
TIMEFORMAT=%R # measure real times

# Keys and IV
iv="000102030405060708090A0B0C0D0E0F"
key128="2b7e151628aed2a6abf7158809cf4f3c"
key192="000102030405060708090a0b0c0d0e0f1011121314151617"
key256="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

# Generate input files filled with up to 128MB of random data
size=$(( 128*1000*1000 ))
nFiles=1 #8
stepSize=$(( $size/$nFiles ))
declare -A files
declare -A fileSizes
for ((fi=1; fi<=nFiles; fi++))
do
	files[fi]=$(mktemp /tmp/paracrypt.XXXXXX)
	fileSizes[fi]=$(( $stepSize*$fi ))
	fiName=${files[fi]}
	fiSize=${fileSizes[fi]}
	trap "rm -f $file" 0 2 3 15
	printf "\ngenerating random data..."
	head -c $fiSize </dev/urandom >$fiName
	printf " $fiSize bytes of random data generated at $fiName\n"
	ls -la $fiName
done

# Generate performance files where each row follow 
#  the format: bytes_processed real_time
openSSLTag="openssl-"
function openssl_test {
	cipher=$1
	key=$2
	iv_option=
	if ! [ -nz "$3" ]; then
		iv_option="-iv $3"
	fi

	output="$outputFolder$openSSLTag$cipher$filesExt"
	printf "\ngenerating $output\n"

	for ((fi=1; fi<=nFiles; fi++))
	do
		fiName=${files[fi]}
		fiSize=${fileSizes[fi]}
		printf   "openssl $cipher -e -K $key $iv_option -in size$fiSize > /dev/null ... "
		real=time openssl $cipher -e -K $key $iv_option -in $fiName     > /dev/null
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
for ((fi=1; fi<=nFiles; fi++))
do
	fiName=${files[fi]}
	rm $fiName
done




