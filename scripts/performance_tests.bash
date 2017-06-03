#!/bin/bash
# bash performance_tests.bash

outputFolder="../info/"
filesExt="_performance.txt"
averageN=20 # average 20 executions (must be greater than nFiles)

# load paracrypt library path
LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"
export LD_LIBRARY_PATH

# Keys and IV
iv="000102030405060708090A0B0C0D0E0F"
key128="2b7e151628aed2a6abf7158809cf4f3c"
key192="000102030405060708090a0b0c0d0e0f1011121314151617"
key256="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

# Generate input files filled with up to 128MB (not MiB!) 
#  of random data. With MB instead of MiB the generated 
#  data will have to be padded ($size % 16 is not 0).
size=$(( 512*1000*1000 )) # $(( 4*1000*1000 ))
nFiles=16 # 4
stepSize=$(( $size/$nFiles ))
declare -A files
declare -A fileSizes
for ((fi=0; fi<nFiles; fi++))
do
	files[$fi]=$(mktemp /tmp/paracrypt.XXXXXX)
	fileSizes[$fi]=$(( $size/(2**$fi) ))
	fiName=${files[$fi]}
	fiSize=${fileSizes[$fi]}
	trap "rm -f $fiName" 0 2 3 15
	printf "\ngenerating random data..."
	if [ $fi -eq "0" ]; then
		head -c $fiSize </dev/urandom > $fiName
	else
		head -c $fiSize <${files[0]} > $fiName
	fi
	printf " $fiSize bytes of random data generated at $fiName\n"
	ls -la $fiName
done
# for results
tmpFile=$(mktemp /tmp/paracrypt.XXXXXX)
tmpFile2=$(mktemp /tmp/paracrypt.XXXXXX)
trap "rm -f $tmpFile" 0 2 3 15
trap "rm -f $tmpFile2" 0 2 3 15

function nanoTime {
	ts=$(date +%s%N) ; eval $@ ; tt=$((($(date +%s%N) - $ts))) ; printf "$tt"
}

#if [ "$averageN" -lt "$nFiles" ]; then
#	exit -1
#fi

# Generate performance files where each row follow 
#  the format: bytes_processed real_time_nanoseconds
dash="-"
checkCorrectness=false
function performance {
	binary=$1
	tag="$binary$dash"
	cipher=$2
	op=$3
	key=$4
	iv_option=
	if ! [ -z "$5" ]; then
		iv_option="-iv $5"
	fi

	output="$outputFolder$tag$cipher$filesExt"
	printf "\ngenerating $output\n"
	if [ -f $output ]; then
		printf "$output already exists... skipping to save time (you still can delete the file manually and call this script again)\n"
		return
	fi
	
	en_execbin=
	de_execbin=
	if [ "$binary" == "openssl" ]
	then
		en_execbin="openssl $cipher -e -K $key $iv_option -in $fiName -out $tmpFile"
		de_execbin="openssl $cipher -d -K $key $iv_option -in $tmpFile -out $tmpFile2"
	elif [ "$binary" == "paracrypt" ]
	then
		en_execbin="paracrypt -c $cipher -e -K $key $iv_option -in $fiName -out $tmpFile --quiet"
		de_execbin="paracrypt -c $cipher -d -K $key $iv_option -in $tmpFile -out $tmpFile2 --quiet"
	else
		printf "unsupported binary"
		exit -1
	fi


	if [ "$op" == "-e" ]; then
		printf "$en_execbin\n"
	elif [ "$op" == "-d" ]; then
		printf "$de_execbin\n"
	else 
		printf "unsupported operation"
		exit -1
	fi

	for ((fi=0; fi<nFiles; fi++))
	do
		fiName=${files[$fi]}
		fiSize=${fileSizes[$fi]}
		sum_real=0
		localAverage=$averageN
		# use this formula for files bigger than 1 MB
		if [ $fiSize -ge "1000000" ]; then 
			# multiply by 2^fi so that we average 
	 		#  aprox. during the same ammount of time
			#  for each file, independently of the
			#  file size. ((3/2)^fi is faster)
			localAverage=$(( $averageN*((3/2)**($fi)) ))
		fi
		for ((i=0; i<localAverage; i++))
		do
			# truncate/clean previous results in output file
			cat /dev/null > $tmpFile
			real=
			if [ "$op" == "-e" ]; then
				real=$( nanoTime "$en_execbin" )
			else
				eval "$en_execbin"
				real=$( nanoTime "$de_execbin" )
				if [ "$checkCorrectness" == "false" ]; then
					cmp --silent $tmpFile $tmpFile2
					if [ "$?" != "0" ]; then
						echo "files are different"
						cmp -l $tmpFile $tmpFile2 | gawk '{printf "%08X %02X %02X\n", $1, strtonum(0$2), strtonum(0$3)}' | head
						exit -1
					fi
				fi
			fi
			prog=$(( $i % (2**$fi) ))
			if [ "$prog" -eq "0" ]; then
				printf "."
			fi
			sum_real=$(( $sum_real+$real ))
		done
		average=$(( $sum_real/$averageN ))
		row="$fiSize $average\n"
		printf "$fi/$nFiles:$fiSize.$average"
		printf "$row" >> $output
	done
}

#TODO do 10 times  average...
#https://stackoverflow.com/questions/4617489/get-values-from-time-command-via-bash-script

printf "\nStarting to measure performances, this may take a while... go grab a cup of cofee :)\n"
#performance "openssl" aes-128-cbc -e $key128 $iv
#performance "openssl" aes-128-cbc -d $key128 $iv
#performance "openssl" aes-128-cbc -d $key128 $iv
#performance "openssl" aes-128-ecb -e $key128
#performance "paracrypt" aes-128-ecb -e $key128
performance "openssl" aes-128-ctr -e $key128 $iv
performance "paracrypt" aes-128-ctr -e $key128 $iv

#performance "openssl" aes-128-cbc -e $key128 $iv

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
	fiName=${files[$fi]}
	rm $fiName
done
rm $tmpFile
rm $tmpFIle2




