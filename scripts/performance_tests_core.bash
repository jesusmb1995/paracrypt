#!/bin/bash
# bash performance_tests.bash
set -e

if [ -z $1 ]; then
	printf "error: missing tests script argument: e.g. bash performance_tests_core.bash performance_tests.bash"
fi
testsScript=$1
mode="full"
if ! [ -z $2 ]; then
	mode=$2
fi

outputFolder="../info/"
filesExt="_performance.txt"
averageN=4 # averages
averageLimit=64

# load paracrypt library path
LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"
export LD_LIBRARY_PATH

# Keys and IV
iv="000102030405060708090A0B0C0D0E0F"
key128="2b7e151628aed2a6abf7158809cf4f3c"
key192="000102030405060708090a0b0c0d0e0f1011121314151617"
key256="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

# Generate input files filled with up to 4GB (not GiB!) 
#  of random data. With MB instead of MiB the generated 
#  data will have to be padded ($size % 16 is not 0).
randomFun="openssl enc -aes-128-ctr -pass pass:\"$(dd if=/dev/urandom bs=128 count=1 2>/dev/null | base64)\" -nosalt < /dev/zero"
size=$(( 4000*1000*1000 ))
nFiles=16

if [ "$mode" == "full" ]; then
	averageN=4
	size=$(( 4000*1000*1000 )) # 4 GB
	nFiles=16
	averageLimit=64
elif [ "$mode" == "fast" ]; then
	averageN=2
	size=$(( 500*1000*1000 )) # 500 MB
	nFiles=13
	averageLimit=16
else
	printf "invalid script mode: use full or fast\n"
	exit -1
fi

stepSize=$(( $size/$nFiles ))
declare -A files
declare -A fileSizes
for ((fi=0; fi<nFiles; fi++))
do
	fileSizes[$fi]=$(( $size/(2**$fi) ))
	fiSize=${fileSizes[$fi]}
	files[$fi]="/tmp/paracrypt.$fiSize" #$(mktemp /tmp/paracrypt.XXXXXX)
	fiName=${files[$fi]}
	if [ -e $fiName ]; then
		printf "\nreusing existing random data..."
	else
		#trap "rm -f $fiName" 0 2 3 15
		printf "\ngenerating random data...\n"
		# use pv to show progress
		if [ $fi -eq "0" ]; then
			# head -c $fiSize </dev/urandom # urandom is slow
			eval "$randomFun" | head -c $fiSize | pv -s $fiSize > $fiName
		else
			head -c $fiSize <${files[0]} | pv -s $fiSize > $fiName
		fi
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
	extra=
	if ! [ -z "$6" ]; then
		extra="$6"
	fi
	tag=
	if ! [ -z "$7" ]; then
		tag="$7"
	fi
	preencrypt="false"
	if ! [ -z "$8" ]; then
		preencrypt="true"
	fi

	output="$outputFolder$binary$dash$cipher$tag$filesExt"
	printf "\n\ngenerating $output$\n"
	if [ -f $output ]; then
		printf "$output already exists... skipping to save time (you still can delete the file manually and call this script again)\n"
		return
	fi
	
	for ((fi=0; fi<nFiles; fi++))
	do
		fiName=${files[$fi]}
		fiSize=${fileSizes[$fi]}

		en_execbin=
		de_execbin=
		if [ "$binary" == "openssl" ]
		then
			en_execbin="openssl $cipher -e -K $key $iv_option -in $fiName -a -out $tmpFile $extra"
			de_execbin="openssl $cipher -d -K $key $iv_option -in $tmpFile -a -out $tmpFile2 $extra"
		elif [ "$binary" == "paracrypt" ]
		then
			en_execbin="paracrypt -c $cipher -e -K $key $iv_option -in $fiName -out $tmpFile --quiet $extra"
			de_execbin="paracrypt -c $cipher -d -K $key $iv_option -in $tmpFile -out $tmpFile2 --quiet $extra"
		else
			printf "unsupported binary"
			exit -1
		fi

		if [ "$op" == "-e" ]; then
			printf "$en_execbin"
		elif [ "$op" == "-d" ]; then
			printf "$de_execbin"
		else 
			printf "unsupported operation"
			exit -1
		fi

		sum_real=0
		localAverage=$(( $averageN**($fi) ))
		if [ "$localAverage" -ge "$averageLimit" ]; then 
			localAverage="$averageLimit" #limit
		fi

		for ((i=0; i<localAverage; i++))
		do
			# truncate/clean previous results in output file
			cat /dev/null > $tmpFile
			real=
			if [ "$op" == "-e" ]; then
				real=$( nanoTime "$en_execbin" )
			else
				if [ $preencrypt == "true" ]; then
					eval "$en_execbin"
				else
					cat $fiName > $tmpFile;
				fi
				real=$( nanoTime "$de_execbin" )
				#if [ "$checkCorrectness" == "false" ]; then
				#	cmp --silent $tmpFile $tmpFile2
				#	if [ "$?" != "0" ]; then
				#		echo "files are different"
				#		cmp -l $tmpFile $tmpFile2 | gawk '{printf "%08X %02X %02X\n", $1, strtonum(0$2), strtonum(0$3)}' | head
				#		exit -1
				#	fi
				#fi
			fi
			prog=$(( $i % ($fi+1) ))
			if [ "$prog" -eq "0" ]; then
				printf "."
			fi
			sum_real=$(( $sum_real+$real ))
		done
		average=$(( $sum_real/$localAverage ))
		row="$fiSize $average\n"
		printf "$fi/$nFiles:$fiSize.$average\n"
		printf "$row" >> $output
	done
}

printf "\nStarting to measure performances ($testsScript), this may take a while... go grab a cup of cofee :)\n"
. "$testsScript"

#for ((fi=0; fi<nFiles; fi++))
#do
#	fiName=${files[$fi]}
#	rm $fiName
#done
rm "$tmpFile"
rm "$tmpFIle2"




