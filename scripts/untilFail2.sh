# Try to force a concurrency fail
#  here we try to generate some 
#  ugly bugs.
#
# The ausence of fails does not mean
#  there isn't some concurrency ugly
#  bugs hidden but something is better
#  than nothing
#
I=1
RESULT=0
until [ $RESULT != 0 ]
do
	echo $I
	../bin/paracrypt_tests --run_test=CUDA_AES/CUDA_AES_8B/AES_128_CBC/random_decrypt > ../info/tryToForceFail.txt
	RESULT=$?	
	I=$((I+1))
done


