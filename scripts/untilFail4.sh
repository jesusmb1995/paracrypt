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
	../bin/paracrypt_tests --run_test=LAUNCHERS/CUDA/SHAREDIO/AES/PARA_8B/RANDOM_DECRYPT_CBC_192/sixtyfive_blocks/in_order_constant_key > ../info/tryToForceFail.txt
	RESULT=$?	
	I=$((I+1))
done


