I=1
RESULT=0
until [ $RESULT != 0 ]
do
	echo $I
	./bin/paracrypt_tests --run_test=LAUNCHERS/CUDA/SHAREDIO/AES > ./info/tryToForceFail.txt
	RESULT=$?	
	I=$((I+1))
done


