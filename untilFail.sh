I=1
until [ $? != 0 ]
do
	echo $I
	./bin/paracrypt_tests --run_test=LAUNCHERS/CUDA/SHAREDIO/AES > ./info/tryToForceFail.txt
	I=$((I+1))
done


