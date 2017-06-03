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
	../bin/paracrypt_tests_dbg --run_test=LAUNCHERS > ../info/tryToForceFail.txt
	RESULT=$?	
	I=$((I+1))
done


