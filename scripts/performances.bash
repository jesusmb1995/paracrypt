#!/bin/bash
# bash performance_tests.bash
set -e

ver="full"
read -p "execute tests quickly? otherwhise I will execute test for precission (it will take me more time)" -n 1 -r
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
	ver="fast"
fi

tests="bash performance_tests_core.bash performance_tests.bash $ver | tee ../info/tests_log.txt"
printf "$tests\n"
eval   "$tests"

plot="python performances_plot.py"
printf "$plot\n"
eval   "$plot"
