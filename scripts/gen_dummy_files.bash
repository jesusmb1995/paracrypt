#!/bin/bash

# generates files that can be used to 
#  test if paracrypt command line tool
#  is working.

outputFolder="../info"

randomfile="$outputFolder/randomfile.txt"
head -c 100 </dev/urandom > $randomfile

printf "random file ($randomfile):\n"
xxd -p $randomfile #display

# NIST-197: Appendix B - Cipher Example (pag. 33)
# https://doi.org/10.6028/NIST.FIPS.197
#
# File with cipher example as output
#
cipherexamplefile="$outputFolder/nistcipherexample.txt"
# https://stackoverflow.com/questions/1604765/linux-shell-scripting-hex-string-to-bytes
printf "3925841d02dc09fbdc118597196a0b32" | \
 perl -pe 's/([0-9a-f]{2})/chr hex $1/gie' > $cipherexamplefile

printf "\ncipher example file ($cipherexamplefile):\n"
xxd -p $cipherexamplefile #display

command="paracrypt -c aes-128-ecb -d -K 2b7e151628aed2a6abf7158809cf4f3c -in $cipherexamplefile -out result.txt"
printf "\ncheck you obtain 3243f6a8885a308d313198a2e0370734 after decryption with $command\n"
