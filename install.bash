#!/bin/bash
set -e

if [ -z $INSTALL_PATH]; then 
	INSTALL_PATH=/usr/local
fi

if [ -z $LIB_DIR]; then 
	LIB_DIR=lib
fi

if [ -z $INC_DIR]; then 
	INC_DIR=include
fi

if [ -z $BIN_DIR]; then 
	INC_DIR=bin
fi

# internal folders to cpy from
SRC_LIB=lib
SRC_INC=inc
SRC_BIN=bin

INSTALL_LIB="$INSTALL_PATH/$LIB_DIR"
INSTALL_INC="$INSTALL_PATH/$INC_DIR"
INSTALL_BIN="$INSTALL_PATH/$BIN_DIR"

read -p "install at $INSTALL_PATH in the subfolders $LIB_DIR, $INC_DIR, and $BIN_DIR?" -n 1 -r
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
	# copies binaries, .so and API .hpp to OS folder
	printf "cp $SRC_LIB/libparacrypt*.so $INSTALL_LIB\n"
	        cp $SRC_LIB/libparacrypt*.so $INSTALL_LIB

	printf "cp -L $SRC_INC/Paracrypt.hpp $INSTALL_INC\n"
	        cp -L $SRC_INC/Paracrypt.hpp $INSTALL_INC

	printf "cp $SRC_BIN/paracrypt* $INSTALL_BIN\n"
	        cp $SRC_BIN/paracrypt* $INSTALL_BIN
else
	printf "set INSTALL_PATH (and LIB_DIR, INC_DIR, BIN_DIR) to the desired location and come back again\n"
fi
