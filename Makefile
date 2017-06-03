 #
 #  Copyright (C) 2017 Jesus Martin Berlanga. All Rights Reserved.
 #
 #  This file is part of Paracrypt.
 #
 #  Paracrypt is free software: you can redistribute it and/or modify
 #  it under the terms of the GNU General Public License as published by
 #  the Free Software Foundation, either version 3 of the License, or
 #  (at your option) any later version.
 #
 #  Paracrypt is distributed in the hope that it will be useful,
 #  but WITHOUT ANY WARRANTY; without even the implied warranty of
 #  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 #  GNU General Public License for more details.
 #
 #  You should have received a copy of the GNU General Public License
 #  along with Paracrypt.  If not, see <http://www.gnu.org/licenses/>.
 #
 #


###################################################################################
# DEFINES #########################################################################
###################################################################################
#
LBITS := $(shell getconf LONG_BIT)
CUDA_PATH ?= /usr/local/cuda
CUDA_LIB ?= $(CUDA_PATH)/lib$(LBITS)
CUDA_INC ?= $(CUDA_PATH)/include
BOOST_PATH ?= /usr
BOOST_LIB ?= $(BOOST_PATH)/lib
OPENSSL_INC ?= /usr/include/openssl
OPENSSL_EXISTS := $(shell [ -d $(OPENSSL_INC) ] && echo 1)
#
NVCC ?= $(CUDA_PATH)/bin/nvcc
CXX ?= g++ # TODO icc versions
#
FLAGS ?=
CXX_FLAGS ?= -Wall -DBOOST_LOG_DYN_LINK
NVCC_FLAGS ?=
CXX_FLAGS_ ?= $(FLAGS) $(CXX_FLAGS)
NVCC_FLAGS_ ?= $(FLAGS) $(NVCC_FLAGS)
CXX_FLAGS__ = # extra flags
NVCC_FLAGS__ = # extra flags
#
SRC_DIR ?= src
TST_DIR ?= $(SRC_DIR)/tests
BIN_DIR ?= bin
LIB_DIR ?= lib
OBJ_DIR ?= obj
INF_DIR ?= info
INC_DIR ?= inc
#
LIBS ?= -L$(BOOST_LIB) -lboost_system -lboost_log -lboost_log_setup -lboost_thread \
        -lpthread -L$(CUDA_LIB) -lcuda -lcudart
INCL ?= -I$(SRC_DIR) -I$(CUDA_INC)
#


###################################################################################
# OBJECTS #########################################################################
###################################################################################
$(OBJ_DIR)/Paracrypt.o: $(SRC_DIR)/Paracrypt.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/BlockCipher.o: $(SRC_DIR)/cipher/BlockCipher.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CUDABlockCipher.o: $(SRC_DIR)/cipher/CUDABlockCipher.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/AES.o: $(SRC_DIR)/cipher/AES/AES.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAES.o: $(SRC_DIR)/cipher/AES/CudaAES.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAESConstant.cu.o: $(SRC_DIR)/cipher/AES/CudaConstant.cu
	$(NVCC) $(NVCC_FLAGS_) $(NVCC_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAesVersions.o: $(SRC_DIR)/cipher/AES/CudaAesVersions.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAes16B.cu.o: $(SRC_DIR)/cipher/AES/CudaAes16B.cu
	$(NVCC) $(NVCC_FLAGS_) $(NVCC_FLAGS__) $(NVCC_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAes16BPtr.cu.o: $(SRC_DIR)/cipher/AES/CudaAes16BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) $(NVCC_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAes8B.cu.o: $(SRC_DIR)/cipher/AES/CudaAes8B.cu
	$(NVCC) $(NVCC_FLAGS_) $(NVCC_FLAGS__)  -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAes8BPtr.cu.o: $(SRC_DIR)/cipher/AES/CudaAes8BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) $(NVCC_FLAGS__)  -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAes4B.cu.o: $(SRC_DIR)/cipher/AES/CudaAes4B.cu
	$(NVCC) $(NVCC_FLAGS_) $(NVCC_FLAGS__)  -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAes4BPtr.cu.o: $(SRC_DIR)/cipher/AES/CudaAes4BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) $(NVCC_FLAGS__)  -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAes1B.cu.o: $(SRC_DIR)/cipher/AES/CudaAes1B.cu
	$(NVCC) $(NVCC_FLAGS_) $(NVCC_FLAGS__)  -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CUDACipherDevice.o: $(SRC_DIR)/device/CUDACipherDevice.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/logging.o: $(SRC_DIR)/logging.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/AES_key_schedule.o: $(SRC_DIR)/openssl/AES_key_schedule.c
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/endianess.o: $(SRC_DIR)/endianess.c
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/Timer.o: $(SRC_DIR)/Timer.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#	
$(OBJ_DIR)/bin_endian_ttable_generator.o: $(SRC_DIR)/cipher/AES/big_endian_ttable_generator.cpp
	$(CXX) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/IO.o: $(SRC_DIR)/io/IO.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/BlockIO.o: $(SRC_DIR)/io/BlockIO.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/SimpleIO.o: $(SRC_DIR)/io/SimpleIO.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/SimpleCudaIO.o: $(SRC_DIR)/io/SimpleCudaIO.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/SharedIO.o: $(SRC_DIR)/io/SharedIO.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaSharedIO.o: $(SRC_DIR)/io/CudaSharedIO.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/Pinned.o: $(SRC_DIR)/io/Pinned.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaPinned.o: $(SRC_DIR)/io/CudaPinned.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/Launcher.o: $(SRC_DIR)/Launcher.cpp
	$(CXX) $(CXX_FLAGS_) $(CXX_FLAGS__) -c $< -o $@ $(INCL)
#
OBJECTS= \
	$(OBJ_DIR)/Paracrypt.o \
	$(OBJ_DIR)/AES_key_schedule.o \
	$(OBJ_DIR)/endianess.o \
	$(OBJ_DIR)/logging.o \
	$(OBJ_DIR)/Timer.o \
	$(OBJ_DIR)/BlockCipher.o \
	$(OBJ_DIR)/CUDABlockCipher.o \
	$(OBJ_DIR)/AES.o \
	$(OBJ_DIR)/CudaAES.o \
	$(OBJ_DIR)/CudaAESConstant.cu.o \
	$(OBJ_DIR)/CudaAesVersions.o  \
	$(OBJ_DIR)/CudaAes16B.cu.o \
	$(OBJ_DIR)/CudaAes16BPtr.cu.o \
	$(OBJ_DIR)/CudaAes8B.cu.o \
	$(OBJ_DIR)/CudaAes8BPtr.cu.o \
	$(OBJ_DIR)/CudaAes4B.cu.o \
	$(OBJ_DIR)/CudaAes4BPtr.cu.o \
	$(OBJ_DIR)/CudaAes1B.cu.o \
	$(OBJ_DIR)/CUDACipherDevice.o \
	$(OBJ_DIR)/IO.o \
	$(OBJ_DIR)/BlockIO.o \
	$(OBJ_DIR)/SharedIO.o \
	$(OBJ_DIR)/CudaSharedIO.o \
	$(OBJ_DIR)/Pinned.o \
	$(OBJ_DIR)/CudaPinned.o \
	$(OBJ_DIR)/Launcher.o


###################################################################################
# PTX #############################################################################
###################################################################################
#
# Generate PTX assembly code: Might be useful for fine 
#  grain code inspection and optimization
#
$(OBJ_DIR)/CudaAes16B.ptx: $(SRC_DIR)/cipher/AES/CudaAes16B.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaAes16BPtr.ptx: $(SRC_DIR)/cipher/AES/CudaAes16BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaAes8B.ptx: $(SRC_DIR)/cipher/AES/CudaAes8B.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaAes8BPtr.ptx: $(SRC_DIR)/cipher/AES/CudaAes8BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaAes4B.ptx: $(SRC_DIR)/cipher/AES/CudaAes4B.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaAes4BPtr.ptx: $(SRC_DIR)/cipher/AES/CudaAes4BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaAes1B.ptx: $(SRC_DIR)/cipher/AES/CudaAes1B.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
ptx: \
$(OBJ_DIR)/CudaAes16B.ptx \
$(OBJ_DIR)/CudaAes16BPtr.ptx \
$(OBJ_DIR)/CudaAes8B.ptx \
$(OBJ_DIR)/CudaAes8BPtr.ptx \
$(OBJ_DIR)/CudaAes4B.ptx \
$(OBJ_DIR)/CudaAes4BPtr.ptx \
$(OBJ_DIR)/CudaAes1B.ptx 
#


###################################################################################
# TESTS ###########################################################################
###################################################################################
LIBS_TESTS =
CXX_FLAGS_TESTS = 
ifeq ($(OPENSSL_EXISTS), 1)
	LIBS_TESTS += -lcrypto
	CXX_FLAGS_TESTS += -DOPENSSL_EXISTS
endif
#
# NOTE: Force to use -O0 to reduce overly long compiling times
$(OBJ_DIR)/tests.o: $(TST_DIR)/tests.cpp
	$(CXX) $(CXX_FLAGS) $(CXX_FLAGS_TESTS) -O0 -g -DDEBUG -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/openssl_aes.o: $(SRC_DIR)/openssl/aes_core.c
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/openssl_aes_test.o: $(TST_DIR)/openssl_aes_test.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
openssl_aes_test: CXX_FLAGS_ += -g -DDEBUG -DDEVEL
openssl_aes_test: \
$(OBJ_DIR)/cpu_AES_round_example.o \
$(OBJ_DIR)/logging.o \
$(OBJ_DIR)/openssl_aes.o \
$(OBJ_DIR)/openssl_aes_test.o
	 $(CXX) $(CXX_FLAGS_) \
	 $(OBJ_DIR)/openssl_aes_test.o \
	 $(OBJ_DIR)/logging.o \
	 $(OBJ_DIR)/openssl_aes.o \
	 -o $(BIN_DIR)/openssl_aes_test $(LIBS)
#
tests: LIBS += $(LIBS_TESTS)
tests: CXX_FLAGS_ += $(CXX_FLAGS_TESTS)
tests: \
$(OBJECTS) \
$(OBJ_DIR)/tests.o \
$(OBJ_DIR)/SimpleIO.o \
$(OBJ_DIR)/SimpleCudaIO.o
	 $(CXX) $(CXX_FLAGS_) \
	 $(OBJECTS) \
	 $(OBJ_DIR)/tests.o \
	 $(OBJ_DIR)/SimpleIO.o \
	 $(OBJ_DIR)/SimpleCudaIO.o \
	 -o $(BIN_DIR)/paracrypt_tests$(OUT_TAG) $(LIBS)
#


###################################################################################
# BUILDS ##########################################################################
###################################################################################
#
#bin_endian_ttable_generator: CXX_FLAGS__ =
#bin_endian_ttable_generator: NVCC_FLAGS__ =
#bin_endian_ttable_generator: \
#$(OBJ_DIR)/bin_endian_ttable_generator.o \
#$(OBJ_DIR)/endianess.o
#	$(CXX) \
#	$(OBJ_DIR)/endianess.o \
#	$(OBJ_DIR)/bin_endian_ttable_generator.o \
#	-o $(BIN_DIR)/bin_endian_ttable_generator
#
library: CXX_FLAGS__ = -fPIC
library: NVCC_FLAGS__ = --compiler-options '-fPIC'
library: \
$(OBJECTS)
	 $(CXX) $(CXX_FLAGS_) \
	 $(OBJECTS) \
	 -shared -o $(LIB_DIR)/libparacrypt$(OUT_TAG).so
#
tool: CXX_FLAGS__ =
tool: NVCC_FLAGS__ =
tool: 
	$(CXX) $(CXX_FLAGS_) -o $(BIN_DIR)/paracrypt$(OUT_TAG) $(SRC_DIR)/main.cpp \
	-lparacrypt$(OUT_TAG) -L$(LIB_DIR) -lboost_program_options $(LIBS)

builds: tests #clean #bin_endian_ttable_generator ptx
#builds: library tool


###################################################################################
# MAKE ############################################################################
###################################################################################
#
clean: 
	rm -f $(OBJ_DIR)/*.o
	rm -f $(OBJ_DIR)/*.ptx
	rm -f $(LIB_DIR)/*.so
	rm -f $(BIN_DIR)/*
	rm -f $(BIN_DIR)/.fuse_hidden*
	rm -f $(SRC_DIR)/*~
	rm -f $(SRC_DIR)/tests/*~
	rm -f $(SRC_DIR)/openssl/*~
	rm -f $(SRC_DIR)/io/*~
	rm -f $(SRC_DIR)/device/*~
	rm -f $(SRC_DIR)/cipher/*~
	rm -f $(INF_DIR)/*
#
all: 
	make clean debug
	make clean devel
	make clean release
#
devel: OUT_TAG=_dev
devel: CXX_FLAGS_ += -g -DDEBUG -DDEVEL
devel: NVCC_FLAGS_ += -g -DDEBUG -DDEVEL
devel: builds
#
debug: OUT_TAG=_dbg
debug: CXX_FLAGS_ += -g -DDEBUG
debug: NVCC_FLAGS_ += -g -DDEBUG
debug: builds
#
# NOTE: consider using -O2 that takes considerable 
# less time to compile than -O4.
#
# -DNDEBUG removes asserts
#
release: OUT_TAG=
release: CXX_FLAGS_ += -O4 -DNDEBUG
release: NVCC_FLAGS_ += -O4
release: builds


###################################################################################
# RUNS ############################################################################
###################################################################################
#
check: tests
	valgrind --leak-check=summary $(BIN_DIR)/paracrypt_tests
	valgrind --leak-check=full --log-file=$(INF_DIR)/leaks.txt $(BIN_DIR)/paracrypt_tests
	valgrind --tool=memcheck ---log-file=$(INF_DIR)/mem.txt  $(BIN_DIR)/paracrypt_tests
	
