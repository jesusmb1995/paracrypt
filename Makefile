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
#
SRC_DIR ?= src
TST_DIR ?= $(SRC_DIR)/tests
BIN_DIR ?= bin
LIB_DIR ?= lib
OBJ_DIR ?= obj
INF_DIR = info
#
LIBS ?= -L$(BOOST_LIB) -lboost_system -lboost_log -lboost_log_setup -lboost_thread \
        -lpthread -L$(CUDA_LIB) -lcuda -lcudart
INCL ?= -I$(SRC_DIR) -I$(CUDA_INC)
#
OBJ_EXT =


###################################################################################
# OBJECTS #########################################################################
###################################################################################
#
$(OBJ_DIR)/BlockCipher$(OBJ_EXT).o: $(SRC_DIR)/cipher/BlockCipher.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CUDABlockCipher$(OBJ_EXT).o: $(SRC_DIR)/cipher/CUDABlockCipher.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/AES$(OBJ_EXT).o: $(SRC_DIR)/cipher/AES/AES.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAES$(OBJ_EXT).o: $(SRC_DIR)/cipher/AES/CudaAES.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAESConstant$(OBJ_EXT).cu.o: $(SRC_DIR)/cipher/AES/CudaConstant.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAesVersions$(OBJ_EXT).o: $(SRC_DIR)/cipher/AES/CudaAesVersions.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAes16B$(OBJ_EXT).cu.o: $(SRC_DIR)/cipher/AES/CudaAes16B.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAes16BPtr$(OBJ_EXT).cu.o: $(SRC_DIR)/cipher/AES/CudaAes16BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAes8B$(OBJ_EXT).cu.o: $(SRC_DIR)/cipher/AES/CudaAes8B.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAes8BPtr$(OBJ_EXT).cu.o: $(SRC_DIR)/cipher/AES/CudaAes8BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAes4B$(OBJ_EXT).cu.o: $(SRC_DIR)/cipher/AES/CudaAes4B.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAes4BPtr$(OBJ_EXT).cu.o: $(SRC_DIR)/cipher/AES/CudaAes4BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAes1B$(OBJ_EXT).cu.o: $(SRC_DIR)/cipher/AES/CudaAes1B.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CUDACipherDevice$(OBJ_EXT).o: $(SRC_DIR)/device/CUDACipherDevice.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/logging$(OBJ_EXT).o: $(SRC_DIR)/logging.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/AES_key_schedule$(OBJ_EXT).o: $(SRC_DIR)/openssl/AES_key_schedule.c
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/endianess$(OBJ_EXT).o: $(SRC_DIR)/endianess.c
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/Timer$(OBJ_EXT).o: $(SRC_DIR)/Timer.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#	
$(OBJ_DIR)/bin_endian_ttable_generator$(OBJ_EXT).o: $(SRC_DIR)/cipher/AES/big_endian_ttable_generator.cpp
	$(CXX) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/IO$(OBJ_EXT).o: $(SRC_DIR)/io/IO.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/BlockIO$(OBJ_EXT).o: $(SRC_DIR)/io/BlockIO.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/SimpleIO$(OBJ_EXT).o: $(SRC_DIR)/io/SimpleIO.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/SimpleCudaIO$(OBJ_EXT).o: $(SRC_DIR)/io/SimpleCudaIO.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/SharedIO$(OBJ_EXT).o: $(SRC_DIR)/io/SharedIO.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaSharedIO$(OBJ_EXT).o: $(SRC_DIR)/io/CudaSharedIO.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/Pinned$(OBJ_EXT).o: $(SRC_DIR)/io/Pinned.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaPinned$(OBJ_EXT).o: $(SRC_DIR)/io/CudaPinned.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/Launcher$(OBJ_EXT).o: $(SRC_DIR)/Launcher.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
OBJECTS= \
	$(OBJ_DIR)/AES_key_schedule$(OBJ_EXT).o \
	$(OBJ_DIR)/endianess$(OBJ_EXT).o \
	$(OBJ_DIR)/logging$(OBJ_EXT).o \
	$(OBJ_DIR)/Timer$(OBJ_EXT).o \
	$(OBJ_DIR)/BlockCipher$(OBJ_EXT).o \
	$(OBJ_DIR)/CUDABlockCipher$(OBJ_EXT).o \
	$(OBJ_DIR)/AES$(OBJ_EXT).o \
	$(OBJ_DIR)/CudaAES$(OBJ_EXT).o \
	$(OBJ_DIR)/CudaAESConstant$(OBJ_EXT).cu.o \
	$(OBJ_DIR)/CudaAesVersions$(OBJ_EXT).o  \
	$(OBJ_DIR)/CudaAes16B$(OBJ_EXT).cu.o \
	$(OBJ_DIR)/CudaAes16BPtr$(OBJ_EXT).cu.o \
	$(OBJ_DIR)/CudaAes8B$(OBJ_EXT).cu.o \
	$(OBJ_DIR)/CudaAes8BPtr$(OBJ_EXT).cu.o \
	$(OBJ_DIR)/CudaAes4B$(OBJ_EXT).cu.o \
	$(OBJ_DIR)/CudaAes4BPtr$(OBJ_EXT).cu.o \
	$(OBJ_DIR)/CudaAes1B$(OBJ_EXT).cu.o \
	$(OBJ_DIR)/CUDACipherDevice$(OBJ_EXT).o \
	$(OBJ_DIR)/IO$(OBJ_EXT).o \
	$(OBJ_DIR)/BlockIO$(OBJ_EXT).o \
	$(OBJ_DIR)/SharedIO$(OBJ_EXT).o \
	$(OBJ_DIR)/CudaSharedIO$(OBJ_EXT).o \
	$(OBJ_DIR)/Pinned$(OBJ_EXT).o \
	$(OBJ_DIR)/CudaPinned$(OBJ_EXT).o \
	$(OBJ_DIR)/Launcher$(OBJ_EXT).o

###################################################################################
# PTX #############################################################################
###################################################################################
#
# Generate PTX assembly code: Might be useful for fine 
#  grain code inspection and optimization
#
$(OBJ_DIR)/CudaAes16B$(OBJ_EXT).ptx: $(SRC_DIR)/cipher/AES/CudaAes16B.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaAes16BPtr$(OBJ_EXT).ptx: $(SRC_DIR)/cipher/AES/CudaAes16BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaAes8B$(OBJ_EXT).ptx: $(SRC_DIR)/cipher/AES/CudaAes8B.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaAes8BPtr$(OBJ_EXT).ptx: $(SRC_DIR)/cipher/AES/CudaAes8BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaAes4B$(OBJ_EXT).ptx: $(SRC_DIR)/cipher/AES/CudaAes4B.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaAes4BPtr$(OBJ_EXT).ptx: $(SRC_DIR)/cipher/AES/CudaAes4BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaAes1B$(OBJ_EXT).ptx: $(SRC_DIR)/cipher/AES/CudaAes1B.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
ptx: \
$(OBJ_DIR)/CudaAes16B$(OBJ_EXT).ptx \
$(OBJ_DIR)/CudaAes16BPtr$(OBJ_EXT).ptx \
$(OBJ_DIR)/CudaAes8B$(OBJ_EXT).ptx \
$(OBJ_DIR)/CudaAes8BPtr$(OBJ_EXT).ptx \
$(OBJ_DIR)/CudaAes4B$(OBJ_EXT).ptx \
$(OBJ_DIR)/CudaAes4BPtr$(OBJ_EXT).ptx \
$(OBJ_DIR)/CudaAes1B$(OBJ_EXT).ptx 
#


###################################################################################
# TESTS ###########################################################################
###################################################################################
#
TESTS_BIN ?= paracrypt_tests
#
$(OBJ_DIR)/tests.o: $(TST_DIR)/tests.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
LIBS_TESTS =
CXX_FLAGS_TESTS = 
ifeq ($(OPENSSL_EXISTS), 1)
	LIBS_TESTS += -lcrypto
	CXX_FLAGS_TESTS += -DOPENSSL_EXISTS
endif
tests: LIBS += $(LIBS_TESTS)
tests: CXX_FLAGS_ += $(CXX_FLAGS_TESTS)
tests: \
$(OBJECTS) \
$(OBJ_DIR)/BlockIO$(OBJ_EXT).o \
$(OBJ_DIR)/SimpleIO$(OBJ_EXT).o
	 $(CXX) $(CXX_FLAGS_) \
	 $(OBJECTS) \
	 $(OBJ_DIR)/BlockIO$(OBJ_EXT).o \
	 $(OBJ_DIR)/SimpleIO$(OBJ_EXT).o
	 -o $(BIN_DIR)/paracrypt_tests $(TESTS_BIN) $(LIBS)
#


###################################################################################
# BUILDS ##########################################################################
###################################################################################
#
bin_endian_ttable_generator: \
$(OBJ_DIR)/bin_endian_ttable_generator$(OBJ_EXT).o \
$(OBJ_DIR)/endianess$(OBJ_EXT).o
	$(CXX) \
	$(OBJ_DIR)/endianess$(OBJ_EXT).o \
	$(OBJ_DIR)/bin_endian_ttable_generator$(OBJ_EXT).o \
	-o $(BIN_DIR)/bin_endian_ttable_generator
#
builds: tests #library tool #bin_endian_ttable_generator ptx


###################################################################################
# MAKE ############################################################################
###################################################################################
#
clean: 
	rm -f $(OBJ_DIR)/*.o
	rm -f $(OBJ_DIR)/*.ptx
	rm -f $(LIB_DIR)/*.a
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
all: release debug devel
TESTS_BIN_BASE=$(TESTS_BIN)
OBJ_EXT_BASE=$(OBJ_EXT)
CXX_FLAGS_BASE=$(CXX_FLAGS)
NVCC_FLAGS_BASE=$(NVCC_FLAGS)
#
devel: TESTS_BIN=$(TESTS_BIN_BASE)_dev
devel: OBJ_EXT=$(OBJ_EXT_BASE)_dev
devel: CXX_FLAGS_ = $(CXX_FLAGS_BASE) -g -DDEBUG -DDEVEL
devel: NVCC_FLAGS_ = $(NVCC_FLAGS_BASE) -g -DDEBUG -DDEVEL
devel: builds
#
debug: TEST_BIN=$(TESTS_BIN_BASE)_dbg
debug: OBJ_EXT=$(OBJ_EXT_BASE)_dbg
debug: CXX_FLAGS_ = $(CXX_FLAGS_BASE) -g -DDEBUG
debug: NVCC_FLAGS_ = $(NVCC_FLAGS_BASE) -g -DDEBUG
debug: builds
#
release: CXX_FLAGS_ = $(CXX_FLAGS_BASE) -O4 -DNDEBUG
release: NVCC_FLAGS_ = $(NVCC_FLAGS_BASE) -O4
release: builds


###################################################################################
# RUNS ############################################################################
###################################################################################
#
check: tests
	valgrind --leak-check=summary $(BIN_DIR)/paracrypt_tests
	valgrind --leak-check=full --log-file=$(INF_DIR)/leaks.txt $(BIN_DIR)/paracrypt_tests
	valgrind --tool=memcheck ---log-file=$(INF_DIR)/mem.txt  $(BIN_DIR)/paracrypt_tests
	
