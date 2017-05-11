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
#
NVCC ?= $(CUDA_PATH)/bin/nvcc
CXX ?= g++
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
#
LIBS ?= -L$(BOOST_LIB) -lboost_system -lboost_log -lboost_log_setup -lboost_thread -lpthread -L$(CUDA_LIB) -lcuda -lcudart
INCL ?= -I$(SRC_DIR) -I$(CUDA_INC)
#


###################################################################################
# OBJECTS #########################################################################
###################################################################################
#
$(OBJ_DIR)/AES.o: $(SRC_DIR)/cipher/AES/AES.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAES.o: $(SRC_DIR)/cipher/AES/CudaAES.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaAESConstant.cu.o: $(SRC_DIR)/cipher/AES/CudaConstant.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes.o: $(SRC_DIR)/cipher/AES/CudaEcbAes.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes16B.o: $(SRC_DIR)/cipher/AES/CudaEcbAes16B.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes16B.cu.o: $(SRC_DIR)/cipher/AES/CudaEcbAes16B.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes16BPtr.o: $(SRC_DIR)/cipher/AES/CudaEcbAes16BPtr.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes16BPtr.cu.o: $(SRC_DIR)/cipher/AES/CudaEcbAes16BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes8B.o: $(SRC_DIR)/cipher/AES/CudaEcbAes8B.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes8B.cu.o: $(SRC_DIR)/cipher/AES/CudaEcbAes8B.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes8BPtr.o: $(SRC_DIR)/cipher/AES/CudaEcbAes8BPtr.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes8BPtr.cu.o: $(SRC_DIR)/cipher/AES/CudaEcbAes8BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes4B.o: $(SRC_DIR)/cipher/AES/CudaEcbAes4B.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes4B.cu.o: $(SRC_DIR)/cipher/AES/CudaEcbAes4B.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes4BPtr.o: $(SRC_DIR)/cipher/AES/CudaEcbAes4BPtr.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes4BPtr.cu.o: $(SRC_DIR)/cipher/AES/CudaEcbAes4BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes1B.o: $(SRC_DIR)/cipher/AES/CudaEcbAes1B.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes1B.cu.o: $(SRC_DIR)/cipher/AES/CudaEcbAes1B.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CUDACipherDevice.o: $(SRC_DIR)/device/CUDACipherDevice.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/logging.o: $(SRC_DIR)/logging.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/logging.d.o: $(SRC_DIR)/logging.cpp 
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/AES_key_schedule.o: $(SRC_DIR)/openssl/AES_key_schedule.c
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/endianess.o: $(SRC_DIR)/endianess.c
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/Timer.o: $(SRC_DIR)/Timer.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#	
$(OBJ_DIR)/bin_endian_ttable_generator.o: $(SRC_DIR)/cipher/AES/big_endian_ttable_generator.cpp
	$(CXX) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/IO.o: $(SRC_DIR)/io/IO.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/BlockIO.o: $(SRC_DIR)/io/BlockIO.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/SimpleIO.o: $(SRC_DIR)/io/SimpleIO.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/SimpleCudaIO.o: $(SRC_DIR)/io/SimpleCudaIO.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/SharedIO.o: $(SRC_DIR)/io/SharedIO.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaSharedIO.o: $(SRC_DIR)/io/CudaSharedIO.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/Pinned.o: $(SRC_DIR)/io/Pinned.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaPinned.o: $(SRC_DIR)/io/CudaPinned.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/Launcher.o: $(SRC_DIR)/Launcher.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#


###################################################################################
# PTX #############################################################################
###################################################################################
#
# Generate PTX assembly code: Might be useful for fine 
#  grain code inspection and optimization
#
$(OBJ_DIR)/CudaEcbAes16B.ptx: $(SRC_DIR)/cipher/AES/CudaEcbAes16B.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaEcbAes16BPtr.ptx: $(SRC_DIR)/cipher/AES/CudaEcbAes16BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaEcbAes8B.ptx: $(SRC_DIR)/cipher/AES/CudaEcbAes8B.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaEcbAes8BPtr.ptx: $(SRC_DIR)/cipher/AES/CudaEcbAes8BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaEcbAes4B.ptx: $(SRC_DIR)/cipher/AES/CudaEcbAes4B.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaEcbAes4BPtr.ptx: $(SRC_DIR)/cipher/AES/CudaEcbAes4BPtr.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
$(OBJ_DIR)/CudaEcbAes1B.ptx: $(SRC_DIR)/cipher/AES/CudaEcbAes1B.cu
	$(NVCC) $(NVCC_FLAGS_) -ptx $< -o $@
#
ptx: \
$(OBJ_DIR)/CudaEcbAes16B.ptx \
$(OBJ_DIR)/CudaEcbAes16BPtr.ptx \
$(OBJ_DIR)/CudaEcbAes8B.ptx \
$(OBJ_DIR)/CudaEcbAes8BPtr.ptx \
$(OBJ_DIR)/CudaEcbAes4B.ptx \
$(OBJ_DIR)/CudaEcbAes4BPtr.ptx \
$(OBJ_DIR)/CudaEcbAes1B.ptx 
#


###################################################################################
# TESTS ###########################################################################
###################################################################################
#
$(OBJ_DIR)/tests.o: $(TST_DIR)/tests.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
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
tests: CXX_FLAGS_ += -g -DDEBUG -DDEVEL
tests: NVCC_FLAGS_ += -g -DDEBUG #-DDEVEL
tests: \
$(OBJ_DIR)/tests.o \
$(OBJ_DIR)/AES_key_schedule.o \
$(OBJ_DIR)/endianess.o \
$(OBJ_DIR)/logging.o \
$(OBJ_DIR)/Timer.o \
$(OBJ_DIR)/AES.o \
$(OBJ_DIR)/CudaAES.o \
$(OBJ_DIR)/CudaAESConstant.cu.o \
$(OBJ_DIR)/CudaEcbAes.o \
$(OBJ_DIR)/CudaEcbAes16B.o  \
$(OBJ_DIR)/CudaEcbAes16B.cu.o \
$(OBJ_DIR)/CudaEcbAes16BPtr.o  \
$(OBJ_DIR)/CudaEcbAes16BPtr.cu.o \
$(OBJ_DIR)/CudaEcbAes8B.o \
$(OBJ_DIR)/CudaEcbAes8B.cu.o \
$(OBJ_DIR)/CudaEcbAes8BPtr.o \
$(OBJ_DIR)/CudaEcbAes8BPtr.cu.o \
$(OBJ_DIR)/CudaEcbAes4B.o \
$(OBJ_DIR)/CudaEcbAes4B.cu.o \
$(OBJ_DIR)/CudaEcbAes4BPtr.o \
$(OBJ_DIR)/CudaEcbAes4BPtr.cu.o \
$(OBJ_DIR)/CudaEcbAes1B.o \
$(OBJ_DIR)/CudaEcbAes1B.cu.o \
$(OBJ_DIR)/CUDACipherDevice.o \
$(OBJ_DIR)/IO.o \
$(OBJ_DIR)/BlockIO.o \
$(OBJ_DIR)/SimpleIO.o \
$(OBJ_DIR)/SimpleCudaIO.o \
$(OBJ_DIR)/SharedIO.o \
$(OBJ_DIR)/CudaSharedIO.o \
$(OBJ_DIR)/Pinned.o \
$(OBJ_DIR)/CudaPinned.o \
$(OBJ_DIR)/Launcher.o
	 $(CXX) $(CXX_FLAGS_) \
	 $(OBJ_DIR)/tests.o \
	 $(OBJ_DIR)/AES_key_schedule.o \
	 $(OBJ_DIR)/endianess.o \
	 $(OBJ_DIR)/AES.o \
	 $(OBJ_DIR)/CudaAESConstant.cu.o \
	 $(OBJ_DIR)/CudaAES.o \
	 $(OBJ_DIR)/CudaEcbAes.o \
	 $(OBJ_DIR)/CudaEcbAes16B.o \
	 $(OBJ_DIR)/CudaEcbAes16B.cu.o \
	 $(OBJ_DIR)/CudaEcbAes16BPtr.o \
	 $(OBJ_DIR)/CudaEcbAes16BPtr.cu.o \
	 $(OBJ_DIR)/CudaEcbAes8B.o \
	 $(OBJ_DIR)/CudaEcbAes8B.cu.o \
	 $(OBJ_DIR)/CudaEcbAes8BPtr.o \
	 $(OBJ_DIR)/CudaEcbAes8BPtr.cu.o \
	 $(OBJ_DIR)/CudaEcbAes4B.o \
	 $(OBJ_DIR)/CudaEcbAes4B.cu.o \
	 $(OBJ_DIR)/CudaEcbAes4BPtr.o \
	 $(OBJ_DIR)/CudaEcbAes4BPtr.cu.o \
	 $(OBJ_DIR)/CudaEcbAes1B.o \
	 $(OBJ_DIR)/CudaEcbAes1B.cu.o \
	 $(OBJ_DIR)/CUDACipherDevice.o \
	 $(OBJ_DIR)/logging.o \
	 $(OBJ_DIR)/Timer.o \
	 $(OBJ_DIR)/IO.o \
	 $(OBJ_DIR)/BlockIO.o \
	 $(OBJ_DIR)/SimpleIO.o \
	 $(OBJ_DIR)/SimpleCudaIO.o \
	 $(OBJ_DIR)/SharedIO.o \
	 $(OBJ_DIR)/CudaSharedIO.o \
	 $(OBJ_DIR)/Pinned.o \
	 $(OBJ_DIR)/CudaPinned.o \
	 $(OBJ_DIR)/Launcher.o \
	 -o $(BIN_DIR)/paracrypt_tests $(LIBS)
#


###################################################################################
# BUILDS ##########################################################################
###################################################################################
#
bin_endian_ttable_generator: \
$(OBJ_DIR)/bin_endian_ttable_generator.o \
$(OBJ_DIR)/endianess.o
	$(CXX) \
	$(OBJ_DIR)/endianess.o \
	$(OBJ_DIR)/bin_endian_ttable_generator.o \
	-o $(BIN_DIR)/bin_endian_ttable_generator
# -DNDEBUG # todo elimina assert


###################################################################################
# MAKE ############################################################################
###################################################################################
#
clean: 
	rm -f $(OBJ_DIR)/*.o
	rm -f $(OBJ_DIR)/*.ptx
	rm -f $(LIB_DIR)/*.a
	rm -f $(BIN_DIR)/*
	rm -f $(SRC_DIR)/*~
	rm -f $(SRC_DIR)/tests/*~
	rm -f $(SRC_DIR)/openssl/*~
#
all: tests
# make icc

