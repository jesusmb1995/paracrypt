###################################################################################
# DEFINES #########################################################################
###################################################################################
#
CUDA_PATH ?= /usr/local/cuda
CUDA_LIB ?= $(CUDA_PATH)/lib64
BOOST_PATH ?= /usr
BOOST_LIB ?= $(BOOST_PATH)/lib/boost
#
NVCC ?= $(CUDA_PATH)/bin/nvcc
CXX ?= g++
#
FLAGS ?= 
LIBS ?= "-L$(CUDA_LIB) -lcuda -lcudart"
#
SRC_DIR ?= src
TST_DIR ?= $(SRC_DIR)/tests
BIN_DIR ?= bin
LIB_DIR ?= lib
OBJ_DIR ?= obj
#


###################################################################################
# OBJECTS #########################################################################
###################################################################################
#
AES.o: $(SRC_DIR)/AES.cpp
	$(CXX) $(FLAGS) -c $< -o $(OBJ_DIR)/$@
#
CudaAES.o: $(SRC_DIR)/CudaAES.cu
	$(CXX) $(FLAGS) -c $< -o $(OBJ_DIR)/$@
#
CudaEcbAes16B.o: $(SRC_DIR)/CudaEcbAes16B.cpp
	$(NVCC) $(FLAGS) -c $< -o $(OBJ_DIR)/$@
#
CudaEcbAes16B.kernels.o: $(SRC_DIR)/CudaEcbAes16B.cu
	$(NVCC) $(FLAGS) -c $< -o $(OBJ_DIR)/$@
#
GPUCipherDevice.o: $(SRC_DIR)/GPUCipherDevice.cpp
	$(CXX) $(FLAGS) -c $< -o $(OBJ_DIR)/$@
#
CUDACipherDevice.o: $(SRC_DIR)/CUDACipherDevice.cpp
	$(NVCC) $(FLAGS) -c $< -o $(OBJ_DIR)/$@
#
logging.o: $(SRC_DIR)/logging.cpp
	$(CXX) $(FLAGS) -c $< -o $(OBJ_DIR)/$@


###################################################################################
# TESTS ###########################################################################
###################################################################################
#
AES_key_schedule.o: $(SRC_DIR)/openssl/AES_key_schedule.c
	$(CXX) $(FLAGS) -c $< -o $(OBJ_DIR)/$@
#
tests.o: $(TST_DIR)/tests.cpp
	$(CXX) $(FLAGS) -c $< -o $(OBJ_DIR)/$@
#	
tests: tests.o AES_key_schedule.o
	$(CXX) $(FLAGS) $(OBJ_DIR)/tests.o $(OBJ_DIR)/AES_key_schedule.o \
	 -o $(BIN_DIR)/paracrypt_tests
#


###################################################################################
# BUILDS ##########################################################################
###################################################################################
#


###################################################################################
# MAKE ############################################################################
###################################################################################
#
clean: 
	rm -f $(OBJ_DIR)/*.o
	rm -f $(LIB_DIR)/*.a
	rm -f $(BIN_DIR)/*
	rm -f $(SRC_DIR)/*~
	rm -f $(SRC_DIR)/tests/*~
	rm -f $(SRC_DIR)/openssl/*~
#
all: tests
	
	# make icc
