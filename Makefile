CUDA_PATH ?= "/usr/local/cuda-8.0"
NVCC := $(CUDA_PATH)/bin/nvcc

BOOST_PATH := /usr
BOOST_LIB := $(BOOST_PATH)/lib/boost
FLAGS := 

SRC_DIR = src
BIN_DIR = bin
LIB_DIR = lib
OBJ_DIR = obj

AES.o: $(SRC_DIR)/AES.cpp
	$(NVCC) $(FLAGS) -c $< -o $(OBJ_DIR)/$@

CudaAES.o: $(SRC_DIR)/CudaAES.cu
	$(NVCC) $(FLAGS) -c $< -o $(OBJ_DIR)/$@

AES_key_test.o: $(SRC_DIR)/tests/AES_key_test.cpp
	$(NVCC) $(FLAGS) -c $< -o $(OBJ_DIR)/$@

test: FLAGS += -g
test: AES_key_test.o CudaAES.o AES.o
	$(NVCC) $(FLAGS) $(OBJ_DIR)/AES_key_test.o $(OBJ_DIR)/CudaAES.o \ 
	$(OBJ_DIR)/AES.o -o $(BIN_DIR)/$@

-lboost_test
