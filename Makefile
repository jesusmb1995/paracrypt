CUDA_PATH ?= "/usr/local/cuda-8.0"
BOOST_PATH := /usr
BOOST_LIB := $(BOOST_PATH)/lib/boost

NVCC := $(CUDA_PATH)/bin/nvcc
CXX := g++

FLAGS := 

SRC_DIR = src
TST_DIR = $(SRC_DIR)/tests
BIN_DIR = bin
LIB_DIR = lib
OBJ_DIR = obj

AES.o: $(SRC_DIR)/AES.cpp
	$(NVCC) $(FLAGS) -c $< -o $(OBJ_DIR)/$@

CudaAES.o: $(SRC_DIR)/CudaAES.cu
	$(NVCC) $(FLAGS) -c $< -o $(OBJ_DIR)/$@

AES_key_schedule.o: $(SRC_DIR)/openssl/AES_key_schedule.c
	$(CXX) $(FLAGS) -c $< -o $(OBJ_DIR)/$@
	
reverse_ssl_internal_key.o: $(SRC_DIR)/openssl/reverse_ssl_internal_key.c
	$(CXX) $(FLAGS) -c $< -o $(OBJ_DIR)/$@

tests.o: $(TST_DIR)/tests.cpp
	$(CXX) $(FLAGS) -c $< -o $(OBJ_DIR)/$@
	
tests: tests.o AES_key_schedule.o reverse_ssl_internal_key.o
	$(CXX) $(FLAGS) $(OBJ_DIR)/tests.o $(OBJ_DIR)/AES_key_schedule.o \
	 $(OBJ_DIR)/reverse_ssl_internal_key.o -o $(BIN_DIR)/paracrypt_tests

clean: 
	rm -f $(OBJ_DIR)/*.o
	rm -f $(LIB_DIR)/*.a
	rm -f $(BIN_DIR)/*
