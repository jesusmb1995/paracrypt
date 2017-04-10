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
LIBS ?= -L$(BOOST_LIB) -lboost_system -lboost_log -lboost_log_setup -lboost_thread -lpthread -L$(CUDA_LIB) -lcuda -lcudart
INCL ?= -I$(CUDA_INC)
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
$(OBJ_DIR)/AES.o: $(SRC_DIR)/AES.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@
#
$(OBJ_DIR)/CudaAES.o: $(SRC_DIR)/CudaAES.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes16B.o: $(SRC_DIR)/CudaEcbAes16B.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/CudaEcbAes16B.cu.o: $(SRC_DIR)/CudaEcbAes16B.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@
#
$(OBJ_DIR)/CUDACipherDevice.o: $(SRC_DIR)/CUDACipherDevice.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/logging.o: $(SRC_DIR)/logging.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@
#
$(OBJ_DIR)/logging.d.o: $(SRC_DIR)/logging.cpp 
	$(CXX) $(CXX_FLAGS_) -c $< -o $@
#
$(OBJ_DIR)/AES_key_schedule.o: $(SRC_DIR)/openssl/AES_key_schedule.c
	$(CXX) $(CXX_FLAGS_) -c $< -o $@
#
$(OBJ_DIR)/endianess.o: $(SRC_DIR)/endianess.c
	$(CXX) $(CXX_FLAGS_) -c $< -o $@


###################################################################################
# TESTS ###########################################################################
###################################################################################
#
$(OBJ_DIR)/tests.o: $(TST_DIR)/tests.cpp
	$(CXX) $(CXX_FLAGS_) -c $< -o $@ $(INCL)
#
$(OBJ_DIR)/cuda_test_kernels.cu.o: $(TST_DIR)/cuda_test_kernels.cu
	$(NVCC) $(NVCC_FLAGS_) -c $< -o $@
#
$(OBJ_DIR)/cpu_AES_round_example.o: $(TST_DIR)/cpu_AES_round_example.c
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
cpu_AES_round_example: CXX_FLAGS_ += -g -DDEBUG -DDEVEL
cpu_AES_round_example: \
$(OBJ_DIR)/cpu_AES_round_example.o \
$(OBJ_DIR)/logging.o
	 $(CXX) $(CXX_FLAGS_) \
	 $(OBJ_DIR)/cpu_AES_round_example.o \
	 $(OBJ_DIR)/logging.o \
	 -o $(BIN_DIR)/cpu_AES_round_example $(LIBS)
#
tests: CXX_FLAGS_ += -g -DDEBUG -DDEVEL
tests: NVCC_FLAGS_ += -g -DDEBUG -DDEVEL
tests: \
$(OBJ_DIR)/tests.o \
$(OBJ_DIR)/cuda_test_kernels.cu.o \
$(OBJ_DIR)/AES_key_schedule.o \
$(OBJ_DIR)/endianess.o \
$(OBJ_DIR)/logging.o \
$(OBJ_DIR)/AES.o \
$(OBJ_DIR)/CudaAES.o \
$(OBJ_DIR)/CudaEcbAes16B.o  \
$(OBJ_DIR)/CudaEcbAes16B.cu.o \
$(OBJ_DIR)/CUDACipherDevice.o
	 $(CXX) $(CXX_FLAGS_) \
	 $(OBJ_DIR)/tests.o \
	 $(OBJ_DIR)/cuda_test_kernels.cu.o \
	 $(OBJ_DIR)/AES_key_schedule.o \
	 $(OBJ_DIR)/endianess.o \
	 $(OBJ_DIR)/AES.o \
	 $(OBJ_DIR)/CudaAES.o \
	 $(OBJ_DIR)/CudaEcbAes16B.o \
	 $(OBJ_DIR)/CudaEcbAes16B.cu.o \
	 $(OBJ_DIR)/CUDACipherDevice.o \
	 $(OBJ_DIR)/logging.o \
	 -o $(BIN_DIR)/paracrypt_tests $(LIBS)

#test: CXX_FLAGS_ += -g -DDEBUG
#test: logging.o $(SRC_DIR)/test.cpp
#	$(CXX) $(CXX_FLAGS_) $(OBJ_DIR)/logging.o $(SRC_DIR)/test.cpp  -o $(BIN_DIR)/test $(LIBS)

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
