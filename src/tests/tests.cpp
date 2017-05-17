/*
 *  Copyright (C) 2017 Jesus Martin Berlanga. All Rights Reserved.
 *
 *  This file is part of Paracrypt.
 *
 *  Paracrypt is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Paracrypt is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Paracrypt.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define BOOST_TEST_MODULE paracrypt
#include <boost/test/included/unit_test.hpp>
#include <stdint.h>
#include "logging.hpp"
#include "openssl/AES_key_schedule.h"
#include "device/CUDACipherDevice.hpp"
#include "cipher/AES/CudaAes16B.hpp"
#include "cipher/AES/CudaAes16BPtr.hpp"
#include "cipher/AES/CudaAes8B.hpp"
#include "cipher/AES/CudaAes8BPtr.hpp"
#include "cipher/AES/CudaAes4B.hpp"
#include "cipher/AES/CudaAes4BPtr.hpp"
#include "cipher/AES/CudaAes1B.hpp"
#include "endianess.h"
#include "Timer.hpp"
#include "assert.h"
#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */
#include <stdio.h>
#include <fstream>
#include "io/IO.hpp"
#include "io/SharedIO.hpp"
#include "io/SimpleCudaIO.hpp"
#include "io/BlockIO.hpp"
#include "io/CudaSharedIO.hpp"
#include "io/Pinned.hpp"
#include "Launcher.hpp"

int random_data_n_blocks;
unsigned char *random_data;

paracrypt::CUDACipherDevice* gpu;

struct Setup {
	Setup()   {
		// 500KiB to 1Mib
	#define TRD_MIN 512*64
	#define TRD_MAX 1024*64
	#define TRD_DIF (TRD_MAX-TRD_MIN)
		srand (time(NULL));
		random_data_n_blocks = (rand() % TRD_DIF + TRD_MIN); // TRD_DIF + TRD_MIN);
		random_data = (unsigned char*) malloc(random_data_n_blocks*16);
		uint32_t* data_ptr = (uint32_t*)random_data;
		for(int i=0; i < random_data_n_blocks*4; i++) {
			data_ptr[i] = (uint32_t) rand();
		}
		//	boost::log::core::get()->set_filter
		//    (
		//    		boost::log::trivial::severity >= boost::log::trivial::trace
		//    );
		//    return true;
		 gpu = new paracrypt::CUDACipherDevice(0);
  }
  ~Setup()  {
	  free(random_data);
	  delete gpu;
  }
};
BOOST_GLOBAL_FIXTURE( Setup );

// NIST-197 test vectors
typedef struct tv {
	const unsigned char input[16];
	const unsigned char key[256];
	const unsigned char output[16];
	const int key_bits;
} tv;

const tv aes_example = {
		.input = {
				0x32U, 0x43U, 0xf6U, 0xa8U,
				0x88U, 0x5aU, 0x30U, 0x8dU,
				0x31U, 0x31U, 0x98U, 0xa2U,
				0xe0U, 0x37U, 0x07U, 0x34U
		},
		.key = {
				0x2bU, 0x7eU, 0x15U, 0x16U,
				0x28U, 0xaeU, 0xd2U, 0xa6U,
				0xabU, 0xf7U, 0x15U, 0x88U,
				0x09U, 0xcfU, 0x4fU, 0x3cU
		},
		.output = {
				0x39U, 0x25U, 0x84U, 0x1dU,
				0x02U, 0xdcU, 0x09U, 0xfbU,
				0xdcU, 0x11U, 0x85U, 0x97U,
				0x19U, 0x6aU, 0x0bU, 0x32U
		},
		.key_bits = 128
};

const tv aes_192_tv = {
		.input = {
				0x00U, 0x11U, 0x22U, 0x33U,
				0x44U, 0x55U, 0x66U, 0x77U,
				0x88U, 0x99U, 0xaaU, 0xbbU,
				0xccU, 0xddU, 0xeeU, 0xffU
		},
		.key = {
				0x00U, 0x01U, 0x02U, 0x03U,
				0x04U, 0x05U, 0x06U, 0x07U,
				0x08U, 0x09U, 0x0aU, 0x0bU,
				0x0cU, 0x0dU, 0x0eU, 0x0fU,
				0x10U, 0x11U, 0x12U, 0x13U,
				0x14U, 0x15U, 0x16U, 0x17U
		},
		.output = {
				0xddU, 0xa9U, 0x7cU, 0xa4U,
				0x86U, 0x4cU, 0xdfU, 0xe0U,
				0x6eU, 0xafU, 0x70U, 0xa0U,
				0xecU, 0x0dU, 0x71U, 0x91U
		},
		.key_bits = 192
};

const tv aes_256_tv = {
		.input = {
				0x00U, 0x11U, 0x22U, 0x33U,
				0x44U, 0x55U, 0x66U, 0x77U,
				0x88U, 0x99U, 0xaaU, 0xbbU,
				0xccU, 0xddU, 0xeeU, 0xffU
		},
		.key = {
				0x00U, 0x01U, 0x02U, 0x03U,
				0x04U, 0x05U, 0x06U, 0x07U,
				0x08U, 0x09U, 0x0aU, 0x0bU,
				0x0cU, 0x0dU, 0x0eU, 0x0fU,
				0x10U, 0x11U, 0x12U, 0x13U,
				0x14U, 0x15U, 0x16U, 0x17U,
				0x18U, 0x19U, 0x1aU, 0x1bU,
				0x1cU, 0x1dU, 0x1eU, 0x1fU
		},
		.output = {
				0x8eU, 0xa2U, 0xb7u, 0xcaU,
				0x51U, 0x67U, 0x45U, 0xbfU,
				0xeaU, 0xfcU, 0x49U, 0x90U,
				0x4bU, 0x49U, 0x60U, 0x89U
		},
		.key_bits = 256
};

tv get_aes_tv(unsigned int key_bits) {
	switch(key_bits) {
	case 128:
		return aes_example;
		break;
	case 192:
		return aes_192_tv;
		break;
	case 256:
		return aes_256_tv;
		break;
	default:
		ERR("Wrong AES key size");
	}
}

/*
 * Encrypts a random input string, decrypts it,
 * and checks if the result is the same original
 * string.
 */
void AES_RDN_TEST(std::string title, tv vector_key, paracrypt::CudaAES* aes, paracrypt::CUDACipherDevice* dev, int key_bits, bool constantKey, bool constantTables)
{
	int data_length = random_data_n_blocks*16;
    unsigned char *result = (unsigned char*) malloc(data_length);

    aes->constantKey(constantKey);
    aes->constantTables(constantTables);
    aes->setKey(vector_key.key,vector_key.key_bits);
    aes->setDevice(dev);
    aes->malloc(random_data_n_blocks);

    Timer* t = new Timer();
    t->tic();
    aes->encrypt(random_data, result, random_data_n_blocks);
    double sec = t->toc_seconds();
    LOG_INF(boost::format("%s needs %f seconds to encrypt %d blocks\n") % title.c_str() % sec % random_data_n_blocks);
    for(int i=0;i<random_data_n_blocks*4;i++) {
    	//LOG_TRACE(boost::format("block %d") % i);
    	BOOST_REQUIRE(((uint32_t*)result)[i] != ((uint32_t*)random_data)[i]);
    }

    t->tic();
    aes->decrypt(result, result, random_data_n_blocks);
    sec = t->toc_seconds();
    LOG_INF(boost::format("%s needs %f seconds to decrypt %d blocks\n") % title.c_str() % sec % random_data_n_blocks);

   	BOOST_CHECK_EQUAL_COLLECTIONS((uint32_t*)result,((uint32_t*)result)+random_data_n_blocks,((uint32_t*)random_data),((uint32_t*)random_data)+random_data_n_blocks);
    free(result);
}

void AES_VECTOR_RDN_TEST(std::string title, tv vector_key, paracrypt::CudaAES* aes, paracrypt::CUDACipherDevice* dev, int key_bits, bool constantKey, bool constantTables)
{
	int data_length = random_data_n_blocks*16;
	unsigned char *result = (unsigned char*) malloc(data_length);
    for(int i=0; i < random_data_n_blocks; i++) {
    	memcpy(result+(i*16),vector_key.input,16);
    }

    aes->constantKey(constantKey);
    aes->constantTables(constantTables);
    aes->setKey(vector_key.key,vector_key.key_bits);
    aes->setDevice(dev);
    aes->malloc(random_data_n_blocks);

    Timer* t = new Timer();
    t->tic();
    aes->encrypt(result, result, random_data_n_blocks);
    double sec = t->toc_seconds();
    LOG_INF(boost::format("%s needs %f seconds to encrypt %d blocks\n") % title.c_str() % sec % random_data_n_blocks);
    for(int i=0;i<random_data_n_blocks*4;i++) {
    	//LOG_TRACE(boost::format("block %d") % i);
    	BOOST_REQUIRE_EQUAL(((uint32_t*)result)[i], ((uint32_t*)vector_key.output)[i%4]);
    }

    t->tic();
    aes->decrypt(result, result, random_data_n_blocks);
    sec = t->toc_seconds();
    LOG_INF(boost::format("%s needs %f seconds to decrypt %d blocks\n") % title.c_str() % sec % random_data_n_blocks);

    for(int i=0;i<random_data_n_blocks*4;i++) {
    	//LOG_TRACE(boost::format("block %d") % i);
    	BOOST_REQUIRE_EQUAL(((uint32_t*)result)[i], ((uint32_t*)vector_key.input)[i%4]);
    }
    free(result);
}

void AES_SB_ENCRYPT_TEST(std::string title, tv vector, int n_blocks, paracrypt::CudaAES* aes, paracrypt::CUDACipherDevice* dev, bool constantKey, bool constantTables)
{
	LOG_TRACE(boost::format("Executing %s...") % title.c_str());
    unsigned char data[16*n_blocks];
    for(int i=0; i < n_blocks; i++) {
    	memcpy(data+(i*16),vector.input,16);
    }

    aes->setKey(vector.key,vector.key_bits);
    aes->setDevice(dev);
    aes->constantKey(constantKey);
    aes->constantTables(constantTables);
    aes->malloc(n_blocks);
    aes->encrypt((unsigned char *) &data, (unsigned char *) &data, n_blocks);
    aes->waitFinish();

    // first block hexdump
    hexdump("expected",vector.output,16);
    hexdump("data",data,16);

    for(int i=0; i < n_blocks; i++) {
    	BOOST_REQUIRE_EQUAL_COLLECTIONS(data+(i*16),data+(i*16)+16,vector.output,vector.output+16);
    }
}

void AES_SB_DECRYPT_TEST(std::string title, tv vector, int n_blocks, paracrypt::CudaAES* aes, paracrypt::CUDACipherDevice* dev, bool constantKey, bool constantTables)
{
	LOG_TRACE(boost::format("Executing %s...") % title.c_str());
    unsigned char data[16*n_blocks];
    for(int i=0; i < n_blocks; i++) {
    	memcpy(data+(i*16),vector.output,16);
    }

    aes->setKey(vector.key,vector.key_bits);
    aes->setDevice(dev);
    aes->constantKey(constantKey);
    aes->constantTables(constantTables);
    aes->malloc(n_blocks);
    aes->decrypt((unsigned char *) &data, (unsigned char *) &data, n_blocks);
    aes->waitFinish();

    // first block hexdump
    hexdump("expected",vector.input,16);
    hexdump("data",data,16);

    for(int i=0; i < n_blocks; i++) {
    	BOOST_REQUIRE_EQUAL_COLLECTIONS(data+(i*16),data+(i*16)+16,vector.input,vector.input+16);
    }
}

#define AES_TEST_SUITE_KEYSIZE(id, testName, className, tv, keyBitsStr) \
	BOOST_AUTO_TEST_SUITE(id) \
		BOOST_AUTO_TEST_CASE(kc_tc_single) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_SB_ENCRYPT_TEST("AES"keyBitsStr"-ECB example vector | " testName " with constant key and t-table", \
					tv,1,aes,gpu,true,true); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(kc_tc_single_decrypt) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_SB_DECRYPT_TEST( "AES"keyBitsStr"-ECB example decrypt vector | " testName " with constant key and t-table", \
					tv,1,aes,gpu,true,true); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(kc_tc_2blocks) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_SB_ENCRYPT_TEST( "AES"keyBitsStr"-ECB example vector | " testName " with constant key and t-table", \
					tv,2,aes,gpu,true,true); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(kc_tc_2blocks_decrypt) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_SB_DECRYPT_TEST( "AES"keyBitsStr"-ECB example decrypt vector | " testName " with constant key and t-table", \
					tv,2,aes,gpu,true,true); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(kc_tc_nblocks) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_VECTOR_RDN_TEST( "AES"keyBitsStr"-ECB (" testName ") n blocks with and constant key and t-table", \
					tv,aes,gpu,128,true,true); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(kc_nblocks) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_VECTOR_RDN_TEST( "AES"keyBitsStr"-ECB (" testName ") n blocks with and constant key", \
					tv,aes,gpu,128,true,false); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(tc_nblocks) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_VECTOR_RDN_TEST( "AES"keyBitsStr"-ECB (" testName ") n blocks with and constant t-table", \
					tv,aes,gpu,128,false,true); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(nblocks) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_VECTOR_RDN_TEST( "AES"keyBitsStr"-ECB (" testName ") n blocks with and dynamic key and t-table", \
					tv,aes,gpu,128,false,false); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(kc_tc_random) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_RDN_TEST( "AES"keyBitsStr"-ECB (" testName ") with random data and constant key and t-table", \
					tv,aes,gpu,128,true,true); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(kc_random) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_RDN_TEST( "AES"keyBitsStr"-ECB (" testName ") with random data and constant key", \
					tv,aes,gpu,128,true,false); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(tc_random) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_RDN_TEST( "AES"keyBitsStr"-ECB (" testName ") with random data and constant t-table", \
					tv,aes,gpu,128,false,true); \
			delete aes; \
		} \
		BOOST_AUTO_TEST_CASE(random) \
		{ \
			paracrypt::CudaAES * aes = new className; \
			AES_RDN_TEST( "AES"keyBitsStr"-ECB (" testName ") with random data and dynamic key and t-table", \
					tv,aes,gpu,128,false,false); \
			delete aes; \
		} \
	BOOST_AUTO_TEST_SUITE_END()

#define AES_TEST_SUITE(id, testName, className) \
	BOOST_AUTO_TEST_SUITE(id) \
		AES_TEST_SUITE_KEYSIZE(AES128, testName, className, aes_example, "128"); \
		AES_TEST_SUITE_KEYSIZE(AES192, testName, className, aes_192_tv, "192"); \
		AES_TEST_SUITE_KEYSIZE(AES256, testName, className, aes_256_tv, "256"); \
	BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(CUDA_AES)
	AES_TEST_SUITE(CUDA_AES_16B, "16B parallelism", paracrypt::CudaAES16B());
	AES_TEST_SUITE(CUDA_AES_16B_PTR, "16B (ptr) parallelism", paracrypt::CudaAES16BPtr());
	AES_TEST_SUITE(CUDA_AES_8B, "8B parallelism", paracrypt::CudaAES8B());
	AES_TEST_SUITE(CUDA_AES_8B_PTR, "8B (ptr) parallelism", paracrypt::CudaAES8BPtr());
	AES_TEST_SUITE(CUDA_AES_4B, "4B parallelism", paracrypt::CudaAES4B());
	AES_TEST_SUITE(CUDA_AES_4B_PTR, "4B (ptr) parallelism", paracrypt::CudaAES4BPtr());
	AES_TEST_SUITE(CUDA_AES_1B, "1B parallelism", paracrypt::CudaAES1B());
BOOST_AUTO_TEST_SUITE_END()

//
// - Creates a input file where each (word) block value is its index except
//   for the last block which can be half-empty. In this case each
//   byte value of the last block is its byte index.
//
//   Block size is 128 bits
//
void GEN_128BPB_IO_FILES(
		std::string *inFileName,
		std::fstream **inFile,
		std::string *outFileName,
		std::fstream **outFile,
		unsigned int blockSize,
		std::streampos totalNBytes,
		bool print=false
){
	{
		char nameBuffer [L_tmpnam];
		std::tmpnam (nameBuffer);
		(*inFileName) = std::string(nameBuffer);
		std::tmpnam (nameBuffer);
		(*outFileName) = std::string(nameBuffer);
	}

	(*inFile) = new std::fstream(inFileName->c_str(),std::fstream::out | std::fstream::binary);
	if(!(*inFile)) {
		FATAL(boost::format("Error creating test input file: %s\n") % strerror(errno));
	}
	(*outFile) = new std::fstream(outFileName->c_str(),std::fstream::out | std::fstream::binary);
	if(!(*outFile)) {
		FATAL(boost::format("Error creating test input file: %s\n") % strerror(errno));
	}

	uint32_t buffer[4];
	std::streampos nBlocks = totalNBytes / blockSize;
	unsigned int remainingBytes = totalNBytes % blockSize;
	for(uint32_t i = 0; i < nBlocks; i++) {
		buffer[0] = i;
		buffer[1] = i;
		buffer[2] = i;
		buffer[3] = i;
		(*inFile)->write((const char*) buffer,4*4);
	}
	for(uint8_t i = 0; i < remainingBytes; i++) {
		(*inFile)->write((const char*) &i,1);
	}
	(*inFile)->flush();
	if(print)
		fdump("input file",*inFileName);
}
void CLOSE_IO_FILES(std::fstream** inFile, std::fstream** outFile)
{
	(*inFile)->close();
	(*outFile)->close();
	delete (*inFile);
	delete (*outFile);
}
//
// - Reads the file using a SharedIO object and checks the read
//    value is correct. Then multiplies the value by two and write
//    it to the output file using the SharedIO object. The first byte
//    of the padding block is incremented by one.
//
// - Finally checks that the output file is correct.
//
void OUT_FILE_128BPB_CORRECTNESS_TEST(
		std::string outFilename,
		std::streampos begin,
		std::streampos end,
		std::streamsize maxBlockRead,
		bool reachPadding,
		const unsigned int remainingBytes,
		uint8_t paddingSize,
		paracrypt::BlockIO::paddingScheme p
){
	char nameBuffer [L_tmpnam];
	std::tmpnam (nameBuffer); // dummy file
	paracrypt::SimpleIO *io = new paracrypt::SimpleCudaIO(outFilename,nameBuffer,16,AUTO_IO_BUFFER_LIMIT,begin,end);
	io->setPadding(paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT);
	paracrypt::BlockIO::chunk c;
	c.status = paracrypt::BlockIO::OK;
	uint32_t check[4];
	unsigned char* checkPtr = (unsigned char*) check;

	// check read correctness and use write interface
	while(c.status == paracrypt::SharedIO::OK) {
		c = io->read();
		uint32_t entireBlocks = remainingBytes > 0 ? c.nBlocks-1 : c.nBlocks;
		// verify n-1 blocks
		for(uint32_t i = 0; i < entireBlocks; i++) {
			uint32_t blockIndex = ((uint32_t) c.blockOffset) + i;
			check[0] = check[1] = check[2] = check[3] = blockIndex*2;
			BOOST_REQUIRE_EQUAL_COLLECTIONS(
					checkPtr, checkPtr+16,
					c.data+i*16, c.data+i*16+16
			);
		}
		if(c.status == paracrypt::SharedIO::END && reachPadding && remainingBytes > 0) {
			std::streampos byteIndex;
			for(uint8_t i = 0; i < remainingBytes; i++) {
				byteIndex = (c.nBlocks-1)*16 + i;
				if(i == 0) {
					BOOST_REQUIRE_EQUAL(i+1,c.data[byteIndex]);
				}
				else
					BOOST_REQUIRE_EQUAL(i,c.data[byteIndex]);
			}
			// verify padding correctness
			for(uint8_t i = remainingBytes; i < 16; i++) {
				byteIndex = (c.nBlocks-1)*16 + i;
				BOOST_REQUIRE_EQUAL(0,c.data[byteIndex]);
			}
		}
	}

	delete io;
}
void FILE_128BPB_IO_TEST(std::fstream *inFile, std::fstream *outFile, paracrypt::BlockIO* io, bool print=false)
{
	unsigned int blockSize = io->getBlockSize();
	std::streamsize maxBlockRead = io->getMaxBlocksRead();
	std::streampos begin = io->getBegin();
	std::streampos end = io->getEnd();
	paracrypt::BlockIO::paddingScheme p = io->getPadding();
	const std::streamsize inFSize = paracrypt::IO::fileSize((std::ifstream*)inFile);
	const unsigned int remainingBytes = inFSize % blockSize; // last block bytes
	uint8_t paddingSize = 16-remainingBytes;
	// end must be at the last remaining Bytes
	bool reachPadding = remainingBytes > 0 && (end == NO_RANDOM_ACCESS || end >= inFSize-((std::streampos)paddingSize));
	std::streamsize totalBlocksRead = 0;

	if(blockSize != 16) {
		FATAL("FILE_128BPB_SIMPLEIO_TEST can only accept a SimpleIO object with 128 bits (16B) block size.");
	} else {
		paracrypt::BlockIO::chunk c;
		c.status = paracrypt::BlockIO::OK;
		uint32_t check[4];
		unsigned char* checkPtr = (unsigned char*) check;

		// check read correctness and use write interface
		while(c.status == paracrypt::SharedIO::OK) {
			c = io->read();
			uint32_t entireBlocks = reachPadding && c.status == paracrypt::SharedIO::END ? c.nBlocks-1 : c.nBlocks;
			// verify n-1 blocks
			for(uint32_t i = 0; i < entireBlocks; i++) {
				totalBlocksRead++;
				uint32_t blockIndex = ((uint32_t) c.blockOffset) + i;
				check[0] = check[1] = check[2] = check[3] = blockIndex;
				BOOST_REQUIRE_EQUAL_COLLECTIONS(
						checkPtr, checkPtr+16,
						c.data+i*16, c.data+i*16+16
				);
				// multiply by 2 each read word
				*((uint32_t*)(c.data+i*16+0 )) *= 2;
				*((uint32_t*)(c.data+i*16+4 )) *= 2;
				*((uint32_t*)(c.data+i*16+8 )) *= 2;
				*((uint32_t*)(c.data+i*16+12)) *= 2;
			}
			if(c.status == paracrypt::SharedIO::END && reachPadding) {
				totalBlocksRead++;
				std::streampos byteIndex;
				for(uint8_t i = 0; i < remainingBytes; i++) {
					byteIndex = (c.nBlocks-1)*16 + i;
					BOOST_REQUIRE_EQUAL(i,c.data[byteIndex]);
				}
				// verify padding correctness
				for(uint8_t i = remainingBytes; i < 16; i++) {
					byteIndex = (c.nBlocks-1)*16 + i;
					if(p == paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT) {
						BOOST_REQUIRE_EQUAL(0,c.data[byteIndex]);
					} else if(p == paracrypt::BlockIO::PKCS7)  {
						BOOST_REQUIRE_EQUAL(paddingSize,c.data[byteIndex]);
					}
				}
				// increment by one first byte of the padding block
				c.data[(c.nBlocks-1)*16]++;
			}
			if(totalBlocksRead > 0) {
				io->dump(c);
			}
		}

		std::string outFilename = io->getOutFileName();
		delete io; // data flushed when IO object is destructed

		// Check write correctness reading the file
		//  with a SimpleIO object.
		if(print)
			fdump("output file",outFilename);
		const std::streamsize outFSize = paracrypt::IO::fileSize((std::ifstream*)outFile);
		std::streamsize expectedSize = 0;
		if(totalBlocksRead != 0) {
			if(remainingBytes > 0) {
				expectedSize = (totalBlocksRead-1)*16+remainingBytes;
			}
			else {
				expectedSize = totalBlocksRead*16;
			}

//			if(p == paracrypt::BlockIO::PKCS7) {
//				expectedSize = end != NO_RANDOM_ACCESS && end < inFSize ? (std::streamsize) end : inFSize;
//			} else if(p == paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT) {
//				expectedSize = begin != NO_RANDOM_ACCESS ? ((std::streamsize)begin)+totalBlocksRead*16 : totalBlocksRead*16;
//			}
		}
		BOOST_REQUIRE_EQUAL(expectedSize,outFSize);

		OUT_FILE_128BPB_CORRECTNESS_TEST(
				outFilename,
				begin,end,
				maxBlockRead,
				reachPadding,
				remainingBytes,
				paddingSize, p
		);
	}
}
void FILE_128BPB_SIMPLEIO_TEST(
		std::streampos totalNBytes,
		paracrypt::BlockIO::paddingScheme p = paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT,
		std::streampos begin = NO_RANDOM_ACCESS,
		std::streampos end = NO_RANDOM_ACCESS,
		rlim_t bufferSizeLimit = AUTO_IO_BUFFER_LIMIT,
		bool time = false
){
	Timer* t = NULL;
	if(time) {
		t = new Timer();
		t->tic();
	}
	std::string inFileName, outFileName;
	std::fstream *inFile, *outFile;
	bool genPrintFiles = true;
	if(totalNBytes > 16*3) {
		genPrintFiles = false;
	}
	GEN_128BPB_IO_FILES(&inFileName,&inFile,&outFileName,&outFile,16,totalNBytes,genPrintFiles);
	paracrypt::SimpleIO *io = new paracrypt::SimpleCudaIO(inFileName,outFileName,16,bufferSizeLimit,begin,end);
	io->setPadding(p);
	FILE_128BPB_IO_TEST(inFile,outFile,io,genPrintFiles); // destructs io
	CLOSE_IO_FILES(&inFile,&outFile);
	if(time) {
		double cpuSec = t->toc_seconds();
		LOG_INF(boost::format("Test completed in %f CPU seconds\n") % cpuSec);
		delete t;
	}
}
void FILE_128BPB_SHAREDIO_TEST(
		std::streampos totalNBytes,
		unsigned int nChunks,
		paracrypt::BlockIO::paddingScheme p = paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT,
		std::streampos begin = NO_RANDOM_ACCESS,
		std::streampos end = NO_RANDOM_ACCESS,
		rlim_t bufferSizeLimit = AUTO_IO_BUFFER_LIMIT,
		bool time = false
){
	Timer* t = NULL;
	if(time) {
		t = new Timer();
		t->tic();
	}
	std::string inFileName, outFileName;
	std::fstream *inFile, *outFile;
	bool genPrintFiles = true;
	if(totalNBytes > 16*3) {
		genPrintFiles = false;
	}
	GEN_128BPB_IO_FILES(&inFileName,&inFile,&outFileName,&outFile,16,totalNBytes,genPrintFiles);
	paracrypt::CudaSharedIO *io = new paracrypt::CudaSharedIO(inFileName,outFileName,16,nChunks,bufferSizeLimit,begin,end);
	io->setPadding(p);
	FILE_128BPB_IO_TEST(inFile,outFile,io,genPrintFiles); // destructs io
	CLOSE_IO_FILES(&inFile,&outFile);
	if(time) {
		double cpuSec = t->toc_seconds();
		LOG_INF(boost::format("Test completed in %f CPU seconds\n") % cpuSec);
		delete t;
	}
}

//void FILE_128BPB_SIMPLEIO_TEST(std::iostream inFile, std::iostream outFile, paracrypt::SimpleIO io)
//{
//	unsigned int blockSize = io.getBlockSize();
//	if(blockSize != 16) {
//		LOG_FATAL("FILE_128BPB_SIMPLEIO_TEST can only accept a SimpleIO object with 128 bits (16B) block size.");
//	} else {
//		const std::streampos inFSize = fileSize(inFile);
//		const std::streampos numberOfEntireBlocks = inFSize / blockSize;
//
//		const unsigned int nBuffers = io.getNBuffers();
//		char* data;
//		unsigned int nBlocks;
//		unsigned int offset;
//		paracrypt::SharedIO::readStatus status = paracrypt::SharedIO::readStatus::OK;
//		while(status == paracrypt::SharedIO::readStatus::OK) {
//			for(int i = 0; status == paracrypt::SharedIO::readStatus::OK && i < nBuffers; i++) {
//				nBlocks = io.read(i,&data,&offset,&status);
//				for(int j = 0; j < nBlocks; j++) {
//
//				}
//			}
//		}
//	}
//}

BOOST_AUTO_TEST_SUITE(IO)
	BOOST_AUTO_TEST_SUITE(simple_CUDA_IO)
		BOOST_AUTO_TEST_SUITE(simple_CUDA_IO_unlimited)
			BOOST_AUTO_TEST_CASE(just_three_blocks) { FILE_128BPB_SIMPLEIO_TEST(16*3); }
			BOOST_AUTO_TEST_CASE(two_blocks_and_zero_padding) { FILE_128BPB_SIMPLEIO_TEST(16*2+3,paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT); }
			BOOST_AUTO_TEST_CASE(two_blocks_and_PKCS7_padding) { FILE_128BPB_SIMPLEIO_TEST(16*2+3,paracrypt::BlockIO::PKCS7); }
			BOOST_AUTO_TEST_CASE(byte_and_PKCS7_padding) { FILE_128BPB_SIMPLEIO_TEST(1,paracrypt::BlockIO::PKCS7); }
			BOOST_AUTO_TEST_CASE(nothing) { FILE_128BPB_SIMPLEIO_TEST(0); }
			BOOST_AUTO_TEST_CASE(random_access_second_of_three) { FILE_128BPB_SIMPLEIO_TEST(16*3,paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT,16,32); }
			BOOST_AUTO_TEST_CASE(random_access_zero_padding) { FILE_128BPB_SIMPLEIO_TEST(16+3,paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT,16,19); }
			BOOST_AUTO_TEST_CASE(random_access_PKCS7_padding) { FILE_128BPB_SIMPLEIO_TEST(16+3,paracrypt::BlockIO::PKCS7,16,19); }
			BOOST_AUTO_TEST_CASE(random_access_eof) { FILE_128BPB_SIMPLEIO_TEST(16,paracrypt::BlockIO::PKCS7,16,32); }
			BOOST_AUTO_TEST_CASE(PKCS7_padding_50MBFile) {
				FILE_128BPB_SIMPLEIO_TEST(50*1000*1000,paracrypt::BlockIO::PKCS7,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,AUTO_IO_BUFFER_LIMIT,true);
			}
		BOOST_AUTO_TEST_SUITE_END()
		BOOST_AUTO_TEST_SUITE(simple_CUDA_IO_1block_buffer)
			BOOST_AUTO_TEST_CASE(just_three_blocks) { FILE_128BPB_SIMPLEIO_TEST(16*3,paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16); }
			BOOST_AUTO_TEST_CASE(two_blocks_and_zero_padding) { FILE_128BPB_SIMPLEIO_TEST(16*2+3,paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16); }
			BOOST_AUTO_TEST_CASE(two_blocks_and_PKCS7_padding) { FILE_128BPB_SIMPLEIO_TEST(16*2+3,paracrypt::BlockIO::PKCS7,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16); }
			BOOST_AUTO_TEST_CASE(byte_and_PKCS7_padding) { FILE_128BPB_SIMPLEIO_TEST(1,paracrypt::BlockIO::PKCS7,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16); }
			BOOST_AUTO_TEST_CASE(nothing) { FILE_128BPB_SIMPLEIO_TEST(0,paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16); }
			BOOST_AUTO_TEST_CASE(random_access_second_of_three) { FILE_128BPB_SIMPLEIO_TEST(16*3,paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT,16,32,16); }
			BOOST_AUTO_TEST_CASE(random_access_zero_padding) { FILE_128BPB_SIMPLEIO_TEST(16+3,paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT,16,19,16); }
			BOOST_AUTO_TEST_CASE(random_access_PKCS7_padding) { FILE_128BPB_SIMPLEIO_TEST(16+3,paracrypt::BlockIO::PKCS7,16,19.16); }
			BOOST_AUTO_TEST_CASE(random_access_eof) { FILE_128BPB_SIMPLEIO_TEST(16,paracrypt::BlockIO::PKCS7,16,32,16); }
			BOOST_AUTO_TEST_CASE(PKCS7_padding_50MBFile) {
				FILE_128BPB_SIMPLEIO_TEST(50*1000*1000,paracrypt::BlockIO::PKCS7,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16,true);
			}
		BOOST_AUTO_TEST_SUITE_END()
		BOOST_AUTO_TEST_SUITE(simple_CUDA_IO_10block_buffer)
			BOOST_AUTO_TEST_CASE(PKCS7_padding_50MBFile) {
				FILE_128BPB_SIMPLEIO_TEST(50*1000*1000,paracrypt::BlockIO::PKCS7,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,160,true);
			}
		BOOST_AUTO_TEST_SUITE_END()
		BOOST_AUTO_TEST_SUITE(simple_CUDA_IO_100block_buffer)
			BOOST_AUTO_TEST_CASE(PKCS7_padding_50MBFile) {
				FILE_128BPB_SIMPLEIO_TEST(50*1000*1000,paracrypt::BlockIO::PKCS7,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,1600,true);
			}
		BOOST_AUTO_TEST_SUITE_END()
	BOOST_AUTO_TEST_SUITE_END()

	BOOST_AUTO_TEST_SUITE(shared_CUDA_IO)
		BOOST_AUTO_TEST_SUITE(shared_CUDA_IO_unlimited)
			BOOST_AUTO_TEST_CASE(just_three_blocks) { FILE_128BPB_SHAREDIO_TEST(16*3,4); }
			BOOST_AUTO_TEST_CASE(two_blocks_and_zero_padding) { FILE_128BPB_SHAREDIO_TEST(16*2+3,4,paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT); }
			BOOST_AUTO_TEST_CASE(two_blocks_and_PKCS7_padding) { FILE_128BPB_SHAREDIO_TEST(16*2+3,4,paracrypt::BlockIO::PKCS7); }
			BOOST_AUTO_TEST_CASE(byte_and_PKCS7_padding) { FILE_128BPB_SHAREDIO_TEST(1,4,paracrypt::BlockIO::PKCS7); }
			BOOST_AUTO_TEST_CASE(nothing) { FILE_128BPB_SHAREDIO_TEST(0,4); }
			BOOST_AUTO_TEST_CASE(random_access_second_of_three) { FILE_128BPB_SHAREDIO_TEST(16*3,4,paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT,16,32); }
			BOOST_AUTO_TEST_CASE(random_access_zero_padding) { FILE_128BPB_SHAREDIO_TEST(16+3,4,paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT,16,19); }
			BOOST_AUTO_TEST_CASE(random_access_PKCS7_padding) { FILE_128BPB_SHAREDIO_TEST(16+3,4,paracrypt::BlockIO::PKCS7,16,19); }
			BOOST_AUTO_TEST_CASE(random_access_eof) { FILE_128BPB_SHAREDIO_TEST(16,4,paracrypt::BlockIO::PKCS7,16,32); }
			BOOST_AUTO_TEST_CASE(PKCS7_padding_50MBFile) {
				FILE_128BPB_SHAREDIO_TEST(50*1000*1000,4,paracrypt::BlockIO::PKCS7,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,AUTO_IO_BUFFER_LIMIT,true);
			}
		BOOST_AUTO_TEST_SUITE_END()
		BOOST_AUTO_TEST_SUITE(shared_CUDA_IO_4block_buffer)
			BOOST_AUTO_TEST_CASE(just_three_blocks) { FILE_128BPB_SHAREDIO_TEST(16*3,4,paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16*4); }
			BOOST_AUTO_TEST_CASE(two_blocks_and_zero_padding) { FILE_128BPB_SHAREDIO_TEST(16*2+3,4,paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16*4); }
			BOOST_AUTO_TEST_CASE(two_blocks_and_PKCS7_padding) { FILE_128BPB_SHAREDIO_TEST(16*2+3,4,paracrypt::BlockIO::PKCS7,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16*4); }
			BOOST_AUTO_TEST_CASE(byte_and_PKCS7_padding) { FILE_128BPB_SHAREDIO_TEST(1,4,paracrypt::BlockIO::PKCS7,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16*4); }
			BOOST_AUTO_TEST_CASE(nothing) { FILE_128BPB_SHAREDIO_TEST(0,4,paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT,
					NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16*4); }
			BOOST_AUTO_TEST_CASE(random_access_second_of_three) { FILE_128BPB_SHAREDIO_TEST(16*3,4,paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT,16,32,16*4); }
			BOOST_AUTO_TEST_CASE(random_access_zero_padding) { FILE_128BPB_SHAREDIO_TEST(16+3,4,paracrypt::BlockIO::APPEND_ZEROS_TO_INPUT,16,19,16*4); }
			BOOST_AUTO_TEST_CASE(random_access_PKCS7_padding) { FILE_128BPB_SHAREDIO_TEST(16+3,4,paracrypt::BlockIO::PKCS7,16,19.16*4); }
			BOOST_AUTO_TEST_CASE(random_access_eof) { FILE_128BPB_SHAREDIO_TEST(16,4,paracrypt::BlockIO::PKCS7,16,32,16*4); }
		BOOST_AUTO_TEST_SUITE_END()
		BOOST_AUTO_TEST_SUITE(shared_CUDA_IO_80block_buffer)
			BOOST_AUTO_TEST_CASE(PKCS7_padding_50MBFile) {
				FILE_128BPB_SHAREDIO_TEST(50*1000*1000,4,paracrypt::BlockIO::PKCS7,NO_RANDOM_ACCESS,NO_RANDOM_ACCESS,16*80,true);
			}
		BOOST_AUTO_TEST_SUITE_END()
	BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE_END()


void GEN_AES_TEST_FILE(
		std::string *fileName,
		std::fstream **file, // WARNING: Must be closed by the caller
		const char* testData,
		unsigned int blockSize,
		unsigned int nBlocks
){
	{
		char nameBuffer [L_tmpnam];
		std::tmpnam (nameBuffer);
		(*fileName) = std::string(nameBuffer);
	}

	(*file) = new std::fstream(fileName->c_str(),std::fstream::out | std::fstream::binary);
	if(!(*file)) {
		FATAL(boost::format("Error creating test file: %s\n") % strerror(errno));
	}
    for(unsigned int i=0; i < nBlocks; i++) {
    	(*file)->write(testData,blockSize);
    	if(!(*file)) {
    		FATAL(boost::format("Error writing to test file: %s\n") % strerror(errno));
    	}
    }
	(*file)->flush();
}
void GEN_AES_ENCRYPT_FILE(
		std::string *fileName,
		std::fstream **file, // WARNING: Must be closed by the caller
		tv vector,
		unsigned int nBlocks
){
	GEN_AES_TEST_FILE(fileName,file,(const char*)vector.input,sizeof(vector.input),nBlocks);
}
void GEN_AES_DECRYPT_FILE(
		std::string *fileName,
		std::fstream **file, // WARNING: Must be closed by the caller
		tv vector,
		unsigned int nBlocks
){
	GEN_AES_TEST_FILE(fileName,file,(const char*)vector.output,sizeof(vector.output),nBlocks);
}

// TODO random encrypt and decrypt with padding...

template < class CudaAES_t >
void CUDA_AES_SHARED_IO_LAUNCHER_SB_OPERATION_TEST(
		paracrypt::Launcher::operation_t op,
		std::string title,
		tv vector,
		int n_blocks,
		bool constantKey,
		bool constantTables
){
	LOG_TRACE(boost::format("Executing %s...") % title.c_str());

	std::string inFileName;
	std::fstream *inFile;

	switch(op) {
		case paracrypt::Launcher::ENCRYPT:
			GEN_AES_ENCRYPT_FILE(&inFileName,&inFile,vector,n_blocks);
			break;
		case paracrypt::Launcher::DECRYPT:
			GEN_AES_DECRYPT_FILE(&inFileName,&inFile,vector,n_blocks);
			break;
		default:
			ERR("Unknown cipher operation.");
	}

	std::string outFileName;
	{
		char nameBuffer [L_tmpnam];
		std::tmpnam (nameBuffer);
		outFileName = std::string(nameBuffer);
	}
	std::ofstream* outFile = new std::ofstream(outFileName.c_str(),std::fstream::out | std::fstream::binary);

    paracrypt::Launcher::launchSharedIOCudaAES<CudaAES_t>(
    		op,
    		inFileName, outFileName,
    		vector.key, vector.key_bits,
    		constantKey, constantTables
    );

	// Verify output blocks are correct
	std::ifstream* upadatedOutFile = new std::ifstream(outFileName.c_str(),std::fstream::in | std::fstream::binary);
	std::streamsize inFileSize  = paracrypt::IO::fileSize(inFile);
	std::streamsize outFileSize = paracrypt::IO::fileSize(upadatedOutFile);
	BOOST_REQUIRE_EQUAL(inFileSize,outFileSize);
	unsigned char buffer[16];
	for(int i = 0; i < n_blocks; i++) {
		upadatedOutFile->read((char*)buffer,16);
		bool err = upadatedOutFile;
	    BOOST_CHECK(err); // check no err
		if(upadatedOutFile->fail()){
			if(upadatedOutFile->eof()) {
				std::streamsize readBytes = upadatedOutFile->gcount();
				BOOST_REQUIRE_EQUAL(readBytes, 16); // the files only contain full blocks
			} else {
				FATAL(boost::format("Error reading input file: %s\n") % strerror(errno));
			}
		}
		switch(op) {
			case paracrypt::Launcher::ENCRYPT:
		    	BOOST_REQUIRE_EQUAL_COLLECTIONS(buffer,buffer+16,vector.output,vector.output+16);
				break;
			case paracrypt::Launcher::DECRYPT:
				BOOST_REQUIRE_EQUAL_COLLECTIONS(buffer,buffer+16,vector.input,vector.input+16);
				break;
			default:
				ERR("Unknown cipher operation.");
		}
	}
	upadatedOutFile->close();
	delete upadatedOutFile;

    inFile->close();
    delete inFile;

    outFile->close();
    delete outFile;
}

template < class CudaAES_t >
void CUDA_AES_SHARED_IO_LAUNCHER_SB_ENCRYPT_TEST(
			std::string title,
			tv vector,
			int n_blocks,
			bool constantKey,
			bool constantTables
){
	CUDA_AES_SHARED_IO_LAUNCHER_SB_OPERATION_TEST<CudaAES_t>(
			paracrypt::Launcher::ENCRYPT,
			title,
			vector, n_blocks,
			constantKey, constantTables
	);
}

template < class CudaAES_t >
void CUDA_AES_SHARED_IO_LAUNCHER_SB_DECRYPT_TEST(
			std::string title,
			tv vector,
			int n_blocks,
			bool constantKey,
			bool constantTables
){
	CUDA_AES_SHARED_IO_LAUNCHER_SB_OPERATION_TEST<CudaAES_t>(
			paracrypt::Launcher::DECRYPT,
			title,
			vector, n_blocks,
			constantKey, constantTables
	);
}


void GEN_AES_RACC_TEST_FILE(
		std::string *fileName,
		std::fstream **file, // WARNING: Must be closed by the caller
		const char* testData,
		unsigned int blockSize,
		unsigned int nBlocks,
		std::streampos beginBlock,
		std::streampos endBlock
){
	{
		char nameBuffer [L_tmpnam];
		std::tmpnam (nameBuffer);
		(*fileName) = std::string(nameBuffer);
	}

	(*file) = new std::fstream(fileName->c_str(),std::fstream::out | std::fstream::binary);
	if(!(*file)) {
		FATAL(boost::format("Error creating test file: %s\n") % strerror(errno));
	}

//	srand (time(NULL));
//	uint32_t random_block_words[4];
	unsigned char zeroes[16];
	memset(zeroes, 0, 16);

    for(unsigned int i=0; i < nBlocks; i++) {
    	if(beginBlock <= i&&i <= endBlock) {
//    		(*file)->flush(); // TODO TOREMOVE
//    		break; // TODO TOREMOVE
    		(*file)->write(testData,blockSize);
    	} else {
//    		// random data at blocks we will not access
//    		for(int j=0; j < 4; j++) {
//    			random_block_words[j] = (uint32_t) rand();
//    		}
    		zeroes[0] = (unsigned char) i;
    		(*file)->write((const char*)zeroes,blockSize);
//    		(*file)->write((const char*)random_block_words,blockSize);
//    		LOG_TRACE(boost::format("written %i bytes\n") % blockSize);// TODO TOREMOVE
//    		hexdump("block_words",(const unsigned char*)random_block_words,blockSize);
    	}
    	if(!(*file)) {
    		FATAL(boost::format("Error writing to test file: %s\n") % strerror(errno));
    	}
    }
	(*file)->flush();
}

template < class CudaAES_t >
void CUDA_AES_SHARED_IO_LAUNCHER_RACC_TEST(
		std::string title,
		tv vector,
		int n_blocks,
		bool constantKey,
		bool constantTables,
		std::streampos begin,
		std::streampos end
){
	LOG_TRACE(boost::format("Executing %s...") % title.c_str());

	unsigned int blockSize = sizeof(vector.input);
	std::streampos beginBlock = begin/blockSize; // begin block
	std::streampos endBlock = end/blockSize; // end block // TODO somethn wrong here ?
	assert(endBlock > beginBlock);
	std::streampos nBlocks = endBlock-beginBlock;

	std::string inFileName;
	std::fstream *inFile;
	GEN_AES_RACC_TEST_FILE(&inFileName,&inFile,(const char*) vector.input,sizeof(vector.input),n_blocks,beginBlock,endBlock);
//	std::streamsize inFileSize = paracrypt::IO::fileSize(inFile);
//
//	if(rem != 0 && end > inFileSize) {
//		nBlocks -= 1;
//	}

	std::string outFileName;
	std::string raccFileName;
	{
		char nameBuffer [L_tmpnam];
		std::tmpnam (nameBuffer);
		outFileName = std::string(nameBuffer);
		std::tmpnam (nameBuffer);
		raccFileName = std::string(nameBuffer);
	}
	std::ofstream* outFile = new std::ofstream(outFileName.c_str(),std::fstream::out | std::fstream::binary);
	std::ofstream* raccFile = new std::ofstream(raccFileName.c_str(),std::fstream::out | std::fstream::binary);

    paracrypt::Launcher::launchSharedIOCudaAES<CudaAES_t>(
    		paracrypt::Launcher::ENCRYPT,
    		inFileName, outFileName,
    		vector.key, vector.key_bits,
    		constantKey, constantTables
    );

    paracrypt::Launcher::launchSharedIOCudaAES<CudaAES_t>(
    		paracrypt::Launcher::DECRYPT,
    		outFileName, raccFileName,
    		vector.key, vector.key_bits,
    		constantKey, constantTables,
    		begin, end
    );

	// Verify output blocks are correct
	std::ifstream* upadatedRaccFile = new std::ifstream(raccFileName.c_str(),std::fstream::in | std::fstream::binary);
	std::streamsize raccFileSize = paracrypt::IO::fileSize(upadatedRaccFile);
	BOOST_REQUIRE_EQUAL(raccFileSize,nBlocks*16);
	unsigned char buffer[16];
	for(int i = 0; i < nBlocks; i++) {
		upadatedRaccFile->read((char*)buffer,16);
		bool err = upadatedRaccFile;
	    BOOST_CHECK(err); // check no err
		if(upadatedRaccFile->fail()){
			if(upadatedRaccFile->eof()) {
				std::streamsize readBytes = upadatedRaccFile->gcount();
				BOOST_REQUIRE_EQUAL(readBytes, 16); // the files only contain full blocks
			} else {
				FATAL(boost::format("Error reading input file: %s\n") % strerror(errno));
			}
		}
    	BOOST_REQUIRE_EQUAL_COLLECTIONS(buffer,buffer+16,vector.input,vector.input+16);
	}
	upadatedRaccFile->close();
	delete upadatedRaccFile;

    inFile->close();
    delete inFile;

    outFile->close();
    delete outFile;

    raccFile->close();
    delete raccFile;
}

#define AES_LAUNCHER_KEYSIZE_TEST_SUITE(id, testName, className, keySizeStr, keySize) \
		BOOST_AUTO_TEST_SUITE(id) \
				BOOST_AUTO_TEST_CASE(constant_key_and_tables) { \
					CUDA_AES_SHARED_IO_LAUNCHER_SB_ENCRYPT_TEST<className>( \
							"Multistream " testName " CUDA ECB AES-"keySizeStr" with constant key and tables.", get_aes_tv(keySize),1000,true, true);} \
				BOOST_AUTO_TEST_CASE(constant_key) { \
					CUDA_AES_SHARED_IO_LAUNCHER_SB_ENCRYPT_TEST<className>( \
							"Multistream " testName " CUDA ECB AES-"keySizeStr" with constant key.", get_aes_tv(keySize),1000,true, false);} \
				BOOST_AUTO_TEST_CASE(dynamic_key_and_tables) { \
					CUDA_AES_SHARED_IO_LAUNCHER_SB_ENCRYPT_TEST<className>( \
							"Multistream " testName " CUDA ECB AES-"keySizeStr".", get_aes_tv(keySize),1000,false, false);} \
 \
				BOOST_AUTO_TEST_CASE(constant_key_and_tables_decrypt) { \
					CUDA_AES_SHARED_IO_LAUNCHER_SB_DECRYPT_TEST<className>( \
							"Multistream " testName " CUDA ECB AES-"keySizeStr" with constant key and tables.", get_aes_tv(keySize),1000,true, true);} \
				BOOST_AUTO_TEST_CASE(constant_key_decrypt) { \
					CUDA_AES_SHARED_IO_LAUNCHER_SB_DECRYPT_TEST<className>( \
							"Multistream " testName " CUDA ECB AES-"keySizeStr" with constant key.", get_aes_tv(keySize),1000,true, false);} \
				BOOST_AUTO_TEST_CASE(dynamic_key_and_tables_decrypt) { \
					CUDA_AES_SHARED_IO_LAUNCHER_SB_DECRYPT_TEST<className>( \
							"Multistream " testName " CUDA ECB AES-"keySizeStr".", get_aes_tv(keySize),1000,false, false);} \
\
				BOOST_AUTO_TEST_CASE(constant_key_and_tables_racc) { \
					CUDA_AES_SHARED_IO_LAUNCHER_RACC_TEST<className>( \
						"Multistream encryption and random access decryption using " testName " CUDA ECB AES-"keySizeStr" with constant key and tables.", get_aes_tv(keySize),1000,true, true, 16*100,16*200);} \
				BOOST_AUTO_TEST_CASE(constant_key_decrypt_racc) { \
					CUDA_AES_SHARED_IO_LAUNCHER_RACC_TEST<className>( \
						"Multistream encryption and random access decryption using " testName " CUDA ECB AES-"keySizeStr" with constant key.", get_aes_tv(keySize),1000,true, false, 16*100,16*200);} \
				BOOST_AUTO_TEST_CASE(dynamic_key_and_tables_racc) { \
					CUDA_AES_SHARED_IO_LAUNCHER_RACC_TEST<className>( \
						"Multistream encryption and random access decryption using " testName " CUDA ECB AES-"keySizeStr".", get_aes_tv(keySize),1000,false, false, 16*100,16*200);} \
\
				BOOST_AUTO_TEST_CASE(constant_key_and_tables_racc_unalig) { \
					CUDA_AES_SHARED_IO_LAUNCHER_RACC_TEST<className>( \
						"Multistream encryption and random access (unaligned to block) decryption using " testName " CUDA ECB AES-"keySizeStr" with constant key and tables.", get_aes_tv(keySize),1000,true, true, 16*99+8,16*200-8);} \
				BOOST_AUTO_TEST_CASE(constant_key_racc_unalig) { \
					CUDA_AES_SHARED_IO_LAUNCHER_RACC_TEST<className>( \
						"Multistream encryption and random access (unaligned to block) decryption using " testName " CUDA ECB AES-"keySizeStr" with constant key.", get_aes_tv(keySize),1000,true, false, 16*99+8,16*200-8);} \
				BOOST_AUTO_TEST_CASE(dynamic_key_and_tables_racc_unalig) { \
					CUDA_AES_SHARED_IO_LAUNCHER_RACC_TEST<className>( \
						"Multistream encryption and random access (unaligned to block) decryption using " testName " CUDA ECB AES-"keySizeStr".", get_aes_tv(keySize),1000,false, false, 16*99+8,16*200-8);} \
		BOOST_AUTO_TEST_SUITE_END()

#define AES_LAUNCHER_TEST_SUITE(id, testName, className) \
		BOOST_AUTO_TEST_SUITE(id) \
			AES_LAUNCHER_KEYSIZE_TEST_SUITE(KEY128, testName, className, "128", 128); \
			AES_LAUNCHER_KEYSIZE_TEST_SUITE(KEY192, testName, className, "192", 192); \
			AES_LAUNCHER_KEYSIZE_TEST_SUITE(KEY256, testName, className, "256", 256); \
		BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(LAUNCHERS)
	BOOST_AUTO_TEST_SUITE(CUDA)
		BOOST_AUTO_TEST_SUITE(SHAREDIO)
			BOOST_AUTO_TEST_SUITE(AES)
				AES_LAUNCHER_TEST_SUITE(PARA_16B,"16B parallelism",paracrypt::CudaAES16B);
				AES_LAUNCHER_TEST_SUITE(PARA_16B_PTR,"16B (ptr) parallelism",paracrypt::CudaAES16BPtr);
				AES_LAUNCHER_TEST_SUITE(PARA_8B,"8B parallelism",paracrypt::CudaAES8B);
				AES_LAUNCHER_TEST_SUITE(PARA_8B_PTR,"8B (ptr) parallelism",paracrypt::CudaAES8BPtr);
				AES_LAUNCHER_TEST_SUITE(PARA_4B,"4B parallelism",paracrypt::CudaAES4B);
				AES_LAUNCHER_TEST_SUITE(PARA_4B_PTR,"4B (ptr) parallelism",paracrypt::CudaAES4BPtr);
				AES_LAUNCHER_TEST_SUITE(PARA_1B,"1B parallelism",paracrypt::CudaAES1B);
			BOOST_AUTO_TEST_SUITE_END()
		BOOST_AUTO_TEST_SUITE_END()
	BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE_END()
