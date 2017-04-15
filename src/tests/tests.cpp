#define BOOST_TEST_MODULE paracrypt
#include <boost/test/included/unit_test.hpp>
#include <stdint.h>
#include "../logging.hpp"
#include "../openssl/AES_key_schedule.h"
#include "../device/CUDACipherDevice.hpp"
#include "../AES/CudaEcbAes16B.hpp"
#include "../AES/CudaEcbAes16BPtr.hpp"
#include "../AES/CudaEcbAes8B.hpp"
#include "../AES/CudaEcbAes4B.hpp"
#include "../endianess.h"
#include "../Timer.hpp"
#include "cuda_test_kernels.cuh"
#include "assert.h"
#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */

int random_data_n_blocks;
unsigned char *random_data;

paracrypt::CUDACipherDevice* gpu;

struct Setup {
	Setup()   {
		// 1Mib to 2Mib data
	#define TRD_MIN 1*1024*64
	#define TRD_MAX 2*1024*64
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

/*
 * Encrypts a random input string, decrypts it,
 * and checks if the result is the same original
 * string.
 */
void AES_RDN_TEST(std::string title, tv vector_key, paracrypt::CudaAES* aes, paracrypt::CUDACipherDevice* dev, int key_bits, bool constantKey, bool constantTables)
{
	int data_length = random_data_n_blocks*16;
    unsigned char *result = (unsigned char*) malloc(data_length); // 16 MiB file

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
    for(int i=0;i<random_data_n_blocks;i++) {
    	BOOST_TEST(((uint32_t*)result)[i] != ((uint32_t*)random_data)[i]);
    }

    t->tic();
    aes->decrypt(result, result, random_data_n_blocks);
    sec = t->toc_seconds();
    LOG_INF(boost::format("%s needs %f seconds to decrypt %d blocks\n") % title.c_str() % sec % random_data_n_blocks);

   	BOOST_CHECK_EQUAL_COLLECTIONS((uint32_t*)result,((uint32_t*)result)+random_data_n_blocks,((uint32_t*)random_data),((uint32_t*)random_data)+random_data_n_blocks);
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

    // first block hexdump
    hexdump("expected",vector.output,16);
    hexdump("data",data,16);

    for(int i=0; i < n_blocks; i++) {
    	BOOST_REQUIRE_EQUAL_COLLECTIONS(data+(i*16),data+(i*16)+16,vector.output,vector.output+16);
    }
}

BOOST_AUTO_TEST_SUITE(CUDA_AES_16B)
	BOOST_AUTO_TEST_CASE(ECB_AES128_kc_tc_single)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES16B();
		AES_SB_ENCRYPT_TEST("AES128-ECB (16B parallelism) with constant key and t-table",
				aes_example,1,aes,gpu,true,true);
		delete aes;
	}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(CUDA_AES_8B)
	BOOST_AUTO_TEST_CASE(ECB_AES128_kc_tc_single)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_SB_ENCRYPT_TEST("AES128-ECB example vector | 8B parallelism with constant key and t-table",
				aes_example,1,aes,gpu,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES192_kc_tc_single)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_SB_ENCRYPT_TEST("AES192-ECB example vector | 8B parallelism with constant key and t-table",
				aes_192_tv,1,aes,gpu,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES256_kc_tc_single)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_SB_ENCRYPT_TEST("AES256-ECB example vector | 8B parallelism with constant key and t-table",
				aes_256_tv,1,aes,gpu,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES128_kc_tc_2blocks)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_SB_ENCRYPT_TEST("AES128-ECB example vector | 8B parallelism with constant key and t-table",
				aes_example,2,aes,gpu,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES192_kc_tc_2blocks)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_SB_ENCRYPT_TEST("AES192-ECB example vector | 8B parallelism with constant key and t-table",
				aes_192_tv,2,aes,gpu,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES256_kc_tc_2blocks)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_SB_ENCRYPT_TEST("AES256-ECB example vector | 8B parallelism with constant key and t-table",
				aes_example,2,aes,gpu,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES128_kc_tc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_RDN_TEST("AES128-ECB (8B parallelism) with random data and constant key and t-table",
				aes_example,aes,gpu,128,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES128_kc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_RDN_TEST("AES128-ECB (8B parallelism) with random data and constant key",
				aes_example,aes,gpu,128,true,false);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES128_tc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_RDN_TEST("AES128-ECB (8B parallelism) with random data and constant t-table",
				aes_example,aes,gpu,128,false,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES128_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_RDN_TEST("AES128-ECB (8B parallelism) with random data and dynamic key and t-table",
				aes_example,aes,gpu,128,false,false);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES192_kc_tc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_RDN_TEST("AES192-ECB (8B parallelism) with random data and constant key and t-table",
				aes_192_tv,aes,gpu,192,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES192_kc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_RDN_TEST("AES192-ECB (8B parallelism) with random data and constant key",
				aes_192_tv,aes,gpu,192,true,false);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES192_tc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_RDN_TEST("AES192-ECB (8B parallelism) with random data and constant t-table",
				aes_192_tv,aes,gpu,192,false,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES192_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_RDN_TEST("AES192-ECB (8B parallelism) with random data and dynamic key and t-table",
				aes_192_tv,aes,gpu,192,false,false);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES256_kc_tc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_RDN_TEST("AES256-ECB (8B parallelism) with random data and constant key and t-table",
				aes_256_tv,aes,gpu,256,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES256_kc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_RDN_TEST("AES256-ECB (8B parallelism) with random data and constant key",
				aes_256_tv,aes,gpu,256,true,false);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES256_tc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_RDN_TEST("AES256-ECB (8B parallelism) with random data and constant t-table",
				aes_256_tv,aes,gpu,256,false,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES256_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_RDN_TEST("AES256-ECB (8B parallelism) with random data and dynamic key and t-table",
				aes_256_tv,aes,gpu,256,false,false);
		delete aes;
	}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(CUDA_AES_4B)
	BOOST_AUTO_TEST_CASE(ECB_AES128_kc_tc_single)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES4B();
		AES_SB_ENCRYPT_TEST("AES128-ECB example vector | 4B parallelism with constant key and t-table",
				aes_example,1,aes,gpu,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES192_kc_tc_single)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES4B();
		AES_SB_ENCRYPT_TEST("AES192-ECB example vector | 4B parallelism with constant key and t-table",
				aes_192_tv,1,aes,gpu,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES256_kc_tc_single)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES4B();
		AES_SB_ENCRYPT_TEST("AES256-ECB example vector | 4B parallelism with constant key and t-table",
				aes_256_tv,1,aes,gpu,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES128_kc_tc_2blocks)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES4B();
		AES_SB_ENCRYPT_TEST("AES128-ECB example vector | 4B parallelism with constant key and t-table",
				aes_example,2,aes,gpu,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES192_kc_tc_2blocks)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES4B();
		AES_SB_ENCRYPT_TEST("AES192-ECB example vector | 4B parallelism with constant key and t-table",
				aes_192_tv,2,aes,gpu,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES256_kc_tc_2blocks)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES4B();
		AES_SB_ENCRYPT_TEST("AES256-ECB example vector | 4B parallelism with constant key and t-table",
				aes_256_tv,2,aes,gpu,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES128_kc_tc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES4B();
		AES_RDN_TEST("AES128-ECB (4B parallelism) with random data and constant key and t-table",
				aes_example,aes,gpu,128,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES128_kc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_RDN_TEST("AES128-ECB (4B parallelism) with random data and constant key",
				aes_example,aes,gpu,128,true,false);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES128_tc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_RDN_TEST("AES128-ECB (4B parallelism) with random data and constant t-table",
				aes_example,aes,gpu,128,false,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES128_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
		AES_RDN_TEST("AES128-ECB (4B parallelism) with random data and dynamic key and t-table",
				aes_example,aes,gpu,128,false,false);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES192_kc_tc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES4B();
		AES_RDN_TEST("AES192-ECB (4B parallelism) with random data and constant key and t-table",
				aes_192_tv,aes,gpu,192,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES192_kc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES4B();
		AES_RDN_TEST("AES192-ECB (4B parallelism) with random data and constant key",
				aes_192_tv,aes,gpu,192,true,false);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES192_tc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES4B();
		AES_RDN_TEST("AES192-ECB (4B parallelism) with random data and constant t-table",
				aes_192_tv,aes,gpu,192,false,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES192_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES4B();
		AES_RDN_TEST("AES192-ECB (4B parallelism) with random data and dynamic key and t-table",
				aes_192_tv,aes,gpu,192,false,false);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES256_kc_tc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES4B();
		AES_RDN_TEST("AES256-ECB (4B parallelism) with random data and constant key and t-table",
				aes_256_tv,aes,gpu,256,true,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES256_kc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES4B();
		AES_RDN_TEST("AES256-ECB (4B parallelism) with random data and constant key",
				aes_256_tv,aes,gpu,256,true,false);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES256_tc_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES4B();
		AES_RDN_TEST("AES256-ECB (4B parallelism) with random data and constant t-table",
				aes_256_tv,aes,gpu,256,false,true);
		delete aes;
	}
	BOOST_AUTO_TEST_CASE(ECB_AES256_random)
	{
		paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES4B();
		AES_RDN_TEST("AES256-ECB (4B parallelism) with random data and dynamic key and t-table",
				aes_256_tv,aes,gpu,256,false,false);
		delete aes;
	}
BOOST_AUTO_TEST_SUITE_END()

//	BOOST_AUTO_TEST_SUITE(key_expansion)
//#include "key_schedule_test.cpp"
//    BOOST_AUTO_TEST_SUITE_END()

//	BOOST_AUTO_TEST_SUITE(key_expansion)
//#include "key_schedule_test.cpp"
//    BOOST_AUTO_TEST_SUITE_END()

//    // how to run a specific test: ./paracrypt_tests --run_test=cuda_aes/cuda_ecb_aes192_16b_singleblock
//    BOOST_AUTO_TEST_SUITE(cuda_aes_16B_encrypt)
//#include "cuda_aes_16B_encrypt_test.cpp"
//    BOOST_AUTO_TEST_SUITE_END()
//
//    BOOST_AUTO_TEST_SUITE(cuda_aes_16B_decrypt)
//#include "cuda_aes_16B_decrypt_test.cpp"
//    BOOST_AUTO_TEST_SUITE_END()
//
//    BOOST_AUTO_TEST_SUITE(cuda_aes_16BPtr_encrypt)
//#include "cuda_aes_16BPtr_encrypt_test.cpp"
//    BOOST_AUTO_TEST_SUITE_END()
//
//    BOOST_AUTO_TEST_SUITE(cuda_aes_16BPtr_decrypt)
//#include "cuda_aes_16BPtr_decrypt_test.cpp"
//    BOOST_AUTO_TEST_SUITE_END()
//
//    BOOST_AUTO_TEST_SUITE(cudacons_aes_16B_encrypt)
//#include "cudacons_aes_16B_encrypt_test.cpp"
//    BOOST_AUTO_TEST_SUITE_END()
