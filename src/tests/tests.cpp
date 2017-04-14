#define BOOST_TEST_MODULE paracrypt
#include <boost/test/included/unit_test.hpp>
#include <stdint.h>
#include "../logging.hpp"
#include "../openssl/AES_key_schedule.h"
#include "../device/CUDACipherDevice.hpp"
#include "../AES/CudaEcbAes16B.hpp"
#include "../AES/CudaEcbAes16BPtr.hpp"
#include "../AES/CudaEcbAes8B.hpp"
#include "../endianess.h"
#include "../Timer.hpp"
#include "cuda_test_kernels.cuh"
#include "assert.h"
#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */

int random_data_n_blocks;
unsigned char *random_data;

struct Setup {
	Setup()   {
		// from 13Mib to 18Mib
	#define TRD_MIN 1*1024*64
	#define TRD_MAX 2*1024*64
	#define TRD_DIF (TRD_MAX-TRD_MIN)
		random_data_n_blocks = (rand() % 10 + 1); // TRD_DIF + TRD_MIN);
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
  }
  ~Setup()  {
	  free(random_data);
  }
};
BOOST_GLOBAL_FIXTURE( Setup );

const unsigned char k[128] = {
    0x2bU, 0x7eU, 0x15U, 0x16U,
    0x28U, 0xaeU, 0xd2U, 0xa6U,
    0xabU, 0xf7U, 0x15U, 0x88U,
    0x09U, 0xcfU, 0x4fU, 0x3cU
};

const unsigned char k2[192] = {
    0x00U, 0x01U, 0x02U, 0x03U,
    0x04U, 0x05U, 0x06U, 0x07U,
    0x08U, 0x09U, 0x0aU, 0x0bU,
    0x0cU, 0x0dU, 0x0eU, 0x0fU,
    0x10U, 0x11U, 0x12U, 0x13U,
    0x14U, 0x15U, 0x16U, 0x17U
};
const unsigned char k3[256] = {
    0x00U, 0x01U, 0x02U, 0x03U,
    0x04U, 0x05U, 0x06U, 0x07U,
    0x08U, 0x09U, 0x0aU, 0x0bU,
    0x0cU, 0x0dU, 0x0eU, 0x0fU,
    0x10U, 0x11U, 0x12U, 0x13U,
    0x14U, 0x15U, 0x16U, 0x17U,
    0x18U, 0x19U, 0x1aU, 0x1bU,
    0x1cU, 0x1dU, 0x1eU, 0x1fU
};

/*
 * Encrypts a random input string, decrypts it,
 * and checks if the result is the same original
 * string.
 */
void AES_RDN_TEST(std::string title, paracrypt::CudaAES* aes, int key_bits, bool constantKey, bool constantTables)
{
	int data_length = random_data_n_blocks*16;
    unsigned char *result = (unsigned char*) malloc(data_length); // 16 MiB file

    paracrypt::CUDACipherDevice * gpu = new paracrypt::CUDACipherDevice(0);
    aes->constantKey(constantKey);
    aes->constantTables(constantTables);
    aes->setKey(k,key_bits);
    aes->setDevice(gpu);
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

    delete aes;
    delete gpu;

   	BOOST_CHECK_EQUAL_COLLECTIONS((uint32_t*)result,((uint32_t*)result)+random_data_n_blocks,((uint32_t*)random_data),((uint32_t*)random_data)+random_data_n_blocks);
    free(result);
}

void AES_SB_TEST(std::string title, paracrypt::CudaAES* aes, int key_bits, bool constantKey, bool constantTables)
{
    unsigned char data[16] = {
	0x32U, 0x43U, 0xf6U, 0xa8U,
	0x88U, 0x5aU, 0x30U, 0x8dU,
	0x31U, 0x31U, 0x98U, 0xa2U,
	0xe0U, 0x37U, 0x07U, 0x34U
    };
    const unsigned char output[16] = {
	0x39U, 0x25U, 0x84U, 0x1dU,
	0x02U, 0xdcU, 0x09U, 0xfbU,
	0xdcU, 0x11U, 0x85U, 0x97U,
	0x19U, 0x6aU, 0x0bU, 0x32U
    };

    paracrypt::CUDACipherDevice * gpu = new paracrypt::CUDACipherDevice(0);
    aes->setKey(k,128);
    aes->setDevice(gpu);
    aes->constantKey(constantKey);
    aes->constantTables(constantTables);
    aes->malloc(1);
    aes->encrypt((unsigned char *) &data, (unsigned char *) &data, 1);

    delete aes;
    delete gpu;

    hexdump("expected",output,16);
    hexdump("data",data,16);
    BOOST_CHECK_EQUAL_COLLECTIONS(data,data+16,output,output+16);
}

BOOST_AUTO_TEST_SUITE(CUDA_AES_16B)
BOOST_AUTO_TEST_CASE(ECB_AES128_kc_tc_random)
{
    paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES16B();
    AES_SB_TEST(
    		"AES128-ECB (16B parallelism) with constant key and t-table",
    		aes,
    		128,
    		true,
    		true
    );
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(CUDA_AES_8B)
BOOST_AUTO_TEST_CASE(ECB_AES128_kc_tc_single)
{
    paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
    AES_SB_TEST(
    		"AES128-ECB test vector | 8B parallelism with constant key and t-table",
    		aes,
    		128,
    		true,
    		true
    );
}
BOOST_AUTO_TEST_CASE(ECB_AES128_kc_tc_random)
{
    paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES8B();
    AES_RDN_TEST(
    		"AES128-ECB (8B parallelism) with constant key and t-table",
    		aes,
    		128,
    		true,
    		true
    );
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
