#define BOOST_TEST_MODULE paracrypt
#include <boost/test/included/unit_test.hpp>
#include <stdint.h>
#include "../logging.hpp"
#include "../openssl/AES_key_schedule.h"
#include "../CUDACipherDevice.hpp"
#include "../CudaEcbAes16B.hpp"
#include "../endianess.h"
#include "cuda_test_kernels.cuh"

//bool init_unit_test()
//{
//	boost::log::core::get()->set_filter
//    (
//    		boost::log::trivial::severity >= boost::log::trivial::trace
//    );
//    return true;
//}

const unsigned char k[128] = {
    0x2bU, 0x7eU, 0x15U, 0x16U,
    0x28U, 0xaeU, 0xd2U, 0xa6U,
    0xabU, 0xf7U, 0x15U, 0x88U,
    0x09U, 0xcfU, 0x4fU, 0x3cU
};

	BOOST_AUTO_TEST_SUITE(key_expansion)
#include "key_schedule_test.cpp"
    BOOST_AUTO_TEST_SUITE_END()

    BOOST_AUTO_TEST_SUITE(cuda_aes)
#include "cuda_aes_test.cpp"
    BOOST_AUTO_TEST_SUITE_END()
