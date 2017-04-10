#define BOOST_TEST_MODULE paracrypt_openssl
#include <boost/test/included/unit_test.hpp>
#include <stdint.h>
#include "../logging.hpp"
#include "../openssl/aes.h"

BOOST_AUTO_TEST_CASE(ecb_aes)
{
	// From NIST 197
	const unsigned char k[128] = {
	    0x2bU, 0x7eU, 0x15U, 0x16U,
	    0x28U, 0xaeU, 0xd2U, 0xa6U,
	    0xabU, 0xf7U, 0x15U, 0x88U,
	    0x09U, 0xcfU, 0x4fU, 0x3cU
	};
	const unsigned char data[128] = {
	    0x32U, 0x43U, 0xf6U, 0xa8U,
	    0x88U, 0x5aU, 0x30U, 0x8dU,
	    0x31U, 0x31U, 0x98U, 0xa2U,
	    0xe0U, 0x37U, 0x07U, 0x34U
	};
	const unsigned char output[128] = {
	    0x39U, 0x25U, 0x84U, 0x1dU,
	    0x02U, 0xdcU, 0x09U, 0xfbU,
	    0xdcU, 0x11U, 0x85U, 0x97U,
	    0x19U, 0x6aU, 0x0bU, 0x32U
	};
	AES_KEY ek;
    AES_set_encrypt_key((const unsigned char *) &k, 128, &ek);
    hexdump("input",(unsigned char*)&data,16);
    AES_encrypt((const unsigned char*) &data, (unsigned char*) &data, &ek);
    hexdump("output",(unsigned char*)&data,16);
    BOOST_CHECK_EQUAL(data,output);
}
