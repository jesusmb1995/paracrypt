#include "../openssl/AES_key_schedule.h"
#include "../openssl/reverse_ssl_internal_key.h"
#include <stdint.h>

// NIST FIPS 197 tests vector

BOOST_AUTO_TEST_CASE(key_schedule_128)
{
    const unsigned char k[128] =
		  {0x2bU, 0x7eU, 0x15U, 0x16U,
		  0x28U, 0xaeU, 0xd2U, 0xa6U,
		  0x28U, 0xaeU, 0xd2U, 0xa6U,
		  0x09U, 0xcfU, 0x4fU, 0x3cU};
    const uint32_t w[40] ={0x2b7e1516U,
		    0x28aed2a6U,
		    0xabf71588U,
		    0x09cf4f3cU,
		    0xa0fafe17U,
		    0x88542cb1U,
		    0x23a33939U,
		    0x2a6c7605U,
		    0xf2c295f2U,
		    0x7a96b943U,
		    0x5935807aU,
		    0x7359f67fU,
		    0x3d80477dU,
		    0x4716fe3eU,
		    0x1e237e44U,
		    0x6d7a883bU,
		    0xef44a541U,
		    0xa8525b7fU,
		    0xb671253bU,
		    0xdb0bad00U,
		    0xd4d1c6f8U,
		    0x7c839d87U,
		    0xcaf2b8bcU,
		    0x11f915bcU,
		    0x6d88a37aU,
		    0x110b3efdU,
		    0xdbf98641U,
		    0xca0093fdU,
		    0x4e54f70eU,
		    0x5f5fc9f3U,
		    0x84a64fb2U,
		    0x4ea6dc4fU,
		    0xead27321U,
		    0xb58dbad2U,
		    0x312bf560U,
		    0x7f8d292fU,
		    0xac7766f3U,
		    0x19fadc21U,
		    0x28d12941U,
		    0x575c006eU};
	AES_KEY ek;
	AES_set_encrypt_key((const unsigned char*)&k,128,&ek);
	uint32_t w2[40];
	AES_get_key((uint32_t*)&w2,&ek);
	BOOST_CHECK_EQUAL_COLLECTIONS(w,w+40,w2,w2+40);
}
