#include "../openssl/AES_key_schedule.h"
#include <stdint.h>

// NIST FIPS 197 tests vector

BOOST_AUTO_TEST_CASE(key_schedule_128)
{
    const unsigned char k[128] =
		  {0x2b, 0x7e, 0x15, 0x16,
		  0x28, 0xae, 0xd2, 0xa6,
		  0x28, 0xae, 0xd2, 0xa6,
		  0x09, 0xcf, 0x4f, 0x3c};
    const uint32_t w[40] ={0x2b7e1516,
		    0x28aed2a6,
		    0xabf71588,
		    0x09cf4f3c,
		    0xa0fafe17,
		    0x88542cb1,
		    0x23a33939,
		    0x2a6c7605,
		    0xf2c295f2,
		    0x7a96b943,
		    0x5935807a,
		    0x7359f67f,
		    0x3d80477d,
		    0x4716fe3e,
		    0x1e237e44,
		    0x6d7a883b,
		    0xef44a541,
		    0xa8525b7f,
		    0xb671253b,
		    0xdb0bad00,
		    0xd4d1c6f8,
		    0x7c839d87,
		    0xcaf2b8bc,
		    0x11f915bc,
		    0x6d88a37a,
		    0x110b3efd,
		    0xdbf98641,
		    0xca0093fd,
		    0x4e54f70e,
		    0x5f5fc9f3,
		    0x84a64fb2,
		    0x4ea6dc4f,
		    0xead27321,
		    0xb58dbad2,
		    0x312bf560,
		    0x7f8d292f,
		    0xac7766f3,
		    0x19fadc21,
		    0x28d12941,
		    0x575c006e};
	AES_KEY ek;
	AES_set_encrypt_key((const unsigned char*)&k,128,&ek);
	char* ek_key = (char*) ek.rd_key;
	BOOST_CHECK_EQUAL_COLLECTIONS(k,k+128,ek_key,ek_key+128);
}
