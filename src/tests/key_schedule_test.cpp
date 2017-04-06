// NIST FIPS 197 tests vector

BOOST_AUTO_TEST_CASE(key_schedule_128_endian)
{
    const uint32_t w[40] = { 0x2b7e1516U,
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
	0x575c006eU
    };
    AES_KEY ek;
    AES_set_encrypt_key((const unsigned char *) &k, 128, &ek);
    hexdump("TV_KEY", (unsigned char *) &w, sizeof(w));
    //hexdump("AES_KEY", (unsigned char *) &ek.rd_key, sizeof(ek.rd_key));
    BOOST_CHECK_EQUAL_COLLECTIONS(w, w + 40, ek.rd_key, ek.rd_key + 40);
}

BOOST_AUTO_TEST_CASE(key_schedule_128)
{
    const unsigned char w[40*4] = {
    		"0x2bU", "0x7eU", "0x15U", "0x16U",
    		"0x28U", "0xaeU", "0xd2U", "0xa6U",
    		"0xabU", "0xf7U", "0x15U", "0x88U",
    		"0x09U", "0xcfU", "0x4fU", "0x3cU",
    		"0xa0U", "0xfaU", "0xfeU", "0x17U",
    		"0x88U", "0x54U", "0x2cU", "0xb1U",
    		"0x23U", "0xa3U", "0x39U", "0x39U",
    		"0x2aU", "0x6cU", "0x76U", "0x05U",
    		"0xf2U", "0xc2U", "0x95U", "0xf2U",
    		"0x7aU", "0x96U", "0xb9U", "0x43U",
    		"0x59U", "0x35U", "0x80U", "0x7aU",
    		"0x73U", "0x59U", "0xf6U", "0x7fU",
    		"0x3dU", "0x80U", "0x47U", "0x7dU",
    		"0x47U", "0x16U", "0xfeU", "0x3eU",
    		"0x1eU", "0x23U", "0x7eU", "0x44U",
    		"0x6dU", "0x7aU", "0x88U", "0x3bU",
    		"0xefU", "0x44U", "0xa5U", "0x41U",
    		"0xa8U", "0x52U", "0x5bU", "0x7fU",
    		"0xb6U", "0x71U", "0x25U", "0x3bU",
    		"0xdbU", "0x0bU", "0xadU", "0x00U",
    		"0xd4U", "0xd1U", "0xc6U", "0xf8U",
    		"0x7cU", "0x83U", "0x9dU", "0x87U",
    		"0xcaU", "0xf2U", "0xb8U", "0xbcU",
    		"0x11U", "0xf9U", "0x15U", "0xbcU",
    		"0x6dU", "0x88U", "0xa3U", "0x7aU",
    		"0x11U", "0x0bU", "0x3eU", "0xfdU",
    		"0xdbU", "0xf9U", "0x86U", "0x41U",
    		"0xcaU", "0x00U", "0x93U", "0xfdU",
    		"0x4eU", "0x54U", "0xf7U", "0x0eU",
    		"0x5fU", "0x5fU", "0xc9U", "0xf3U",
    		"0x84U", "0xa6U", "0x4fU", "0xb2U",
    		"0x4eU", "0xa6U", "0xdcU", "0x4fU",
    		"0xeaU", "0xd2U", "0x73U", "0x21U",
    		"0xb5U", "0x8dU", "0xbaU", "0xd2U",
    		"0x31U", "0x2bU", "0xf5U", "0x60U",
    		"0x7fU", "0x8dU", "0x29U", "0x2fU",
    		"0xacU", "0x77U", "0x66U", "0xf3U",
    		"0x19U", "0xfaU", "0xdcU", "0x21U",
    		"0x28U", "0xd1U", "0x29U", "0x41U",
    		"0x57U", "0x5cU", "0x00U", "0x6eU"
    };
    AES_KEY ek;
    AES_set_encrypt_key((const unsigned char *) &k, 128, &ek);
    hexdump("TV_KEY", (unsigned char *) &w, sizeof(w));
    //hexdump("AES_KEY", (unsigned char *) &ek.rd_key, sizeof(ek.rd_key));
    BOOST_CHECK_EQUAL_COLLECTIONS(w, w + 40, ek.rd_key, ek.rd_key + 40);
}
