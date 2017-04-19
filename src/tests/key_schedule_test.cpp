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
    hexdump("AES_KEY", (unsigned char *) &ek.rd_key, sizeof(ek.rd_key));
    BOOST_CHECK_EQUAL_COLLECTIONS(w, w + 40, ek.rd_key, ek.rd_key + 40);
}

BOOST_AUTO_TEST_CASE(key_schedule_128)
{
    const unsigned char w[40*4] = {
    		0x2b, 0x7e, 0x15, 0x16,
    		0x28, 0xae, 0xd2, 0xa6,
    		0xab, 0xf7, 0x15, 0x88,
    		0x09, 0xcf, 0x4f, 0x3c,
    		0xa0, 0xfa, 0xfe, 0x17,
    		0x88, 0x54, 0x2c, 0xb1,
    		0x23, 0xa3, 0x39, 0x39,
    		0x2a, 0x6c, 0x76, 0x05,
    		0xf2, 0xc2, 0x95, 0xf2,
    		0x7a, 0x96, 0xb9, 0x43,
    		0x59, 0x35, 0x80, 0x7a,
    		0x73, 0x59, 0xf6, 0x7f,
    		0x3d, 0x80, 0x47, 0x7d,
    		0x47, 0x16, 0xfe, 0x3e,
    		0x1e, 0x23, 0x7e, 0x44,
    		0x6d, 0x7a, 0x88, 0x3b,
    		0xef, 0x44, 0xa5, 0x41,
    		0xa8, 0x52, 0x5b, 0x7f,
    		0xb6, 0x71, 0x25, 0x3b,
    		0xdb, 0x0b, 0xad, 0x00,
    		0xd4, 0xd1, 0xc6, 0xf8,
    		0x7c, 0x83, 0x9d, 0x87,
    		0xca, 0xf2, 0xb8, 0xbc,
    		0x11, 0xf9, 0x15, 0xbc,
    		0x6d, 0x88, 0xa3, 0x7a,
    		0x11, 0x0b, 0x3e, 0xfd,
    		0xdb, 0xf9, 0x86, 0x41,
    		0xca, 0x00, 0x93, 0xfd,
    		0x4e, 0x54, 0xf7, 0x0e,
    		0x5f, 0x5f, 0xc9, 0xf3,
    		0x84, 0xa6, 0x4f, 0xb2,
    		0x4e, 0xa6, 0xdc, 0x4f,
    		0xea, 0xd2, 0x73, 0x21,
    		0xb5, 0x8d, 0xba, 0xd2,
    		0x31, 0x2b, 0xf5, 0x60,
    		0x7f, 0x8d, 0x29, 0x2f,
    		0xac, 0x77, 0x66, 0xf3,
    		0x19, 0xfa, 0xdc, 0x21,
    		0x28, 0xd1, 0x29, 0x41,
    		0x57, 0x5c, 0x00, 0x6e
    };
    AES_KEY ek;
    AES_set_encrypt_key((const unsigned char *) &k, 128, &ek);
    int n_words = (ek.rounds+1)*4;
    int n_bytes = n_words * 4;
    uint32_t big_rd_key[40];
    big((uint32_t*)&ek.rd_key,(uint32_t*)&big_rd_key,n_words);
    hexdump("TV_KEY", (unsigned char *) &w, sizeof(w));
    hexdump("AES_KEY", (unsigned char *) &big_rd_key, n_bytes);
    BOOST_CHECK_EQUAL_COLLECTIONS(w, w + 40*4,(unsigned char *)big_rd_key, ((unsigned char *) big_rd_key) + 40*4);
}
