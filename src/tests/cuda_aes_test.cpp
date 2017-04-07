
BOOST_AUTO_TEST_CASE(cuda_ecb_aes_16b)
{
    unsigned char data[128] = {
	0x32U, 0x43U, 0xf6U, 0xa8U,
	0x88U, 0x5aU, 0x30U, 0x8dU,
	0x31U, 0x31U, 0x98U, 0xa2U,
	0xe0U, 0x37U, 0x07U, 0x34U
    };
    const unsigned char expected_output[128] = {
	0x39U, 0x02U, 0xdcU, 0x19U,
	0x25U, 0xdcU, 0x11U, 0x6aU,
	0x84U, 0x09U, 0x85U, 0x0bU,
	0x1dU, 0xfbU, 0x97U, 0x32U
    };

    paracrypt::CUDACipherDevice * gpu = new paracrypt::CUDACipherDevice(0);
    paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES16B();
    aes->setKey(k,128);
    aes->setDevice(gpu);
    aes->malloc(1);
    aes->encrypt((unsigned char *) &data, (unsigned char *) &data, 1);

    delete aes;
    delete gpu;
}

BOOST_AUTO_TEST_CASE(cuda_16b_round_key)
{
	_16B result = aes_add_16B_round_key_call
			(
					0x328831e0U,
					0x435a3137U,
					0xf6309807U,
					0xa88da234U,
					0x2b28ab09U,
					0x7eaef7cfU,
					0x15d2154fU,
					0x16a6883cU
			);
	BOOST_CHECK_EQUAL(result.w1,0x19a09ae9);
	BOOST_CHECK_EQUAL(result.w2,0x3df4c6f8);
	BOOST_CHECK_EQUAL(result.w3,0xe3e28d48);
	BOOST_CHECK_EQUAL(result.w4,0xbe2b2a08);
}

// Test SubBytes Only
