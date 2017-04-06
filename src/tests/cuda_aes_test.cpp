
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

// Test SubBytes Only
