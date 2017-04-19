BOOST_AUTO_TEST_CASE(cuda_decryptecb_aes128_16b_singleblock)
{
    unsigned char output[16] = {
	0x32U, 0x43U, 0xf6U, 0xa8U,
	0x88U, 0x5aU, 0x30U, 0x8dU,
	0x31U, 0x31U, 0x98U, 0xa2U,
	0xe0U, 0x37U, 0x07U, 0x34U
    };
    const unsigned char data[16] = {
	0x39U, 0x25U, 0x84U, 0x1dU,
	0x02U, 0xdcU, 0x09U, 0xfbU,
	0xdcU, 0x11U, 0x85U, 0x97U,
	0x19U, 0x6aU, 0x0bU, 0x32U
    };

    paracrypt::CUDACipherDevice * gpu = new paracrypt::CUDACipherDevice(0);
    paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES16B();
    aes->setKey(k,128);
    aes->setDevice(gpu);
    aes->malloc(1);
    aes->decrypt((unsigned char *) &data, (unsigned char *) &data, 1);

    delete aes;
    delete gpu;

    hexdump("expected",output,16);
    hexdump("data",data,16);
    BOOST_CHECK_EQUAL_COLLECTIONS(data,data+16,output,output+16);
}

BOOST_AUTO_TEST_CASE(cuda_decryptecb_aes192_16b_singleblock)
{
    unsigned char output[16] = {
    	0x00U, 0x11U, 0x22U, 0x33U,
    	0x44U, 0x55U, 0x66U, 0x77U,
    	0x88U, 0x99U, 0xaaU, 0xbbU,
    	0xccU, 0xddU, 0xeeU, 0xffU
    };
    const unsigned char data[16] = {
    		0xddU, 0xa9U, 0x7cU, 0xa4U,
    		0x86U, 0x4cU, 0xdfU, 0xe0U,
    		0x6eU, 0xafU, 0x70U, 0xa0U,
    		0xecU, 0x0dU, 0x71U, 0x91U
    };
    paracrypt::CUDACipherDevice * gpu = new paracrypt::CUDACipherDevice(0);
    paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES16B();
    aes->setKey(k2,192);
    aes->setDevice(gpu);
    aes->malloc(1);
    aes->decrypt((unsigned char *) &data, (unsigned char *) &data, 1);

    delete aes;
    delete gpu;

    hexdump("expected",output,16);
    hexdump("data",data,16);
    BOOST_CHECK_EQUAL_COLLECTIONS(data,data+16,output,output+16);
}

BOOST_AUTO_TEST_CASE(cuda_decryptecb_aes256_16b_singleblock)
{
    unsigned char output[16] = {
	0x00U, 0x11U, 0x22U, 0x33U,
	0x44U, 0x55U, 0x66U, 0x77U,
	0x88U, 0x99U, 0xaaU, 0xbbU,
	0xccU, 0xddU, 0xeeU, 0xffU
    };
    const unsigned char data[16] = {
    0x8eU, 0xa2U, 0xb7u, 0xcaU,
    0x51U, 0x67U, 0x45U, 0xbfU,
    0xeaU, 0xfcU, 0x49U, 0x90U,
    0x4bU, 0x49U, 0x60U, 0x89U
    };
    paracrypt::CUDACipherDevice * gpu = new paracrypt::CUDACipherDevice(0);
    paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES16B();
    aes->setKey(k3,256);
    aes->setDevice(gpu);
    aes->malloc(1);
    aes->decrypt((unsigned char *) &data, (unsigned char *) &data, 1);

    delete aes;
    delete gpu;

    hexdump("expected",output,16);
    hexdump("data",data,16);
    BOOST_CHECK_EQUAL_COLLECTIONS(data,data+16,output,output+16);
}

// Test SubBytes Only
