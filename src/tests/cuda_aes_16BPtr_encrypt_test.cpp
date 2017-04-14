BOOST_AUTO_TEST_CASE(cuda_encryptecb_aes128_16b_ptr_singleblock)
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
    paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES16BPtr();
    aes->setKey(k,128);
    aes->setDevice(gpu);
    aes->malloc(1);
    aes->encrypt((unsigned char *) &data, (unsigned char *) &data, 1);

    delete aes;
    delete gpu;

    hexdump("expected",output,16);
    hexdump("data",data,16);
    BOOST_CHECK_EQUAL_COLLECTIONS(data,data+16,output,output+16);
}

BOOST_AUTO_TEST_CASE(cuda_encryptecb_aes192_16b_ptr_singleblock)
{
    unsigned char data[16] = {
	0x00U, 0x11U, 0x22U, 0x33U,
	0x44U, 0x55U, 0x66U, 0x77U,
	0x88U, 0x99U, 0xaaU, 0xbbU,
	0xccU, 0xddU, 0xeeU, 0xffU
    };
    const unsigned char output[16] = {
	0xddU, 0xa9U, 0x7cU, 0xa4U,
	0x86U, 0x4cU, 0xdfU, 0xe0U,
	0x6eU, 0xafU, 0x70U, 0xa0U,
	0xecU, 0x0dU, 0x71U, 0x91U
    };

    paracrypt::CUDACipherDevice * gpu = new paracrypt::CUDACipherDevice(0);
    paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES16BPtr();
    aes->setKey(k2,192);
    aes->setDevice(gpu);
    aes->malloc(1);
    aes->encrypt((unsigned char *) &data, (unsigned char *) &data, 1);

    delete aes;
    delete gpu;

    hexdump("expected",output,16);
    hexdump("data",data,16);
    BOOST_CHECK_EQUAL_COLLECTIONS(data,data+16,output,output+16);
}

BOOST_AUTO_TEST_CASE(cuda_encryptecb_aes256_16b_ptr_singleblock)
{
    unsigned char data[16] = {
	0x00U, 0x11U, 0x22U, 0x33U,
	0x44U, 0x55U, 0x66U, 0x77U,
	0x88U, 0x99U, 0xaaU, 0xbbU,
	0xccU, 0xddU, 0xeeU, 0xffU
    };
    const unsigned char output[16] = {
    0x8eU, 0xa2U, 0xb7u, 0xcaU,
    0x51U, 0x67U, 0x45U, 0xbfU,
    0xeaU, 0xfcU, 0x49U, 0x90U,
    0x4bU, 0x49U, 0x60U, 0x89U
    };

    paracrypt::CUDACipherDevice * gpu = new paracrypt::CUDACipherDevice(0);
    paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES16BPtr();
    aes->setKey(k3,256);
    aes->setDevice(gpu);
    aes->malloc(1);
    aes->encrypt((unsigned char *) &data, (unsigned char *) &data, 1);

    delete aes;
    delete gpu;

    hexdump("expected",output,16);
    hexdump("data",data,16);
    BOOST_CHECK_EQUAL_COLLECTIONS(data,data+16,output,output+16);
}

BOOST_AUTO_TEST_CASE(cuda_encryptecb_aes128_16b_ptr_1kblocks)
{
    unsigned char block[16] = {
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
    unsigned char data[16*1024];
    for(int i=0; i < 1024; i++) {
    	memcpy(data+(i*16),block,16);
    }

    paracrypt::CUDACipherDevice * gpu = new paracrypt::CUDACipherDevice(0);
    paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES16BPtr();
    aes->setKey(k,128);
    aes->setDevice(gpu);
    aes->malloc(1024);
    aes->encrypt((unsigned char *) &data, (unsigned char *) &data, 1024);

    delete aes;
    delete gpu;

    for(int i=0; i < 1024; i++) {
    	BOOST_REQUIRE_EQUAL_COLLECTIONS(data+(i*16),data+(i*16)+16,output,output+16);
    }
}

BOOST_AUTO_TEST_CASE(cuda_encryptecb_aes128_16b_ptr_nodd)
{
    unsigned char block[16] = {
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
    unsigned char data[16*1025];
    for(int i=0; i < 1025; i++) {
    	memcpy(data+(i*16),block,16);
    }

    paracrypt::CUDACipherDevice * gpu = new paracrypt::CUDACipherDevice(0);
    paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES16BPtr();
    aes->setKey(k,128);
    aes->setDevice(gpu);
    aes->malloc(1025);
    aes->encrypt((unsigned char *) &data, (unsigned char *) &data, 1025);

    delete aes;
    delete gpu;

    for(int i=0; i < 1025; i++) {
    	BOOST_REQUIRE_EQUAL_COLLECTIONS(data+(i*16),data+(i*16)+16,output,output+16);
    }
}

BOOST_AUTO_TEST_CASE(cuda_encryptecb_aes128_16b_ptr_16MiB)
{
	int n_blocks = 1048576;

    unsigned char block[16] = {
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
    unsigned char *data;
    data = (unsigned char*) malloc(16*n_blocks); // 16 MiB file
    for(int i=0; i < n_blocks; i++) {
    	memcpy(data+(i*16),block,16);
    }
    assert(data != NULL);

    paracrypt::CUDACipherDevice * gpu = new paracrypt::CUDACipherDevice(0);
    paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES16BPtr();
    aes->setKey(k,128);
    aes->setDevice(gpu);
    aes->malloc(n_blocks);

    Timer* t = new Timer();
    t->tic();
    aes->encrypt(data, data, n_blocks);
    double clocks = t->toc();
    printf("CudaEcbAES16BPtr needs %f to encrypt 1048576 blocks\n",clocks);

    delete aes;
    delete gpu;

    for(int i=0; i < n_blocks; i++) {
    	BOOST_REQUIRE_EQUAL_COLLECTIONS(data+(i*16),data+(i*16)+16,output,output+16);
    }
    free(data);
}