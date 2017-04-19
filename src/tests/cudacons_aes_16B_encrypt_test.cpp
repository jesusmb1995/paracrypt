BOOST_AUTO_TEST_CASE(cuda_kc_tc_encryptecb_aes128_16b_16MiB)
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
    paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES16B();
    aes->constantKey(true);
    aes->constantTables(true);
    aes->setKey(k,128);
    aes->setDevice(gpu);
    aes->malloc(n_blocks);

    Timer* t = new Timer();
    t->tic();
    aes->encrypt(data, data, n_blocks);
    double clocks = t->toc();
    printf("CudaEcbAES16B needs %f to encrypt 1048576 blocks\n",clocks);

    delete aes;
    delete gpu;

    for(int i=0; i < n_blocks; i++) {
    	BOOST_REQUIRE_EQUAL_COLLECTIONS(data+(i*16),data+(i*16)+16,output,output+16);
    }
    free(data);
}

BOOST_AUTO_TEST_CASE(cuda_tc_encryptecb_aes128_16b_16MiB)
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
    paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES16B();
    aes->constantTables(true);
    aes->setKey(k,128);
    aes->setDevice(gpu);
    aes->malloc(n_blocks);

    Timer* t = new Timer();
    t->tic();
    aes->encrypt(data, data, n_blocks);
    double clocks = t->toc();
    printf("CudaEcbAES16B needs %f to encrypt 1048576 blocks\n",clocks);

    delete aes;
    delete gpu;

    for(int i=0; i < n_blocks; i++) {
    	BOOST_REQUIRE_EQUAL_COLLECTIONS(data+(i*16),data+(i*16)+16,output,output+16);
    }
    free(data);
}

BOOST_AUTO_TEST_CASE(cuda_kc_encryptecb_aes128_16b_16MiB)
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
    paracrypt::CudaAES * aes = new paracrypt::CudaEcbAES16B();
    aes->constantKey(true);
    aes->setKey(k,128);
    aes->setDevice(gpu);
    aes->malloc(n_blocks);

    Timer* t = new Timer();
    t->tic();
    aes->encrypt(data, data, n_blocks);
    double clocks = t->toc();
    printf("CudaEcbAES16B needs %f to encrypt 1048576 blocks\n",clocks);

    delete aes;
    delete gpu;

    for(int i=0; i < n_blocks; i++) {
    	BOOST_REQUIRE_EQUAL_COLLECTIONS(data+(i*16),data+(i*16)+16,output,output+16);
    }
    free(data);
}
