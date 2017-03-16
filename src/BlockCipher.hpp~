namespace paracrypt {

    class BlockCipher {
      public:
	virtual int encrypt(char in[], char out[], int n_blocks) = 0;
	virtual int decrypt(char in[], char out[], int n_blocks) = 0;
	virtual int setKey(char key[], int bits) = 0;
	virtual int setBlockSize(int bits) = 0;
    };

}
