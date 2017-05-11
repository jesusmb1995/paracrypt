#include "Launcher.hpp"
#include "cipher/AES/CudaAES.hpp"

template < class Cipher_t >
void paracrypt::Launcher::freeCiphers(Cipher_t* ciphers[], unsigned int n)
{
	BOOST_STATIC_ASSERT((boost::is_base_of<BlockCipher, Cipher_t>::value));
    for(unsigned int c = 0; c < n; c++) {
    	delete ciphers[c];
    }
    delete[] ciphers;	
}

template < class CudaAES_t >
CudaAES_t** paracrypt::Launcher::linkAES(
		CUDACipherDevice* devices[], 
		unsigned int n, 
		const unsigned char key[], 
		int keyBits,
		bool constantKey,
		bool constantTables,
		unsigned int *nCiphers // save result here
){
	BOOST_STATIC_ASSERT((boost::is_base_of<paracrypt::CudaAES, CudaAES_t>::value));
	
	std::vector<CudaAES_t*> ciphers;
	
	for(unsigned int d = 0; d < n; d++) {
		for(int i = 0; i < devices[d]->getConcurrentKernels(); i++) {
			CudaAES_t* c = new CudaAES_t();
			c->setDevice(devices[d]);
			c->constantKey(constantKey);
			c->constantTables(constantTables);
			if(d == 0 && i == 0) {
				c->setKey(key,keyBits);
			} else {
				c->setEncryptionKey(ciphers.at(0)->getEncryptionExpandedKey());
			}
			ciphers.push_back(c);
		}
	}
	
	*nCiphers = ciphers.size();
	CudaAES_t** cArray = new CudaAES_t*[*nCiphers] ;
	std::copy(ciphers.begin(), ciphers.end(), cArray);
	return cArray;
}

template < class CudaAES_t >
void paracrypt::Launcher::launchSharedIOCudaAES(
		std::string inFileName,
		std::string outFileName,
		const unsigned char key[],
		int key_bits,
		bool constantKey,
		bool constantTables,
		std::streampos begin,
		std::streampos end
 ){
	int nDevices = paracrypt::CUDACipherDevice::getDevicesCount();
	CUDACipherDevice** devices = paracrypt::CUDACipherDevice::instantiateAllDevices();
	SharedIO* io = paracrypt::Launcher::newAdjustedSharedIO(
			inFileName, outFileName, 16,
			devices, nDevices,
			begin, end
	);

	unsigned int nCiphers;
	CudaAES_t** ciphers = paracrypt::Launcher::linkAES<CudaAES_t>(
			devices, nDevices,
			key, key_bits,
			constantKey, constantTables,
			&nCiphers
	);

	// cast to CUDABlockCipher* array
	CUDABlockCipher** cudaBlockCiphers = new CUDABlockCipher*[nCiphers];
	for(unsigned int i = 0; i < nCiphers; i++) {
		cudaBlockCiphers[i] = ciphers[i];
	}
	delete[] ciphers;
	
	paracrypt::Launcher::encrypt(cudaBlockCiphers, nCiphers, io);

	paracrypt::Launcher::freeCiphers<CUDABlockCipher>(cudaBlockCiphers,nCiphers);
    delete io;
    paracrypt::CUDACipherDevice::freeAllDevices(devices);
}