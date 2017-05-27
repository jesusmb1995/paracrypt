#include "Launcher.hpp"
#include "cipher/AES/CudaAES.hpp"
#include "logging.hpp"

template < class Cipher_t >
void paracrypt::Launcher::freeCiphers(Cipher_t* ciphers[], unsigned int n)
{
	BOOST_STATIC_ASSERT((boost::is_base_of<BlockCipher, Cipher_t>::value));
    for(unsigned int c = 0; c < n; c++) {
    	delete ciphers[c];
    }
    delete[] ciphers;	
}

// NOTE: Is the caller responsability to malloc desired number of blocks
//        per each cipher
template < class CudaAES_t >
CudaAES_t** paracrypt::Launcher::linkAES(
		operation_t op,
		CUDACipherDevice* devices[], 
		unsigned int n, 
		const unsigned char key[], 
		int keyBits,
		bool constantKey,
		bool constantTables,
		paracrypt::BlockCipher::Mode m,
		const unsigned char iv[], 
		int ivBits,
		unsigned int *nCiphers // save result here
){
	BOOST_STATIC_ASSERT((boost::is_base_of<paracrypt::CudaAES, CudaAES_t>::value));
	
	std::vector<CudaAES_t*> ciphers;
	
	for(unsigned int d = 0; d < n; d++) {
		for(int i = 0; i < devices[d]->getConcurrentKernels(); i++) {
			CudaAES_t* c;
			if(d == 0 && i == 0) {
				c = new CudaAES_t();
				c->setDevice(devices[d]);
				c->setMode(m);
				if(m != paracrypt::BlockCipher::ECB) {
					c->setIV(iv,ivBits);
				}
				c->constantKey(constantKey);
				c->constantTables(constantTables);
				c->setKey(key,keyBits);
				switch(op) {
				case paracrypt::Launcher::ENCRYPT:
					c->initDeviceEKey(); 
					c->initDeviceTe();
					break;
				case paracrypt::Launcher::DECRYPT:
					c->initDeviceDKey(); 
					c->initDeviceTd();
					break;
				default:
					ERR("Unknown cipher operation.");
				}				
			} else if(i == 0) {
				// each new cipher within the same GPU uses 
				//  its own stream
				c = new CudaAES_t();
				c->setMode(m);
				if(m == paracrypt::BlockCipher::CTR) {
					// All the CTR ciphers have the
					// same noence. On the other hand,
					// the IV is only set to the first
					// cipher for CBC and CFB modes
					c->setIV(iv,ivBits);
				}
				c->setDevice(devices[d]);
				c->constantKey(constantKey);
				c->constantTables(constantTables);
				// reuse expanded key, do not waste CPU resources
				//  expanding the key again
				switch(op) {
				case paracrypt::Launcher::ENCRYPT:
					c->setEncryptionKey(ciphers.at(0)->getEncryptionExpandedKey());
					c->initDeviceEKey();
					c->initDeviceTe();
					break;
				case paracrypt::Launcher::DECRYPT:
					c->setDecryptionKey(ciphers.at(0)->getDecryptionExpandedKey());
					c->initDeviceDKey();
					c->initDeviceTd();
					break;
				default:
					ERR("Unknown cipher operation.");
				}
			} else {
				// reuse keys and tables already available in the same GPU device,
				//   do not waste GPU resources having multiple copies of the
				//   same key in the same GPU.
				c = new CudaAES_t(ciphers.back());
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
		operation_t op,
		std::string inFileName,
		std::string outFileName,
		const unsigned char key[],
		int key_bits,
		bool constantKey,
		bool constantTables,
		paracrypt::BlockCipher::Mode m,
		const unsigned char iv[], 
		int ivBits,
		bool outOfOrder,
		std::streampos begin,
		std::streampos end
 ){
	LOG_TRACE(boost::format("Launcher input file %s")  % inFileName );
	LOG_TRACE(boost::format("Launcher output file %s") % outFileName);
	
	int nDevices = paracrypt::CUDACipherDevice::getDevicesCount();
	CUDACipherDevice** devices = paracrypt::CUDACipherDevice::instantiateAllDevices();
	SharedIO* io = paracrypt::Launcher::newAdjustedSharedIO(
			inFileName, outFileName, 16,
			devices, nDevices,
			begin, end
	);
	switch(m) {
		case paracrypt::BlockCipher::ECB:
		case paracrypt::BlockCipher::CBC:
		case paracrypt::BlockCipher::CFB:
			io->setPadding(paracrypt::BlockIO::PKCS7);
			break;
		// CTR mode does NOT require padding
		case paracrypt::BlockCipher::CTR:
		case paracrypt::BlockCipher::GCM:
			io->setPadding(paracrypt::BlockIO::UNPADDED);
			break;
	}

	unsigned int nCiphers;
	CudaAES_t** ciphers = paracrypt::Launcher::linkAES<CudaAES_t>(
			op,
			devices, nDevices,
			key, key_bits,
			constantKey, constantTables,
			m, iv, ivBits,
			&nCiphers
	);

	// cast to CUDABlockCipher* array
	CUDABlockCipher** cudaBlockCiphers = new CUDABlockCipher*[nCiphers];
	for(unsigned int i = 0; i < nCiphers; i++) {
		cudaBlockCiphers[i] = ciphers[i];
	}
	delete[] ciphers;

	LOG_TRACE("Launcher: starting encryption...");
	operation(op,cudaBlockCiphers, nCiphers, io, outOfOrder);
	
	LOG_TRACE("Launcher: freeying ciphers...");
	paracrypt::Launcher::freeCiphers<CUDABlockCipher>(cudaBlockCiphers,nCiphers);
	
	LOG_TRACE("Launcher: deleting IO...");
    delete io;
    
    LOG_TRACE("Launcher: freeying devices...");
    paracrypt::CUDACipherDevice::freeAllDevices(devices);
}