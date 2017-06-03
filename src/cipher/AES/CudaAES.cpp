/*
 *  Copyright (C) 2017 Jesus Martin Berlanga. All Rights Reserved.
 *
 *  This file is part of Paracrypt.
 *
 *  Paracrypt is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Paracrypt is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Paracrypt.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "CudaAES.hpp"
#include "device/CUDACipherDevice.hpp"
#include "cipher/CUDABlockCipher.hpp"
#include "cipher/BlockCipher.hpp"
#include "CudaConstant.cuh"
#include "io/CudaPinned.hpp"
#include "cipher/AES/CudaAESTTables.cpp"

#define TO_IMPLEMENT_OUT_OF_PLACE() \
ERR("Only in-place encryption and decryption is supported in " \
	" this release. Out-of-place algorithm would consume" \
    " more GPU memory than the in-place version and thus" \
    " it's not implemented yet. It could be implemented to " \
    " empirically compare the performance." \
    "\n" \
    " This is a open-source project - you are more than welcome to" \
    " implement the out-of-place version and prepare a benchmark :)");

paracrypt::CudaAES::CudaAES()
	: paracrypt::CUDABlockCipher::CUDABlockCipher()
{
	this->deviceEKeyConstant = false;
	this->deviceDKeyConstant = false;
	this->useConstantKey = false;
	this->useConstantTables = false;
	this->enInstantiatedButInOtherDevice = false;
	this->deInstantiatedButInOtherDevice = false;
	this->inPlace = true; // use neighbours by default
	this->pin = new CudaPinned();
	this->ivIsCopy = false;
}

paracrypt::CudaAES::CudaAES(CudaAES* aes)
	: paracrypt::CudaAES::AES(aes), paracrypt::CUDABlockCipher::CUDABlockCipher(aes)
{
	this->setDevice(aes->device);
	this->deviceEKey = aes->deviceEKey;
	this->deviceEKeyConstant = aes->deviceEKeyConstant;
	this->deviceDKey = aes->deviceDKey;
	this->deviceDKeyConstant = aes->deviceDKeyConstant;
	this->deviceTe0 = aes->deviceTe0;
	this->deviceTe1 = aes->deviceTe1;
	this->deviceTe2 = aes->deviceTe2;
	this->deviceTe3 = aes->deviceTe3;
	this->deviceTd0 = aes->deviceTd0;
	this->deviceTd1 = aes->deviceTd1;
	this->deviceTd2 = aes->deviceTd2;
	this->deviceTd3 = aes->deviceTd3;
	this->deviceTd4 = aes->deviceTd4;
	this->useConstantKey = aes->useConstantKey;
	this->useConstantTables = aes->useConstantTables;
//	this->malloc(aes->n_blocks);
	this->enInstantiatedButInOtherDevice = false;
	this->deInstantiatedButInOtherDevice = false;
	this->deviceIV = aes->deviceIV;
	this->ivIsCopy = true;
	this->pin = aes->pin;
}

paracrypt::CudaAES::~CudaAES()
{
    if (!this->isCopy && this->deviceEKey != NULL && !deviceEKeyConstant) {
	this->getDevice()->free(this->deviceEKey);
    }
    if (!this->isCopy && this->deviceDKey != NULL && !deviceDKeyConstant) {
    	this->getDevice()->free(this->deviceDKey);
    }
    if (this->data != NULL) {
	this->getDevice()->free(this->data);
	this->getDevice()->delStream(this->stream);
    }
    if (!this->isCopy && this->deviceTe0 != NULL) {
	this->getDevice()->free(this->deviceTe0);
    }
    if (!this->isCopy && this->deviceTe1 != NULL) {
	this->getDevice()->free(this->deviceTe1);
    }
    if (!this->isCopy && this->deviceTe2 != NULL) {
	this->getDevice()->free(this->deviceTe2);
    }
    if (!this->isCopy && this->deviceTe3 != NULL) {
	this->getDevice()->free(this->deviceTe3);
    }
    if (!this->isCopy && this->deviceTd0 != NULL) {
	this->getDevice()->free(this->deviceTd0);
    }
    if (!this->isCopy && this->deviceTd1 != NULL) {
	this->getDevice()->free(this->deviceTd1);
    }
    if (!this->isCopy && this->deviceTd2 != NULL) {
	this->getDevice()->free(this->deviceTd2);
    }
    if (!this->isCopy && this->deviceTd3 != NULL) {
	this->getDevice()->free(this->deviceTd3);
    }
    if (!this->isCopy && this->deviceTd4 != NULL) {
	this->getDevice()->free(this->deviceTd4);
    }
    if (!this->ivIsCopy && this->deviceIV != NULL) {
    DEV_TRACE(boost::format("Freeing IV %x") % (void*) this->deviceIV);
	this->getDevice()->free(this->deviceIV);
    }
    if(this->neighborsDev != NULL) {
    	this->getDevice()->free(this->neighborsDev);
    }
    if(this->neighborsPin != NULL) {
    	this->pin->free((void*)this->neighborsPin);
    }
}

// must be called after setKey
void paracrypt::CudaAES::setDevice(CUDACipherDevice * device)
{
	if (!this->isCopy && this->deviceEKey != NULL && !deviceEKeyConstant) {
		this->getDevice()->free(this->deviceEKey);
		this->deviceEKey = NULL;
	}
	if (!this->isCopy && this->deviceDKey != NULL && !deviceDKeyConstant) {
		this->getDevice()->free(this->deviceDKey);
		this->deviceDKey = NULL;
	}
	if (this->data != NULL) {
		this->getDevice()->free(this->data);
		this->data = NULL;
		this->getDevice()->delStream(this->stream);
	}
		if (!this->isCopy && this->deviceTe0 != NULL) {
		this->getDevice()->free(this->deviceTe0);
		this->deviceTe0 = NULL;
		}
		if (!this->isCopy && this->deviceTe1 != NULL) {
		this->getDevice()->free(this->deviceTe1);
		this->deviceTe1 = NULL;
		}
		if (!this->isCopy && this->deviceTe2 != NULL) {
		this->getDevice()->free(this->deviceTe2);
		this->deviceTe2 = NULL;
		}
		if (!this->isCopy && this->deviceTe3 != NULL) {
		this->getDevice()->free(this->deviceTe3);
		this->deviceTe3 = NULL;
		}
		if (!this->isCopy && this->deviceTd0 != NULL) {
		this->getDevice()->free(this->deviceTd0);
		this->deviceTd0 = NULL;
		}
		if (!this->isCopy && this->deviceTd1 != NULL) {
		this->getDevice()->free(this->deviceTd1);
		this->deviceTd1 = NULL;
		}
		if (!this->isCopy && this->deviceTd2 != NULL) {
		this->getDevice()->free(this->deviceTd2);
		this->deviceTd2 = NULL;
		}
		if (!this->isCopy && this->deviceTd3 != NULL) {
		this->getDevice()->free(this->deviceTd3);
		this->deviceTd3 = NULL;
		}
		if (!this->isCopy && this->deviceTd4 != NULL) {
		this->getDevice()->free(this->deviceTd4);
		this->deviceTd4 = NULL;
		}
	    if (!this->ivIsCopy && this->deviceIV != NULL) {
		DEV_TRACE(boost::format("Freeing IV %x") % (void*) this->deviceIV);
		this->getDevice()->free(this->deviceIV);
	    }
	    if(this->neighborsDev != NULL) {
	    	this->getDevice()->free(this->neighborsDev);
	    	this->neighborsDev = NULL;
	    }
	    if(this->neighborsPin != NULL) {
	    	this->pin->free((void*)this->neighborsPin);
	    	this->neighborsPin = NULL;
	    }
		this->device = device;
		this->stream = this->getDevice()->addStream();
		LOG_INF(boost::format("New cipher %x at device %x stream %i")
			% (void*) this
			% (void*) this->device
			% this->stream);
}

paracrypt::CUDACipherDevice * paracrypt::CudaAES::getDevice()
{
    return this->device;
}

void paracrypt::CudaAES::initDeviceEKey() {
	if(this->deInstantiatedButInOtherDevice || (!this->isCopy && this->deviceEKey == NULL)) {
		if(this->constantKey()) {
			int nKeyWords = (4 * (this->getEncryptionExpandedKey()->rounds + 1));
			this->deviceEKey = __setAesKey__(this->getEncryptionExpandedKey()->rd_key,nKeyWords);
			deviceEKeyConstant = true;
		}
		else {
		size_t keySize =
			(4 * (this->getEncryptionExpandedKey()->rounds + 1)) * sizeof(uint32_t);
		this->getDevice()->malloc((void **) &(this->deviceEKey), keySize);
		this->getDevice()->malloc((void **) &(this->deviceEKey), keySize);
		// copy to default stream so that all kernels in other streams can access the key
		this->getDevice()->memcpyTo(this->getEncryptionExpandedKey()->rd_key,
					this->deviceEKey, keySize);
		deviceEKeyConstant = false;
		}
	}
}

void paracrypt::CudaAES::initDeviceDKey() {
	if(this->getMode() == paracrypt::BlockCipher::CTR
			|| this->getMode() == paracrypt::BlockCipher::GCM
			|| this->getMode() == paracrypt::BlockCipher::CFB
	) {
		// CTR and CFB modes use the encryption function even for decryption
		initDeviceEKey();
	}
	else if(this->deInstantiatedButInOtherDevice || (!this->isCopy &&  this->deviceDKey == NULL)) {
		if(this->constantKey()) {
			int nKeyWords = (4 * (this->getDecryptionExpandedKey()->rounds + 1));
			this->deviceDKey = __setAesKey__(this->getDecryptionExpandedKey()->rd_key,nKeyWords);
			deviceDKeyConstant = true;
		}
		else {
		size_t keySize =
		(4 * (this->getDecryptionExpandedKey()->rounds + 1)) * sizeof(uint32_t);
		this->getDevice()->malloc((void **) &(this->deviceDKey), keySize);
		this->getDevice()->malloc((void **) &(this->deviceDKey), keySize);
		this->getDevice()->memcpyTo(this->getDecryptionExpandedKey()->rd_key,
					this->deviceDKey, keySize);
		deviceDKeyConstant = false;
		}
	}
}


// Only instantiate key when it is needed,
//  avoid instantiating both encryption/decryption
//  keys and wasting GPU mem. resources.
uint32_t* paracrypt::CudaAES::getDeviceEKey()
{
	this->initDeviceEKey();
    return this->deviceEKey;
}

uint32_t* paracrypt::CudaAES::getDeviceDKey()
{
	this->initDeviceDKey();
    return this->deviceDKey;
}

//int paracrypt::CudaAES::setOtherDeviceEncryptionKey(AES_KEY * expandedKey)
//{
//    this->setEncryptionKey(expandedKey);
//	this->enInstantiatedButInOtherDevice = true;
//    return 0;
//}
//
//int paracrypt::CudaAES::setOtherDeviceDecryptionKey(AES_KEY * expandedKey)
//{
//    this->setDecryptionKey(expandedKey);
//    this->deInstantiatedButInOtherDevice = true;
//    return 0;
//}

void paracrypt::CudaAES::malloc(unsigned int n_blocks, bool isInplace)
{
    if (this->data != NULL) {
    	this->getDevice()->free(this->data);
    }
    int dataSize = AES_BLOCK_SIZE_B * n_blocks;
    this->getDevice()->malloc((void **) &(this->data), dataSize);

    if(this->neighborsDev != NULL) {
    	this->getDevice()->free(this->neighborsDev);
    }
    if(this->neighborsPin != NULL) {
    	this->pin->free((void*)this->neighborsPin);
    }
    this->inPlace = isInplace;
    if(!isInplace) {
    	TO_IMPLEMENT_OUT_OF_PLACE() // TODO allocate x2 mem.
    }
    if(this->inPlace && (this->getMode() == CBC || this->getMode() == CFB)) {
		int threadsPerCipherBlock = this->getThreadsPerCipherBlock();
    	int threadsPerBlock = this->getDevice()->getThreadsPerThreadBlock();
		this->cipherBlocksPerThreadBlock = threadsPerBlock / threadsPerCipherBlock;
		assert(threadsPerBlock % threadsPerCipherBlock == 0);
		this->nNeighbors = n_blocks / this->cipherBlocksPerThreadBlock;
		if(this->nNeighbors > 0 && n_blocks % this->cipherBlocksPerThreadBlock == 0)
			this->nNeighbors--;
		LOG_TRACE(boost::format("I will use %u copies of input blocks in"
				" addition to the %u original blocks.") % this->nNeighbors % n_blocks);
		this->neighSize = this->nNeighbors * (this->getBlockSize()/8);
		this->getDevice()->malloc((void **) &(this->neighborsDev), this->neighSize);
		this->pin->alloc((void**)&neighborsPin,this->neighSize);
    }
}

void paracrypt::CudaAES::setMode(Mode m)
{
	paracrypt::BlockCipher::setMode(m);
    if(this->neighborsDev != NULL && (m != CBC || m != CFB)) {
    	this->getDevice()->free(this->neighborsDev);
    	this->neighborsDev = NULL;
    }
}

void paracrypt::CudaAES::initDeviceTe()
{
	if(!this->constantTables()) {
		if (!this->isCopy && this->deviceTe0 == NULL)
		{
			this->getDevice()->malloc((void **) &(this->deviceTe0), TTABLE_SIZE); // 1024 = 256*4
			// memcpy to general stream 0 so that all copies of CudaAES can reutilize this table.
			this->getDevice()->memcpyTo((void*)Te0,this->deviceTe0, TTABLE_SIZE);
		}
		if (!this->isCopy && this->deviceTe1 == NULL)
		{
			this->getDevice()->malloc((void **) &(this->deviceTe1), TTABLE_SIZE);
			this->getDevice()->memcpyTo((void*)Te1,this->deviceTe1, TTABLE_SIZE);
		}
		if (!this->isCopy && this->deviceTe2 == NULL)
		{
			this->getDevice()->malloc((void **) &(this->deviceTe2), TTABLE_SIZE);
			this->getDevice()->memcpyTo((void*)Te2,this->deviceTe2, TTABLE_SIZE);
		}
		if (!this->isCopy && this->deviceTe3 == NULL)
		{
			this->getDevice()->malloc((void **) &(this->deviceTe3), TTABLE_SIZE);
			this->getDevice()->memcpyTo((void*)Te3,this->deviceTe3, TTABLE_SIZE);
		}
	}
}

void paracrypt::CudaAES::initDeviceTd()
{
	if(this->getMode() == paracrypt::BlockCipher::CTR
			|| this->getMode() == paracrypt::BlockCipher::GCM
			|| this->getMode() == paracrypt::BlockCipher::CFB
	) {
		// CTR and CFB modes use the encryption function even for decryption
		initDeviceTe();
	}
	else if(!this->constantTables()) {
		if (!this->isCopy && this->deviceTd0 == NULL)
		{
			this->getDevice()->malloc((void **) &(this->deviceTd0), TTABLE_SIZE);
			this->getDevice()->memcpyTo((void*)Td0,this->deviceTd0, TTABLE_SIZE);
		}
		if (!this->isCopy && this->deviceTd1 == NULL)
		{
			this->getDevice()->malloc((void **) &(this->deviceTd1), TTABLE_SIZE);
			this->getDevice()->memcpyTo((void*)Td1,this->deviceTd1, TTABLE_SIZE);
		}
		if (!this->isCopy && this->deviceTd2 == NULL)
		{
			this->getDevice()->malloc((void **) &(this->deviceTd2), TTABLE_SIZE);
			this->getDevice()->memcpyTo((void*)Td2,this->deviceTd2, TTABLE_SIZE);
		}
		if (!this->isCopy && this->deviceTd3 == NULL)
		{
			this->getDevice()->malloc((void **) &(this->deviceTd3), TTABLE_SIZE);
			this->getDevice()->memcpyTo((void*)Td3,this->deviceTd3, TTABLE_SIZE);
		}
		if (!this->isCopy && this->deviceTd4 == NULL)
		{
			this->getDevice()->malloc((void **) &(this->deviceTd4), 256);
			this->getDevice()->memcpyTo((void*)Td4,this->deviceTd4, 256);
		}
	}
}

AES_KEY *paracrypt::CudaAES::getDecryptionExpandedKey()
{
	AES_KEY* k;
	if(this->getMode() == paracrypt::BlockCipher::CTR
			|| this->getMode() == paracrypt::BlockCipher::GCM
			|| this->getMode() == paracrypt::BlockCipher::CFB
	){
		k = paracrypt::AES::getEncryptionExpandedKey();
	}
	else {
		k = paracrypt::AES::getDecryptionExpandedKey();
	}
	return k;
}

int paracrypt::CudaAES::setDecryptionKey(AES_KEY * expandedKey) {
	if(this->getMode() == paracrypt::BlockCipher::CTR
			|| this->getMode() == paracrypt::BlockCipher::GCM
			|| this->getMode() == paracrypt::BlockCipher::CFB
	){
		paracrypt::AES::setEncryptionKey(expandedKey);
	}
	else {
		paracrypt::AES::setDecryptionKey(expandedKey);
	}
	return 0;
}

void paracrypt::CudaAES::setIV(const unsigned char iv[], int bits)
{
	if(bits != 128) {
		ERR("Wrong IV size for AES (an 128 bit input vector is required).");
	}
   if ((!this->ivIsCopy && this->deviceIV == NULL) || this->isCopy) {
	   this->deviceIV = NULL;
	   this->getDevice()->malloc((void **) &(this->deviceIV), 16);
	   this->ivIsCopy = false;
	   DEV_TRACE(boost::format("Malloc 16 device bytes at IV %x") % (void*) this->deviceIV);
    }
	if (!this->ivIsCopy && this->deviceIV != NULL) {
		// TODO do not copy to device!! wait and copy at the same time
		//  we copy data in one single transference. This will produce
		//  a notable performance improvement in CBC and CFB modes.
		DEV_TRACE(boost::format("Memcpy 16 bytes to IV %x") % (void*) this->deviceIV);
		this->getDevice()->memcpyTo((void*)iv,(void*)this->deviceIV, 16);
	}
}

unsigned char* paracrypt::CudaAES::getIV()
{
	return this->deviceIV;
}

uint32_t*  paracrypt::CudaAES::getDeviceTe0()
{
	if(this->constantTables()) {
		return __Te0__();
	}
	else {
		this->initDeviceTe();
		return this->deviceTe0;
	}
}

uint32_t*  paracrypt::CudaAES::getDeviceTe1()
{
	if(this->constantTables()) {
		return __Te1__();
	}
	else {
		this->initDeviceTe();
		return this->deviceTe1;
	}
}

uint32_t* paracrypt::CudaAES::getDeviceTe2()
{
	if(this->constantTables()) {
		return __Te2__();
	}
	else {
		this->initDeviceTe();
		return this->deviceTe2;
	}
}

uint32_t* paracrypt::CudaAES::getDeviceTe3()
{
	if(this->constantTables()) {
		return __Te3__();
	}
	else {
		this->initDeviceTe();
		return this->deviceTe3;
	}
}

uint32_t* paracrypt::CudaAES::getDeviceTd0()
{
	if(this->constantTables()) {
		return __Td0__();
	}
	else {
		this->initDeviceTd();
		return this->deviceTd0;
	}
}

uint32_t* paracrypt::CudaAES::getDeviceTd1()
{
	if(this->constantTables()) {
		return __Td1__();
	}
	else {
		this->initDeviceTd();
		return this->deviceTd1;
	}
}

uint32_t* paracrypt::CudaAES::getDeviceTd2()
{
	if(this->constantTables()) {
		return __Td2__();
	}
	else {
		this->initDeviceTd();
		return this->deviceTd2;
	}
}

uint32_t* paracrypt::CudaAES::getDeviceTd3()
{
	if(this->constantTables()) {
		return __Td3__();
	}
	else {
		this->initDeviceTd();
		return this->deviceTd3;
	}
}

uint8_t* paracrypt::CudaAES::getDeviceTd4()
{
	if(this->constantTables()) {
		return __Td4__();
	}
	else {
		this->initDeviceTd();
		return this->deviceTd4;
	}
}

void paracrypt::CudaAES::constantKey(bool val){
	this->useConstantKey = val;
}
void paracrypt::CudaAES::constantTables(bool val){
	this->useConstantTables = val;
}
bool paracrypt::CudaAES::constantKey() {
	return this->useConstantKey;
}
bool paracrypt::CudaAES::constantTables(){
	return this->useConstantTables;
}

int paracrypt::CudaAES::setBlockSize(int bits) {
    return 0;
}

unsigned int paracrypt::CudaAES::getBlockSize() {
    return AES_BLOCK_SIZE;
}

int paracrypt::CudaAES::setKey(const unsigned char key[], int bits) {
    return paracrypt::AES::setKey(key,bits);
}

void paracrypt::CudaAES::waitFinish() {
	this->getDevice()->waitMemcpyFrom(this->stream);
}

bool paracrypt::CudaAES::checkFinish() {
	return this->getDevice()->checkMemcpyFrom(this->stream);
}

bool paracrypt::CudaAES::isInplace() {
	return this->inPlace;
}

// TODO do not copy to device!! wait and copy at the same time
//  we copy data in one single transference. This will produce
//  a notable performance improvement in CBC and CFB modes.
void paracrypt::CudaAES::transferNeighborsToGPU(
		const unsigned char blocks[],
		std::streamsize n_blocks)
{
	unsigned int blockSizeBytes = this->getBlockSize()/8;
	for(unsigned int i = 0; i < this->nNeighbors; i++) {
		// neighBlock calculation works for both CBC and CFB
		unsigned int neighBlock = ((i+1)*this->cipherBlocksPerThreadBlock)-1;
		DEV_TRACE(boost::format("Copying neighbor block %i") % neighBlock);
		unsigned int despPin = i*blockSizeBytes;
		unsigned int despBlocks = neighBlock*blockSizeBytes;
		std::memcpy(neighborsPin+despPin,blocks+despBlocks,blockSizeBytes);
	}
	this->getDevice()->memcpyTo(this->neighborsPin, this->neighborsDev, this->neighSize, this->stream);
}

int paracrypt::CudaAES::encrypt(const unsigned char in[],
				      const unsigned char out[],
				      std::streamsize n_blocks)
{
	if(this->getMode() == paracrypt::BlockCipher::CBC) {
		ERR("CBC or CFB encryption is not supported due to their parallel limitations."
			" Use OpenSSL instead. You can use the same key and input vector with "
			" Paracrypt for faster CBC/CFB decryption.");
	}

	int threadsPerCipherBlock = this->getThreadsPerCipherBlock();
    int gridSize = this->getDevice()->getGridSize(n_blocks, threadsPerCipherBlock);
    int threadsPerBlock = this->getDevice()->getThreadsPerThreadBlock();
    size_t dataSize = n_blocks * AES_BLOCK_SIZE_B;
    uint32_t *key = this->getDeviceEKey();
    assert(key != NULL);
    int rounds = this->getEncryptionExpandedKey()->rounds;

    // CFB does decryption and encryption is
    //  performed with encrypt cipher function
    //  so we have to include the neighbor transfer
    //  here.
	if(this->getMode() == paracrypt::BlockCipher::CFB) {
		if(this->inPlace) {
			if(in != out) {
				LOG_WAR("The cipher is configured to process data "
						"in-place but two different pointers are given.");
			}
			// only CBC and CFB use neighbors
			transferNeighborsToGPU(in,n_blocks);
		} else {
			if(in == out) {
				ERR("The cipher is not configured to process data in-place.");
			}
		}
	}

//    DEV_TRACE(boost::format("encryption key: %x") % key);
//    DEV_TRACE(boost::format("encryption data ptr: %x") % (int*) in);
//    DEV_TRACE(boost::format("encryption data size: %i") % dataSize);
//    DEV_TRACE(boost::format("encryption Te0: %x") % this->getDeviceTe0());
//    DEV_TRACE(boost::format("encryption Te1: %x") % this->getDeviceTe1());
//    DEV_TRACE(boost::format("encryption Te2: %x") % this->getDeviceTe2());
//    DEV_TRACE(boost::format("encryption Te3: %x") % this->getDeviceTe3());

    this->getDevice()->memcpyTo((void *) in, this->data, dataSize,
				this->stream);

	DEV_TRACE(boost::format(this->getImplementationName()+"_encrypt("
			"mode=%d"
			", gridSize=%d"
			", threadsPerBlock=%d"
			", data=%x"
			", blockOffset=%d"
			", n_blocks=%d"
			", iv=%x"
			", expanded_key=%x"
			", rounds=%d)")
	    % this->getMode()
		% gridSize
		% threadsPerBlock
		% (void*) (this->data)
		% this->getCurrentBlockOffset()
		% n_blocks
		% (void*) this->getIV()
		% key
		% rounds);
	this->getEncryptFunction()(
			this->getMode(),
			gridSize,
			threadsPerBlock,
			this->getDevice()->acessStream(this->stream),
			n_blocks,
			this->getEncryptBlockOffset(),
			this->data,
			this->data, // TODO implement out-of-place version
			this->neighborsDev,
			this->getIV(),
			key,
			this->getKeyBits(rounds),
			this->getDeviceTe0(),
			this->getDeviceTe1(),
			this->getDeviceTe2(),
			this->getDeviceTe3()
	);

    this->getDevice()->memcpyFrom(this->data, (void *) out, dataSize,
				  this->stream);

	paracrypt::BlockCipher::encrypt(in,out,n_blocks); // increment block offset
    return 0;
}

int paracrypt::CudaAES::decrypt(const unsigned char in[],
				      const unsigned char out[],
				      std::streamsize n_blocks)
{
	if(this->getMode() == paracrypt::BlockCipher::CTR
			|| this->getMode() == paracrypt::BlockCipher::GCM
			|| this->getMode() == paracrypt::BlockCipher::CFB
	) {
		// CTR and CFB modes use the encryption function even for decryption
		this->setInitialBlockOffset(this->getDecryptBlockOffset());
		return encrypt(in, out, n_blocks);
	}

	int threadsPerCipherBlock = this->getThreadsPerCipherBlock();
    int gridSize = this->getDevice()->getGridSize(n_blocks, threadsPerCipherBlock);
    int threadsPerBlock = this->getDevice()->getThreadsPerThreadBlock();
    size_t dataSize = n_blocks * AES_BLOCK_SIZE_B;
    uint32_t *key = this->getDeviceDKey();
    assert(key != NULL);
    int rounds = this->getDecryptionExpandedKey()->rounds;

	if(this->getMode() == paracrypt::BlockCipher::CBC) {
		if(this->inPlace) {
			if(in != out) {
				LOG_WAR("The cipher is configured to process data "
						"in-place but two different pointers are given.");
			}
			// only CBC and CFB use neighbors
			transferNeighborsToGPU(in,n_blocks);
		} else {
			if(in == out) {
				ERR("The cipher is not configured to process data in-place.");
			}
		}
	}

//    DEV_TRACE(boost::format("decryption key: %x") % key);
//    DEV_TRACE(boost::format("decryption data ptr: %x") % (int*) in);
//    DEV_TRACE(boost::format("decryption data size: %i") % dataSize);
//    DEV_TRACE(boost::format("decryption Td0: %x") % this->getDeviceTd0());
//    DEV_TRACE(boost::format("decryption Td1: %x") % this->getDeviceTd1());
//    DEV_TRACE(boost::format("decryption Td2: %x") % this->getDeviceTd2());
//    DEV_TRACE(boost::format("decryption Td3: %x") % this->getDeviceTd3());
//    DEV_TRACE(boost::format("decryption Td4: %x") % (int*) this->getDeviceTd4());

    this->getDevice()->memcpyTo((void *) in, this->data, dataSize,
				this->stream);

	DEV_TRACE(boost::format(this->getImplementationName()+"_decrypt("
			"mode=%d"
			", gridSize=%d"
			", threadsPerBlock=%d"
			", data=%x"
			", blockOffset=%d"
			", n_blocks=%d"
			", iv=%x"
			", expanded_key=%x"
			", rounds=%d)")
		% this->getMode()
		% gridSize
		% threadsPerBlock
		% (void*) (this->data)
		% this->getCurrentBlockOffset()
		% n_blocks
		% (void*) this->getIV()
		% key
		% rounds);
	this->getDecryptFunction()
			(
					this->getMode(),
					gridSize,
					threadsPerBlock,
					this->getDevice()->acessStream(this->stream),
					n_blocks,
					this->getDecryptBlockOffset(),
					this->data,
					this->data, // TODO implement out-of-place version
					this->neighborsDev,
					this->getIV(),
					key,
					this->getKeyBits(rounds),
					this->getDeviceTd0(),
					this->getDeviceTd1(),
					this->getDeviceTd2(),
					this->getDeviceTd3(),
					this->getDeviceTd4()
			);

    this->getDevice()->memcpyFrom(this->data, (void *) out, dataSize,
				  this->stream);

	paracrypt::BlockCipher::decrypt(in,out,n_blocks); // increment block offset
    return 0;
}
