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

#include "Launcher.hpp"
#include "io/IO.hpp"
#include "io/CudaSharedIO.hpp"
#include <vector>
#include <algorithm>
#include <fstream>

//template <class T>
//T *creatClass(){
//  check base class assert
//    return new T();
//}

// TODO templates that retrieve total number o devices and create
//  each type of object, one function for each type

//TODO CUDACipherDevice.getDevices()

// Calls SharedIO.construct() with limited memory
//  according to the devices maximum capacity
//  and sets the number of chunks according to
//  devices number of concurrent kernels.
paracrypt::SharedIO* paracrypt::Launcher::newAdjustedSharedIO(
		std::string inFilename,
		std::string outFilename,
		unsigned int blockSize,
		CUDACipherDevice* devices[],
		int n,
		std::streampos begin,
		std::streampos end
){
	SharedIO* io = NULL;
	if(n == 0) return io;

	int totalConcurrentKernels = 0;
	rlim_t memLimit = IO::fileSize(inFilename);

	for(int d = 0; d < n; d++) {
		totalConcurrentKernels += devices[d]->getConcurrentKernels();
		memLimit = std::min(memLimit,devices[d]->getDeviceProperties()->totalGlobalMem);
	}

	io = new CudaSharedIO(inFilename,outFilename,blockSize,totalConcurrentKernels,memLimit,begin,end);
	return io;
}

void paracrypt::Launcher::operation(
		 operation_t op,
		 CUDABlockCipher* ciphers[],
		 unsigned int n,
		 SharedIO* io,
		 bool outOfOrder
){
		if(n == 0) return;

		const std::streamsize chunkSizeBytes = io->getChunkSize()*io->getBlockSize();
		paracrypt::BlockIO::chunk* chunks = new paracrypt::BlockIO::chunk[n];

		const unsigned int blockSizeBytes = io->getBlockSize();
		for(unsigned int i = 0; i < n; i++) {
			// block sizes in bits
			assert(blockSizeBytes*8 == ciphers[i]->getBlockSize());
			ciphers[i]->malloc(chunkSizeBytes);
		}

		std::vector<int> executingKernells;
		std::vector<int>::iterator it;
		paracrypt::BlockIO::chunk c;
		c.status = paracrypt::BlockIO::OK;

		unsigned char* nextIV = NULL;
		if(isIVLinkable(ciphers[0])){
			nextIV = new unsigned char[blockSizeBytes];
			std::streampos b = io->getBeginBlock();
			if(b > 0) {
				// IV is prev. block
				b -= 1;
				// Read IV from prev. block
				std::string inName = io->getInFileName();
				std::ifstream in(inName.c_str(),std::ifstream::binary);
				in.seekg(b*blockSizeBytes);
				in.read((char*)nextIV,blockSizeBytes);
				if(in.fail()){
					ERR(boost::format("Error trying to retrieve IV "
						"from random access previous block (%llu).")
					% b);
				}
				in.close();
				hexdump("IV retrieved from previous block",nextIV,blockSizeBytes);
				ciphers[0]->setIV(nextIV,ciphers[0]->getBlockSize());
			}
		}
// TODO almacenar
//
// 				if(m != paracrypt::BlockCipher::ECB) {
//					c->setIV(iv,ivBits);
//				}

		// launch first kernels
		for(unsigned int i = 0; c.status == paracrypt::BlockIO::OK && i < n; i++) {
				c = chunks[i];
				c = io->read();
//				if(i < 5) {
//					hexdump("readed block sample", c.data, c.nBlocks);
//				}
				chunks[i] = c;
				// In CBC and CFB modes the next cipher-IV
				//  will be the last block of this cipher
				DEV_TRACE(boost::format("Launcher: encrypting chunk starting at block %llu in stream %u... \n")
					% c.blockOffset % i);
				if(c.nBlocks > 0) {
#ifdef DEVEL
					if(c.nBlocks <= 66) {
						hexdump("operating",c.data,c.nBlocks*16);
					}
#endif
					// First cipher already has set the user intoduced IV
					//  operation won't overwrite the IV when the iv pointer
					//  is NULL
					unsigned char* iv = i == 0 ? NULL : nextIV;
#ifdef DEVEL
					if(iv != NULL) {
						hexdump("...with a previous block as input vector",iv,16);
					}
#endif
					operation(op,ciphers[i],c,iv);
					if(isIVLinkable(ciphers[i])) {
						// TODO RACE CONDITION !! c is being operated asynchronously with operation and will be changed !!!
						// can't safely use c after operation has been launched !!
						cpyLastBlock(nextIV,c,blockSizeBytes);
					}
					executingKernells.push_back(i);
				}
		}

		while(c.status == paracrypt::BlockIO::OK) {
			for(unsigned int i = 0; c.status == paracrypt::BlockIO::OK && i < n; i++) {
				if(finished(ciphers[i],outOfOrder)) {
					DEV_TRACE(boost::format("Launcher: chunk starting at block %llu in stream %u has finished encryption.\n")
						% c.blockOffset % i);
					c = chunks[i];
//					if(i < 5) {
//						hexdump("to output block sample", c.data, c.nBlocks);
//					}
#ifdef DEVEL
					if(c.nBlocks <= 66) {
						std::stringstream stream;
						stream << boost::format("writing (offset %llu)...") % c.blockOffset;
						hexdump(stream.str(), c.data,c.nBlocks*16);
					}
#endif
					io->dump(c);
					c = io->read();
//					if(i < 5) {
//						hexdump("readed block sample", c.data, c.nBlocks);
//					}
					chunks[i] = c;
					DEV_TRACE(boost::format("Launcher: encrypting chunk starting at block %llu in stream %u... \n")
						% c.blockOffset % i);
					if(c.nBlocks > 0) {
#ifdef DEVEL
					if(c.nBlocks <= 66) {
						hexdump("operating...",c.data,c.nBlocks*16);
					}
#endif
#ifdef DEVEL
						if(nextIV != NULL) {
							hexdump("...with a previous block as input vector",nextIV,16);
						}
#endif
						operation(op,ciphers[i],c,nextIV);
						if(isIVLinkable(ciphers[i])) {
							// TODO RACE CONDITION !! c is being operated asynchronously with operation and will be changed !!!
							// can't safely use c after operation has been launched !!
							cpyLastBlock(nextIV,c,blockSizeBytes);
						}
					}
				}
			}
		}

		if(nextIV != NULL){
			delete[] nextIV;
		}
		DEV_TRACE(boost::format("Launcher: Let's wait for %i chunks to finish... \n") % executingKernells.size() );

		// One of the kernels has reached EOF: make
		//  sure we have recollect all the outputs before exit
		//    Note: this can be done synchronizing the device or with
		//          an auxiliar list as we do here.
		// busy wait in list of n executed...
		while(executingKernells.size() > 0) {
			it = executingKernells.begin();
			while(it != executingKernells.end()) {
				if(finished(ciphers[*it],outOfOrder)) {
					DEV_TRACE(boost::format("Launcher: chunk starting at block %llu in stream "
							"%u has finished. Waiting for another %%i chunks... \n")
						% executingKernells.size()
						% *it
					);
					c = chunks[*it];
//					if(*it < 5) {
//						hexdump("to output block sample", c.data, c.nBlocks);
//					}
#ifdef DEVEL
					if(c.nBlocks <= 66) {
						std::stringstream stream;
						stream << boost::format("writing (offset %llu)...") % c.blockOffset;
						hexdump(stream.str(), c.data,c.nBlocks*16);
					}
#endif
					io->dump(c);
					it = executingKernells.erase(it);
					DEV_TRACE(boost::format("Launcher: I'm yet waiting for another %i chunks... \n") % executingKernells.size());
				} else  {
					++it;
				}
			}
		}

		delete[] chunks;

		LOG_TRACE("Launcher: I'm finished dealing with the encryption.\n");
}

// TODO para la versión simple va a hacer falta version multibuffer
//  para que cada GPU lea de su buffer.

//void paracrypt::Launcher::encrypt(
//			 CUDABlockCipher* ciphers[],
////			 CUDACipherDevice* devices[], // cada device se obtiene del cipher->getCipherDevice()
//			 unsigned int n,
//			 SimpleIO* io // TODO SimpleIO configurado con maximo correcto y inFile e outFile
//			              // TODO reusar este para version SharedIO solo cambiar pin
//)
//{
//	if(n == 0) return;
//
//	// TODO calcular kernels totales disponibles
//	const std::streamsize pin = io->getBufferSize()*io->getBlockSize();
//	for(unsigned int i = 0; i < n; i++) {
//		// block sizes in bits
//		assert(io->getBlockSize()*8 == ciphers[i]->getBlockSize());
//		ciphers[i]->malloc(pin);
//		if(i == 0){
//			ciphers[0]->getDevice()->genGlobalMemcpyFromEvent();
//		} else {
//			ciphers[i]->getDevice()->setGlobalMemcpyFromEvent(
//					ciphers[0]->getDevice()->genGlobalMemcpyFromEvent());
//		}
//	}
//
//
//	BlockIO::chunk c;
//
//	c = io->read(); // dividir bloques en los distintos kernels totales disponibles...
//
//	// dividir
//
//	// TODO version shared
////	// launch first kernels
////	for(unsigned int i = 0; c.status == OK && i < n; i++) {
////		c = io->read();
////		ciphers[i]->encrypt(c.data,c.data,c.nBlocks);
////	}
////
////	while(c.status == OK) {
////		// blocking call in order not to busy wait
////		//  the global wait is in any device...
////		ciphers[0]->getDevice()->waitAnyGPUMemcpyFrom();
////		for(unsigned int i = 0; i < n; i++) {
////			if(ciphers[0]) { // TODO check memcpyFrom
////				// TODO write to output file
////				c = io->read(); // TODO read another chunk
////
////			}
////		}
////	}
//
//	// if(c.status == END) synchronize and make
//	//  sure we have recollect all the outputs
//
//
//
//	// CUDABlockCipher <-- set clone method
//	//	devices[0]->
//
//
//	// if(!finished)
//	//   wait...
//}

// TODO set cuda callbacks...
//   awake main thread if finished
