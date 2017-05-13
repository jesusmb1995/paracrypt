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
#include <vector>
#include <algorithm>
#include "io/IO.hpp"
#include "io/CudaSharedIO.hpp"

//template <class T>
//T *creatClass(){
//  check base class assert
//    return new T();
//}

// TODO templates that retreive total number o devices and create
//  each type of object, one function for each type

//TODO CUDACipherDevice.getDevices()

// Calls SharedIO.construct() with limitted memory
//  according to the devices maximum capacity
//  and sets the number of chunks according to
//  devices number of concurrent kernells.
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

void paracrypt::Launcher::encrypt(
			 CUDABlockCipher* ciphers[],
			 unsigned int n,
			 SharedIO* io
){
		if(n == 0) return;

		const std::streamsize chunkSizeBytes = io->getChunkSize()*io->getBlockSize();
		paracrypt::BlockIO::chunk* chunks = new paracrypt::BlockIO::chunk[n];


		for(unsigned int i = 0; i < n; i++) {
			// block sizes in bits
			assert(io->getBlockSize()*8 == ciphers[i]->getBlockSize());
			ciphers[i]->malloc(chunkSizeBytes);
//			if(i == 0){
//				ciphers[0]->getDevice()->genGlobalMemcpyFromEvent();
//			} else {
//				ciphers[i]->getDevice()->setGlobalMemcpyFromEvent(
//						ciphers[0]->getDevice()->genGlobalMemcpyFromEvent());
//			}
		}

		/*
		 * HOLY GRAIL -\
		 * https://devtalk.nvidia.com/default/topic/488265/get-rid-of-busy-waiting-during-asynchronous-cuda-stream-executions/
		 *
		 * Hacer varias versiones:
		 *  1- busy wait...
		 *  2- block wait y hacer issues siempre en mismo orden...
         *  3- Usar busy wait... cudaEventSynchronize evento cualquier stream...
         *
         * ahora mismo se realiza de forma Depth first... probar width?
         *
         *  cudaEvent_t is useful for timing, but for performance use <--
         *  cudaEventCreateWithFlags ( &event, cudaEventDisableTiming )
         *
         *  TODO traza llamadas metodos cuda en CUDACipherDevice como en cualquier otro lado
         *     para ver que funciona ben
         *
         *  TODO asegurarse con el profiler que se ejecutan concurrentemente...
		 */
		/*
		 *
		 * Callbacks are processed by a driver thread
		 *	—
		 *		The same thread processes all callbacks
		 *		—
		 *		You can use this thread to signal other threads
		 *
		 */			//
		// Callbacks must not make any CUDA API calls. Attempting to use CUDA APIs will result in cudaErrorNotPermitted. Callbacks must not perform any synchronization that may depend on outstanding device work or other callbacks that are not mandated to run earlier. Callbacks without a mandated order (in independent streams) execute in undefined order and may be serialized.
		//
		// Read more at: http://docs.nvidia.com/cuda/cuda-runtime-api/index.html#ixzz4gWhWLVBu
		//Follow us: @GPUComputing on Twitter | NVIDIA on Facebook
		//
		// Usar callbacks para revivir a este thread y que no haya busy wait!
		//  version mejorada y simple!


		std::vector<int> executingKernells;
		std::vector<int>::iterator it;
		paracrypt::BlockIO::chunk c;
		c.status = paracrypt::BlockIO::OK;

		// launch first kernels
		for(unsigned int i = 0; c.status == paracrypt::BlockIO::OK && i < n; i++) {
// habrá un varios cipher para mismo device.
//			for(int j = 0; j < ciphers[i]->getDevice()->getConcurrentKernels(); j++) {
				c = chunks[i];
				c = io->read();
				chunks[i] = c;
				ciphers[i]->encrypt(c.data,c.data,c.nBlocks);
				executingKernells.push_back(i);
//			}
		}

		while(c.status == paracrypt::BlockIO::OK) {
				// blocking call in order not to busy wait
				//  the global wait is in any device...
				//	ciphers[0]->getdevice()->waitanygpumemcpyfrom();

			for(unsigned int i = 0; i < n; i++) {
				if(ciphers[i]->checkFinish()) {
					c = chunks[i];
					io->dump(c);
					c = io->read();
					chunks[i] = c;
					ciphers[i]->encrypt(c.data,c.data,c.nBlocks);
					if(c.status == paracrypt::BlockIO::END) {
						it = find (executingKernells.begin(), executingKernells.end(), i);
						executingKernells.erase(it);
						break;
					}
				}
			}
		}


		// One of the kernels has reached EOF: make
		//  sure we have recollect all the outputs before exit
		//    Note: this can be done synchronizing the device or with
		//          an auxiliar list as we do here.
		// busy wait in list of n executed...
		while(executingKernells.size() > 0) {
			it = executingKernells.begin();
			while(it != executingKernells.end()) {
				if(ciphers[*it]->checkFinish()) {
					c = chunks[*it];
					io->dump(c);
					it = executingKernells.erase(it);
				} else  {
					++it;
				}
			}
		}

//
//			 CUDABlockCipher <-- set clone method
//				devices[0]->
//
//
//			 if(!finished)
//			   wait...

//		ciphers[i]->getDevice()->getConcurrentKernels();

		delete[] chunks;
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
