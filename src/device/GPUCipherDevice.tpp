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

#include "GPUCipherDevice.hpp"
#include "logging.hpp"
#include <math.h> 

template < typename S, typename F >
int paracrypt::GPUCipherDevice < S, F >::getNWarpsPerBlock()
{
    return this->nWarpsPerBlock;
}

template < typename S, typename F >
int paracrypt::GPUCipherDevice < S, F >::getThreadsPerThreadBlock()
{
    return this->nThreadsPerThreadBlock;
}

template < typename S, typename F >
void paracrypt::GPUCipherDevice < S, F >::setThreadsPerThreadBlock(int tptb)
{
	LOG_WAR(
			"Changing the number of threads per block will limit the maximum"
			"device thread occupancy. This could have a negative impact in performance."
			);
    this->nThreadsPerThreadBlock = tptb;
}

template < typename S, typename F >
int paracrypt::GPUCipherDevice < S, F >::getMaxBlocksPerSM()
{
    return this->maxBlocksPerSM;
}

template < typename S, typename F >
int paracrypt::GPUCipherDevice < S, F >::getConcurrentKernels()
{
    return this->nConcurrentKernels;
}

template < typename S, typename F >
    paracrypt::GPUCipherDevice < S, F >::~GPUCipherDevice()
{
//    boost::unique_lock< boost::shared_mutex > lock(this->streams_access);
	typename boost::unordered_map<int,S>::iterator iter;
    for(iter = this->streams.begin(); iter != this->streams.end(); ++iter)
    {
//    	  LOG_TRACE(boost::format("~GPUCipherDevice(): delStream(%d)") % iter->first);
          delStream(iter->first);
    }
}

template < typename S, typename F >
    int paracrypt::GPUCipherDevice < S, F >::getGridSize(int n_blocks,
							 int
							 threadsPerCipherBlock)
{
	int tptb = this->getThreadsPerThreadBlock();
	float cipherBlocksPerThreadBlock = tptb / threadsPerCipherBlock;
	if(std::fmod(cipherBlocksPerThreadBlock,1) != 0) {
		LOG_WAR(
				"Changing the number of threads per tread-block"
				"to avoid heavy syncronization when having parts of cipher-blocks"
				"in different thread-blocks. This shouldn't happen because the"
				"maximum number of threads per block should be multiple of the warp size."
				"Consider to use paralelism at block level"
				"(only one thread processes a cipher block) instead."
				);
		int newTptb = threadsPerCipherBlock;
		int newTptbAux = newTptb;
		do {
			newTptb = newTptbAux;
			newTptbAux *= 2;
		}while(newTptbAux < tptb);
		this->setThreadsPerThreadBlock(newTptb);
//		LOG_FATAL(boost::format("unsupported operation: %d/%d=%f does not constitute"
//				" a fixed number of cipher-blocks per thread-block. "
//				" ) 
//			% tptb 
//			% threadsPerCipherBlock
//			% cipherBlocksPerThreadBlock);
//		exit(-1);
	}
    float fGridSize =
	n_blocks * threadsPerCipherBlock /
	(float) tptb;
    int gridSize = ceil(fGridSize);
    return gridSize;
}

template < typename S, typename F >
    int paracrypt::GPUCipherDevice < S, F >::addStream()
{
//    boost::unique_lock< boost::shared_mutex > lock(this->streams_access);
    int id = this->streams.size();
    this->streams[id] = newStream();
//    LOG_TRACE(boost::format("GPUCipherDevice.addStream() => %d") % id);
    return id;
}

template < typename S, typename F >
    void paracrypt::GPUCipherDevice < S, F >::delStream(int stream_id)
{
//    boost::unique_lock< boost::shared_mutex > lock(this->streams_access);
    freeStream(this->streams[stream_id]);
    this->streams.erase(stream_id);
}

template < typename S, typename F >
    S paracrypt::GPUCipherDevice < S, F >::acessStream(int stream_id)
{
//    boost::shared_lock < boost::shared_mutex > lock(this->streams_access);
    return this->streams[stream_id];
}
