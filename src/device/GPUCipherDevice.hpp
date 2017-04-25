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
 *  Foobar is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include <boost/unordered_map.hpp>
#include <boost/thread/shared_mutex.hpp>

namespace paracrypt {

    template < typename S, typename F > class GPUCipherDevice {
      protected:
    boost::unordered_map<int,S> streams;
	boost::shared_mutex streams_access;
	virtual S newStream();
	virtual void freeStream(S s);
	S acessStream(int stream_id);
	int maxBlocksPerSM;
	int nWarpsPerBlock;
	int nThreadsPerThreadBlock;
	int nConcurrentKernels;
      public:
	 virtual ~ GPUCipherDevice();
	int getThreadsPerThreadBlock();
	void setThreadsPerThreadBlock(int tptb);
	int getNWarpsPerBlock();
	int getMaxBlocksPerSM();
	int getConcurrentKernels();
	int getGridSize(int n_blocks, int threadsPerCipherBlock);
	virtual void set() = 0;	// must be called to set operations to this device
	virtual void malloc(void **data, int size) = 0;
	virtual void free(void *data) = 0;
	virtual void memcpyTo(void *host, void *dev, int size, int stream_id) = 0;	// Async
	virtual void memcpyFrom(void *dev, void *host, int size, int stream_id) = 0;	// Async
	virtual void waitMemcpyFrom(int stream_id) = 0;;	//waits until mempcyFrom finishes
	virtual int checkMemcpyFrom(int stream_id) = 0;;	//checks if memcpyFrom has finished
	virtual void setMemCpyFromCallback(int stream_id, F func) = 0;;
	int addStream();	// thread-safe
	void delStream(int stream_id);	// thread-safe
    };

}

#include "GPUCipherDevice.tpp"
