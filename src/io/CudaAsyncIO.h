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

#ifndef CUDAASYNCIO_H_
#define CUDAASYNCIO_H_

namespace paracrypt {

class CudaAsyncIO {
private:
	/*
	 * Two pointers (*in, *out) to allow async IO
	 */
	typedef enum {
		EMPTY = 0,
		 // - Nothing to read or to dump to the outFile

		PENDING_READ = 1,
		 // - The "in" buffer is filled with data from the inFile
		 //   and can be retrieved with the read() function. Data is
		 //   stored moved to the "out" pointer when read() is executed.

		PENDING_DUMP = 2,
		 // - The "out" buffer has data in it and can be dumped to the
		 //  outFile calling dump()

		PENDING_READ_DUMP = 3,
		 // - Both "in" and "out" buffers are full and waiting for
		 //  a call to write() and then read(). A call to read()
		 //  before write() would result in an error.
	} io_buffer_state;

	typedef struct io_buffer {
		unsigned char* in;
		unsigned char* out;
		const unsigned long size;
		unsigned long read_pointer;
		io_buffer_state state;
	} io_buffer;
    const io_buffer buffers[];
	const int nBuffers;
public:
	CudaAsyncIO();
	virtual ~CudaAsyncIO();
};

} /* namespace paracrypt */

#endif /* CUDAASYNCIO_H_ */
